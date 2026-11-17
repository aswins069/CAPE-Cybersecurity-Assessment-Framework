"""Report data assembly from database for CAPE."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from cape.shared.finding import Finding
from cape.show.models import Opportunity

logger = logging.getLogger(__name__)


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    scan_profile: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    tools_used: list[str] = field(default_factory=list)


@dataclass
class ReportData:
    """All data assembled for report generation."""

    target: str
    scan_summary: ScanSummary
    findings: list[Finding]
    opportunities: list[Opportunity]
    plan: Optional[object] = None
    session: Optional[object] = None
    evidence: list[object] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.utcnow)
    operator: str = ""
    # CAPE report engine upgrade — three audiences
    audience: str = "full"  # ciso | auditor | engineer | full
    client_id: Optional[str] = None
    # Pillar B: compliance control annotations, keyed by finding id (str)
    compliance_by_finding: dict[str, dict] = field(default_factory=dict)
    compliance_frameworks_with_open_findings: list[str] = field(default_factory=list)
    # Pillar C: drift since the previous scan, if any
    drift_summary: Optional[object] = None  # show.drift.DriftReport | None
    remediation_progress: Optional[str] = None  # e.g. "4 of 9 findings from last scan are now fixed"
    # Pillar D: audit chain verification result for this target
    audit_verification: Optional[object] = None  # core.audit_chain.ChainVerificationResult | None
    # Pillar A(+): remediation guidance keyed by opportunity id (str)
    remediation_by_opportunity: dict[str, dict] = field(default_factory=dict)


class ReportAssembler:
    """Assembles ReportData from the database for a target."""

    def assemble(
        self,
        target: str,
        scan_id: Optional[str] = None,
        session_id: Optional[str] = None,
        operator: str = "",
        audience: str = "full",
        client_id: Optional[str] = None,
    ) -> ReportData:
        """Assemble complete report data from database.

        Args:
            target: Target hostname/IP.
            scan_id: Optional specific scan ID.
            session_id: Optional attack session ID.
            operator: Operator name.
            audience: One of 'ciso', 'auditor', 'engineer', 'full'. Determines
                which extra sections (compliance, drift, audit chain)
                get populated below.
            client_id: Optional CAPE client ID to scope data to.

        Returns:
            ReportData ready for report generators.
        """
        audience = audience.lower()
        if audience not in ("ciso", "auditor", "engineer", "full"):
            raise ValueError(f"Invalid audience '{audience}'. Use ciso, auditor, engineer, or full.")

        findings = self._load_findings(target, scan_id, client_id)
        opportunities = self._load_opportunities(target)
        evidence = self._load_evidence(session_id) if session_id else []

        summary = self._build_summary(findings)

        data = ReportData(
            target=target,
            scan_summary=summary,
            findings=sorted(findings, key=lambda f: self._severity_key(f.severity.value), reverse=True),
            opportunities=sorted(opportunities, key=lambda o: o.score, reverse=True),
            evidence=evidence,
            generated_at=datetime.utcnow(),
            operator=operator,
            audience=audience,
            client_id=client_id,
        )

        # CISO and AUDITOR audiences need compliance posture; ENGINEER needs
        # per-finding annotations too. FULL gets everything.
        if audience in ("ciso", "auditor", "engineer", "full"):
            data.compliance_by_finding, data.compliance_frameworks_with_open_findings = (
                self._load_compliance(findings)
            )

        # CISO and AUDITOR audiences want drift/remediation-progress framing.
        if audience in ("ciso", "auditor", "full"):
            data.drift_summary = self._load_latest_drift(target)
            data.remediation_progress = self._summarize_remediation(data.drift_summary)

        # AUDITOR audience needs the audit chain verification result.
        if audience in ("auditor", "full"):
            data.audit_verification = self._load_audit_verification()

        # ENGINEER and FULL audiences get concrete countermeasures per
        # opportunity, so the report tells operators how to fix findings,
        # not just what they are.
        if audience in ("engineer", "full"):
            data.remediation_by_opportunity = self._load_remediation(data.opportunities, findings)

        return data

    def _load_remediation(
        self, opportunities: list[Opportunity], findings: list[Finding],
    ) -> dict[str, dict]:
        """Build a RemediationPlan per opportunity, keyed by opportunity id (str)."""
        try:
            from cape.show.knowledge.loader import KnowledgeBaseLoader
            from cape.show.remediation.mapper import RemediationMapper

            mapper = RemediationMapper()
            patterns_by_id = {p.id: p for p in KnowledgeBaseLoader().load_attack_patterns()}

            plans: dict[str, dict] = {}
            for opp in opportunities:
                supporting = [f for f in findings if f.id in set(opp.supporting_findings)]
                plan = mapper.build_plan(
                    opportunity=opp,
                    attack_pattern=patterns_by_id.get(opp.attack_pattern_id),
                    findings=supporting,
                )
                plans[str(opp.id)] = plan.to_dict()
            return plans
        except Exception as e:
            logger.error(f"Failed to build remediation plans for report: {e}")
            return {}

    def _load_compliance(self, findings: list[Finding]) -> tuple[dict[str, dict], list[str]]:
        """Load persisted compliance annotations for a set of findings.

        Returns:
            Tuple of (annotations keyed by finding id string, sorted list
            of framework names that have at least one open/matched control).
        """
        annotations: dict[str, dict] = {}
        frameworks_with_findings: set[str] = set()

        try:
            from cape.db.session import db_session
            from cape.db.models import FindingModel

            finding_ids = [str(f.id) for f in findings]
            if not finding_ids:
                return annotations, []

            with db_session() as session:
                rows = (
                    session.query(FindingModel)
                    .filter(FindingModel.id.in_(finding_ids))
                    .all()
                )
                for row in rows:
                    pci = row.compliance_pci_dss or []
                    soc2 = row.compliance_soc2 or []
                    iso = row.compliance_iso27001 or []
                    csf = row.compliance_nist_csf or []
                    cis = row.compliance_cis_controls or []
                    annotations[row.id] = {
                        "pci_dss": pci,
                        "soc2": soc2,
                        "iso27001": iso,
                        "nist_csf": csf,
                        "cis_controls": cis,
                    }
                    if pci:
                        frameworks_with_findings.add("PCI-DSS")
                    if soc2:
                        frameworks_with_findings.add("SOC2")
                    if iso:
                        frameworks_with_findings.add("ISO27001")
                    if csf:
                        frameworks_with_findings.add("NIST CSF")
                    if cis:
                        frameworks_with_findings.add("CIS Controls")
        except Exception as e:
            logger.error(f"Failed to load compliance annotations: {e}")

        return annotations, sorted(frameworks_with_findings)

    def _load_latest_drift(self, target: str):
        """Load drift between the two most recent scans of a target, if any."""
        try:
            from cape.show.drift import ScanDiffer
            reports = ScanDiffer().compare_last_n(target, 2)
            return reports[-1] if reports else None
        except Exception as e:
            logger.error(f"Failed to load drift summary: {e}")
            return None

    def _summarize_remediation(self, drift_summary) -> Optional[str]:
        """Build a one-line remediation-progress sentence from a DriftReport."""
        if drift_summary is None:
            return None
        total_before = drift_summary.fixed_count + drift_summary.persistent_count + drift_summary.regressed_count + drift_summary.improved_count
        if total_before == 0:
            return None
        return (
            f"{drift_summary.fixed_count} of {total_before} findings from the "
            f"previous scan are now fixed."
        )

    def _load_audit_verification(self):
        """Run audit chain verification for the auditor report section."""
        try:
            from cape.core.audit_chain import get_audit_logger
            return get_audit_logger().verify_chain()
        except Exception as e:
            logger.error(f"Failed to verify audit chain for report: {e}")
            return None

    def _load_findings(
        self, target: str, scan_id: Optional[str], client_id: Optional[str] = None,
    ) -> list[Finding]:
        """Load findings from database, optionally scoped to a client_id."""
        try:
            from cape.db.session import db_session
            from cape.db.models import FindingModel
            from cape.shared.enums import FindingCategory, Severity
            from uuid import UUID

            findings: list[Finding] = []
            with db_session() as s:
                q = s.query(FindingModel).filter(FindingModel.target == target)
                if scan_id:
                    q = q.filter(FindingModel.scan_id == scan_id)
                if client_id:
                    q = q.filter(FindingModel.client_id == client_id)
                for fm in q.all():
                    findings.append(Finding(
                        id=UUID(fm.id),
                        target=fm.target,
                        source_tool=fm.source_tool,
                        scan_profile=fm.scan_profile,
                        timestamp=fm.timestamp,
                        category=FindingCategory(fm.category),
                        severity=Severity(fm.severity),
                        confidence=fm.confidence,
                        title=fm.title,
                        description=fm.description,
                        evidence=fm.evidence,
                        host=fm.host,
                        port=fm.port,
                        protocol=fm.protocol,
                        service=fm.service,
                        cve_ids=fm.cve_ids or [],
                        cvss_score=fm.cvss_score,
                        cvss_vector=fm.cvss_vector,
                        remediation=fm.remediation,
                        references=fm.references or [],
                        tags=fm.tags or [],
                        extra=fm.extra or {},
                    ))
            return findings
        except Exception as e:
            logger.error(f"Failed to load findings: {e}")
            return []

    def _load_opportunities(self, target: str) -> list[Opportunity]:
        """Load opportunities from database."""
        try:
            from cape.db.session import db_session
            from cape.db.models import OpportunityModel
            from cape.shared.enums import AttackDomain, Severity
            from uuid import UUID

            opps: list[Opportunity] = []
            with db_session() as s:
                for om in s.query(OpportunityModel).filter_by(target=target).all():
                    opps.append(Opportunity(
                        id=UUID(om.id),
                        target=om.target,
                        domain=AttackDomain(om.domain),
                        attack_pattern_id=om.attack_pattern_id,
                        rule_id=om.rule_id or "",
                        name=om.name,
                        description=om.description,
                        score=om.score,
                        confidence=om.confidence,
                        severity=Severity(om.severity),
                        supporting_findings=[UUID(f) for f in (om.supporting_findings or [])],
                        recommended_modules=om.recommended_modules or [],
                        mitre_technique=om.mitre_technique,
                        explanation=om.explanation,
                    ))
            return opps
        except Exception as e:
            logger.error(f"Failed to load opportunities: {e}")
            return []

    def _load_evidence(self, session_id: str) -> list:
        """Load evidence for a session."""
        try:
            from cape.db.session import db_session
            from cape.db.models import EvidenceModel
            with db_session() as s:
                return s.query(EvidenceModel).filter_by(session_id=session_id).all()
        except Exception as e:
            logger.error(f"Failed to load evidence: {e}")
            return []

    def _build_summary(self, findings: list[Finding]) -> ScanSummary:
        """Build scan summary from findings."""
        from collections import Counter
        sev_counts = Counter(f.severity.value for f in findings)
        tools = list({f.source_tool for f in findings})
        profiles = list({f.scan_profile for f in findings})
        return ScanSummary(
            total_findings=len(findings),
            critical_count=sev_counts.get("CRITICAL", 0),
            high_count=sev_counts.get("HIGH", 0),
            medium_count=sev_counts.get("MEDIUM", 0),
            low_count=sev_counts.get("LOW", 0),
            info_count=sev_counts.get("INFO", 0),
            scan_profile=", ".join(profiles),
            tools_used=tools,
        )

    def _severity_key(self, severity: str) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}.get(severity, 0)
