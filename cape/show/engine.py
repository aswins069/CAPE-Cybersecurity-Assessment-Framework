"""Show engine - identifies attack opportunities from scan findings."""
from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from cape.show.knowledge.loader import KnowledgeBaseLoader
from cape.show.models import Opportunity
from cape.show.rule_evaluator import RuleEvaluator
from cape.show.scorer import OpportunityScorer
from cape.shared.finding import Finding

logger = logging.getLogger(__name__)


class ShowEngine:
    """Identifies attack opportunities from normalized findings.

    Uses a deterministic rule-based approach: loads rules from the
    knowledge base, evaluates them against findings, scores matches.
    """

    def __init__(self, kb_loader: Optional[KnowledgeBaseLoader] = None) -> None:
        """Initialize show engine."""
        self.kb_loader = kb_loader or KnowledgeBaseLoader()
        self.evaluator = RuleEvaluator()
        self.scorer = OpportunityScorer()

    def analyze(
        self,
        target: str,
        findings: list[Finding],
        min_score: float = 0.0,
        domain_filter: Optional[str] = None,
    ) -> list[Opportunity]:
        """Analyze findings and return scored opportunities.

        Args:
            target: Target being assessed.
            findings: Normalized findings from scan engine.
            min_score: Minimum score threshold (0.0-10.0).
            domain_filter: Optional domain to filter by.

        Returns:
            List of opportunities sorted by score descending.
        """
        if not findings:
            logger.info("No findings to analyze")
            return []

        # Load knowledge base
        attack_patterns = self.kb_loader.load_attack_patterns()
        opportunity_rules = self.kb_loader.load_opportunity_rules()

        if not opportunity_rules:
            logger.warning("No opportunity rules loaded from knowledge base")
            return []

        # Apply domain filter
        if domain_filter:
            opportunity_rules = [
                r for r in opportunity_rules
                if r.domain.value == domain_filter.upper()
            ]

        # Evaluate rules
        evaluations = self.evaluator.evaluate(findings, opportunity_rules)

        # Score matched evaluations
        opportunities: list[Opportunity] = []
        for evaluation in evaluations:
            if not evaluation.matched:
                continue

            # Find the rule
            rule = next((r for r in opportunity_rules if r.id == evaluation.rule_id), None)
            if not rule:
                continue

            # Find matching attack pattern
            pattern = next(
                (p for p in attack_patterns if rule.id.startswith(p.id.split("-")[0])),
                None,
            )

            opp = self.scorer.score(
                evaluation=evaluation,
                rule=rule,
                findings=findings,
                attack_pattern=pattern,
                target=target,
            )

            if opp:
                # CAPE Bug Fix #2: ShowEngine is the authoritative place that
                # links an Opportunity back to the rule that produced it.
                # cape explain uses this field as its lookup key - no more
                # fragile prefix-matching against attack_pattern_id.
                opp.rule_id = rule.id

            if opp and opp.score >= min_score:
                opportunities.append(opp)

        # Sort by score descending
        opportunities.sort(key=lambda o: o.score, reverse=True)

        logger.info(f"Identified {len(opportunities)} opportunities for {target}")

        # CAPE Pillar B: annotate findings with compliance control mappings
        # before persisting, so the data is available to cape show --compliance,
        # cape explain, and all report audiences.
        try:
            from cape.show.compliance.mapper import ComplianceMapper
            mapper = ComplianceMapper()
            annotations = mapper.annotate_all(findings)
            self._persist_compliance_annotations(annotations)
        except Exception as e:
            logger.error(f"Compliance annotation failed: {e}")

        # Persist to database
        self._persist_opportunities(opportunities, target)

        return opportunities

    def _persist_compliance_annotations(self, annotations: dict) -> None:
        """Persist compliance control annotations onto FindingModel rows.

        Args:
            annotations: Mapping of finding UUID -> ComplianceControlAnnotation.
        """
        if not annotations:
            return
        try:
            from cape.db.session import db_session
            from cape.db.models import FindingModel

            with db_session() as session:
                for finding_id, annotation in annotations.items():
                    fm = session.get(FindingModel, str(finding_id))
                    if fm is None:
                        continue
                    fm.compliance_pci_dss = annotation.pci_dss
                    fm.compliance_soc2 = annotation.soc2
                    fm.compliance_iso27001 = annotation.iso27001
                    fm.compliance_nist_csf = annotation.nist_csf
                    fm.compliance_cis_controls = annotation.cis_controls
        except Exception as e:
            logger.error(f"Failed to persist compliance annotations: {e}")


    def load_findings_from_db(self, target: str, scan_id: Optional[str] = None) -> list[Finding]:
        """Load findings from the database for a target.

        Args:
            target: Target hostname/IP.
            scan_id: Optional specific scan ID.

        Returns:
            List of Finding objects.
        """
        try:
            from cape.db.session import db_session
            from cape.db.models import FindingModel
            from cape.shared.enums import FindingCategory, Severity

            findings: list[Finding] = []
            with db_session() as session:
                query = session.query(FindingModel).filter(FindingModel.target == target)
                if scan_id:
                    query = query.filter(FindingModel.scan_id == scan_id)

                for fm in query.all():
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
            logger.error(f"Failed to load findings from DB: {e}")
            return []

    def _persist_opportunities(self, opportunities: list[Opportunity], target: str) -> None:
        """Persist opportunities to the database."""
        try:
            from cape.db.session import db_session
            from cape.db.models import OpportunityModel
            from datetime import datetime

            with db_session() as session:
                for opp in opportunities:
                    om = OpportunityModel(
                        id=str(opp.id),
                        target=target,
                        domain=opp.domain.value,
                        attack_pattern_id=opp.attack_pattern_id,
                        rule_id=opp.rule_id,
                        name=opp.name,
                        description=opp.description,
                        score=opp.score,
                        confidence=opp.confidence,
                        severity=opp.severity.value,
                        supporting_findings=[str(f) for f in opp.supporting_findings],
                        recommended_modules=opp.recommended_modules,
                        mitre_technique=opp.mitre_technique,
                        explanation=opp.explanation,
                        created_at=datetime.utcnow(),
                    )
                    session.merge(om)
        except Exception as e:
            logger.error(f"Failed to persist opportunities: {e}")
