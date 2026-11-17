"""JSON report generator for CAPE."""
from __future__ import annotations

import json
from datetime import datetime, date
from pathlib import Path
from uuid import UUID

from cape.reports.assembler import ReportData
from cape.reports.generators.base import BaseReportGenerator


class JSONReportGenerator(BaseReportGenerator):
    """Generates a pretty-printed JSON report from ReportData.

    Dispatches to per-audience builders so the JSON shape mirrors the
    HTML/PDF reports: CISO gets no raw evidence or ports, auditor gets
    compliance + audit chain, engineer gets full technical detail, full
    gets everything.
    """

    def generate(self, report_data: ReportData, output_path: Path) -> Path:
        """Generate JSON report.

        Args:
            report_data: Assembled report data.
            output_path: Output file path (should end in .json).

        Returns:
            Path to generated JSON file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        dispatch = {
            "ciso": self._build_ciso,
            "auditor": self._build_auditor,
            "engineer": self._build_engineer,
            "full": self._build_full,
        }
        build_fn = dispatch.get(report_data.audience, self._build_full)
        data = build_fn(report_data)

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=self._json_default)

        return output_path

    def _metadata(self, report_data: ReportData) -> dict:
        return {
            "target": report_data.target,
            "audience": report_data.audience,
            "generated_at": report_data.generated_at.isoformat(),
            "operator": report_data.operator,
            "client_id": report_data.client_id,
        }

    def _summary(self, report_data: ReportData) -> dict:
        s = report_data.scan_summary
        return {
            "total_findings": s.total_findings, "critical": s.critical_count,
            "high": s.high_count, "medium": s.medium_count, "low": s.low_count,
            "info": s.info_count, "scan_profile": s.scan_profile, "tools_used": s.tools_used,
        }

    def _build_ciso(self, report_data: ReportData) -> dict:
        """CISO: business summary only - no ports, no raw evidence, no commands."""
        top5 = sorted(report_data.opportunities, key=lambda o: o.score, reverse=True)[:5]
        return {
            "report_metadata": self._metadata(report_data),
            "risk_summary": self._summary(report_data),
            "top_opportunities": [
                {"name": o.name, "score": o.score, "severity": o.severity.value, "business_impact": o.description}
                for o in top5
            ],
            "remediation_progress": report_data.remediation_progress,
            "compliance_frameworks_with_open_findings": report_data.compliance_frameworks_with_open_findings,
            "trend": (
                {"trend_score": report_data.drift_summary.trend_score}
                if report_data.drift_summary else None
            ),
        }

    def _build_auditor(self, report_data: ReportData) -> dict:
        """Auditor: audit chain, compliance evidence - no exploit detail."""
        return {
            "report_metadata": self._metadata(report_data),
            "audit_chain_verification": (
                report_data.audit_verification.model_dump() if report_data.audit_verification else None
            ),
            "findings_with_compliance": [
                {
                    "id": str(f.id), "title": f.title, "severity": f.severity.value,
                    "compliance": report_data.compliance_by_finding.get(str(f.id), {}),
                }
                for f in report_data.findings
            ],
            "drift_summary": (
                report_data.drift_summary.model_dump(mode="json") if report_data.drift_summary else None
            ),
        }

    def _build_engineer(self, report_data: ReportData) -> dict:
        """Engineer: full technical detail, evidence, reproduction data."""
        return {
            "report_metadata": self._metadata(report_data),
            "scan_summary": self._summary(report_data),
            "findings": [
                {**f.to_dict(), "compliance": report_data.compliance_by_finding.get(str(f.id), {})}
                for f in report_data.findings
            ],
            "opportunities": [
                {**o.to_dict(), "remediation": report_data.remediation_by_opportunity.get(str(o.id), {})}
                for o in report_data.opportunities
            ],
            "evidence": self._evidence_list(report_data),
        }

    def _build_full(self, report_data: ReportData) -> dict:
        """Full: everything combined."""
        return {
            "report_metadata": self._metadata(report_data),
            "scan_summary": self._summary(report_data),
            "findings": [
                {**f.to_dict(), "compliance": report_data.compliance_by_finding.get(str(f.id), {})}
                for f in report_data.findings
            ],
            "opportunities": [
                {**o.to_dict(), "remediation": report_data.remediation_by_opportunity.get(str(o.id), {})}
                for o in report_data.opportunities
            ],
            "evidence": self._evidence_list(report_data),
            "compliance_frameworks_with_open_findings": report_data.compliance_frameworks_with_open_findings,
            "remediation_progress": report_data.remediation_progress,
            "drift_summary": (
                report_data.drift_summary.model_dump(mode="json") if report_data.drift_summary else None
            ),
            "audit_chain_verification": (
                report_data.audit_verification.model_dump() if report_data.audit_verification else None
            ),
        }

    def _evidence_list(self, report_data: ReportData) -> list[dict]:
        return [
            {
                "id": str(getattr(e, "id", "")),
                "tool": getattr(e, "tool", ""),
                "command_run": getattr(e, "command_run", ""),
                "summary": getattr(e, "summary", ""),
                "timestamp": str(getattr(e, "timestamp", "")),
            }
            for e in report_data.evidence
        ]

    def _json_default(self, obj):
        """JSON serialization fallback."""
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, Path):
            return str(obj)
        return str(obj)
