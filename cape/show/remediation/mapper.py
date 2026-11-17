"""CAPE Pillar A(+) — RemediationMapper.

Turns a scored Opportunity into a concrete, prioritized RemediationPlan:
what the catalog recommends for this attack pattern (or, failing that,
for its domain), plus any remediation text a scan tool itself reported
on the supporting findings (e.g. ZAP's own "solution" field).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import yaml

from cape.shared.finding import Finding
from cape.show.models import AttackPattern, Opportunity
from cape.show.remediation.models import Countermeasure, RemediationPlan

logger = logging.getLogger(__name__)

_DEFAULT_CATALOG_PATH = Path(__file__).parent / "catalog.yaml"

_PRIORITY_BY_SEVERITY = {
    "CRITICAL": "Fix immediately",
    "HIGH": "Fix this sprint",
    "MEDIUM": "Schedule",
    "LOW": "Track",
    "INFO": "Track",
}


class RemediationMapper:
    """Builds RemediationPlan objects from the remediation catalog."""

    def __init__(self, catalog_path: Optional[Path] = None) -> None:
        """Initialize with an optional custom catalog path (defaults to the built-in one)."""
        self.catalog_path = catalog_path or _DEFAULT_CATALOG_PATH
        self._catalog: Optional[dict] = None

    def load_catalog(self) -> dict:
        """Load (and cache) the remediation catalog YAML."""
        if self._catalog is not None:
            return self._catalog
        if not self.catalog_path.exists():
            logger.warning(f"Remediation catalog not found: {self.catalog_path}")
            self._catalog = {"patterns": {}, "domain_fallback": {}}
            return self._catalog
        try:
            self._catalog = yaml.safe_load(self.catalog_path.read_text(encoding="utf-8")) or {}
            self._catalog.setdefault("patterns", {})
            self._catalog.setdefault("domain_fallback", {})
        except Exception as e:
            logger.error(f"Failed to load remediation catalog: {e}")
            self._catalog = {"patterns": {}, "domain_fallback": {}}
        return self._catalog

    def build_plan(
        self,
        opportunity: Opportunity,
        attack_pattern: Optional[AttackPattern] = None,
        findings: Optional[list[Finding]] = None,
    ) -> RemediationPlan:
        """Build the full remediation plan for one scored Opportunity.

        Looks up the catalog by attack_pattern_id first; falls back to a
        generic entry for the opportunity's domain if there's no specific
        match, so every opportunity gets actionable guidance. Any
        tool-supplied remediation text on the supporting findings (e.g.
        from ZAP) is appended as an extra, clearly-labeled countermeasure
        rather than silently dropped.
        """
        catalog = self.load_catalog()
        pattern_id = (attack_pattern.id if attack_pattern else opportunity.attack_pattern_id) or ""

        entry = catalog["patterns"].get(pattern_id)
        source = "catalog"
        if entry is None:
            entry = catalog["domain_fallback"].get(opportunity.domain.value, {})
            source = "domain-fallback" if entry else "domain-fallback"

        countermeasures = [
            Countermeasure(**cm) for cm in entry.get("countermeasures", [])
        ]
        verification_steps = list(entry.get("verification_steps", []))

        # Fold in any tool-reported remediation text so nothing a scanner
        # already told us gets lost just because it isn't in the catalog.
        tool_notes = self._collect_tool_remediation(findings or [])
        for tool, text in tool_notes:
            countermeasures.append(
                Countermeasure(
                    title=f"As reported by {tool}",
                    description=text,
                    stage="immediate",
                    effort="low",
                )
            )

        priority = _PRIORITY_BY_SEVERITY.get(opportunity.severity.value, "Schedule")

        pattern_name = attack_pattern.name if attack_pattern else opportunity.name
        summary = (
            f"{priority} — {len(countermeasures)} countermeasure(s) identified for "
            f"{pattern_name} (score {opportunity.score:.1f}, {opportunity.severity.value})."
        )

        residual_risk_note = None
        if not countermeasures:
            residual_risk_note = (
                "No specific or domain-level remediation guidance is catalogued for this "
                "opportunity yet. Treat the finding manually and consider extending "
                "show/remediation/catalog.yaml with a matching entry."
            )
            source = "none"

        return RemediationPlan(
            opportunity_id=opportunity.id,
            attack_pattern_id=pattern_id or opportunity.rule_id,
            target=opportunity.target,
            priority=priority,
            summary=summary,
            countermeasures=countermeasures,
            verification_steps=verification_steps,
            residual_risk_note=residual_risk_note,
            source=source,
        )

    def _collect_tool_remediation(self, findings: list[Finding]) -> list[tuple[str, str]]:
        """Pull distinct (tool, remediation_text) pairs off supporting findings."""
        seen: set[tuple[str, str]] = set()
        for f in findings:
            if f.remediation:
                seen.add((f.source_tool, f.remediation.strip()))
        return sorted(seen)
