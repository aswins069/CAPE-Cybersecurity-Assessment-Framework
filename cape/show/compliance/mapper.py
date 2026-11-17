"""ComplianceMapper — maps normalized Findings to compliance controls.

CAPE Pillar B: every finding can be automatically annotated with the
PCI-DSS, SOC2, and ISO27001 controls it implicates, using a declarative
YAML knowledge base (mappings.yaml) that is loaded read-only at runtime.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional
from uuid import UUID

import yaml
from pydantic import BaseModel, Field

from cape.shared.enums import FindingCategory, Severity
from cape.shared.finding import Finding

# Ordinal weight used to compare severities (INFO is weakest, CRITICAL strongest).
_SEVERITY_WEIGHT: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}

_DEFAULT_MAPPINGS_FILE = Path(__file__).parent / "mappings.yaml"


def severity_weight(severity: str | Severity) -> int:
    """Return the ordinal weight of a severity string/enum for comparison."""
    value = severity.value if isinstance(severity, Severity) else str(severity)
    return _SEVERITY_WEIGHT.get(value, 0)


class ComplianceControlAnnotation(BaseModel):
    """The set of compliance controls a finding implicates, with rationale."""

    pci_dss: list[str] = Field(default_factory=list)
    soc2: list[str] = Field(default_factory=list)
    iso27001: list[str] = Field(default_factory=list)
    nist_csf: list[str] = Field(default_factory=list)
    cis_controls: list[str] = Field(default_factory=list)
    rationale: str = ""

    def is_empty(self) -> bool:
        """True if no controls were matched at all."""
        return not (
            self.pci_dss or self.soc2 or self.iso27001
            or self.nist_csf or self.cis_controls
        )


# Every framework the mapper knows how to fill in from a rule's `controls`
# block. Adding a new pluggable framework (Section 15 of the spec) means
# adding one entry here plus a matching field on ComplianceControlAnnotation
# above and populating `controls.<key>` in mappings.yaml — no other code
# changes needed.
_FRAMEWORK_KEYS = ("pci_dss", "soc2", "iso27001", "nist_csf", "cis_controls")


class ComplianceMapper:
    """Maps Findings to compliance controls using a YAML rule set.

    Rules are matched additively: a finding may match several rules, and
    the resulting controls are the union across all matches. Rationale
    strings from every matching rule are concatenated so a reviewer can
    see every reason a finding was flagged.
    """

    def __init__(self, mappings_file: Optional[Path] = None) -> None:
        """Load the compliance mapping knowledge base.

        Args:
            mappings_file: Path to a mappings YAML file. Defaults to the
                bundled show/compliance/mappings.yaml.
        """
        self.mappings_file = mappings_file or _DEFAULT_MAPPINGS_FILE
        self._rules: list[dict] = self._load_mappings(self.mappings_file)

    @staticmethod
    def _load_mappings(path: Path) -> list[dict]:
        """Load and lightly validate the mappings YAML file.

        Raises:
            FileNotFoundError: if the mappings file does not exist.
            ValueError: if the YAML is malformed or missing the
                top-level 'mappings' key.
        """
        if not path.exists():
            raise FileNotFoundError(f"Compliance mappings file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict) or "mappings" not in data:
            raise ValueError(
                f"Compliance mappings file {path} must have a top-level 'mappings' list"
            )

        rules = data["mappings"]
        if not isinstance(rules, list):
            raise ValueError(f"'mappings' in {path} must be a list")

        return rules

    def annotate_finding(self, finding: Finding) -> ComplianceControlAnnotation:
        """Return the merged compliance annotation for a single finding.

        For each rule in the knowledge base, all configured checks
        (category, severity floor, tool, port range, tags) must pass for
        the rule to match. Matching rules' controls are unioned and their
        rationale strings concatenated.

        Args:
            finding: The normalized Finding to annotate.

        Returns:
            A ComplianceControlAnnotation with the union of all matching
            rules' controls. Empty lists/rationale if nothing matched.
        """
        controls_by_framework: dict[str, set[str]] = {key: set() for key in _FRAMEWORK_KEYS}
        rationales: list[str] = []

        finding_severity_weight = severity_weight(finding.severity)

        for rule in self._rules:
            if not self._rule_matches(rule, finding, finding_severity_weight):
                continue

            controls = rule.get("controls", {}) or {}
            for key in _FRAMEWORK_KEYS:
                controls_by_framework[key].update(controls.get(key, []) or [])

            rationale = rule.get("rationale", "")
            if rationale and rationale not in rationales:
                rationales.append(rationale)

        return ComplianceControlAnnotation(
            pci_dss=sorted(controls_by_framework["pci_dss"]),
            soc2=sorted(controls_by_framework["soc2"]),
            iso27001=sorted(controls_by_framework["iso27001"]),
            nist_csf=sorted(controls_by_framework["nist_csf"]),
            cis_controls=sorted(controls_by_framework["cis_controls"]),
            rationale=" | ".join(rationales),
        )

    def annotate_all(self, findings: list[Finding]) -> dict[UUID, ComplianceControlAnnotation]:
        """Annotate a batch of findings.

        Args:
            findings: List of Findings to annotate.

        Returns:
            Mapping of finding.id -> ComplianceControlAnnotation. Findings
            with no matching rules are still included, with empty
            annotation lists, so callers can distinguish "not yet
            evaluated" from "evaluated, no matches".
        """
        return {finding.id: self.annotate_finding(finding) for finding in findings}

    @staticmethod
    def _rule_matches(rule: dict, finding: Finding, finding_severity_weight: int) -> bool:
        """Check whether a single rule applies to a finding."""
        # --- category check (empty list = match any) ---
        categories = rule.get("finding_categories") or []
        if categories:
            category_value = (
                finding.category.value
                if isinstance(finding.category, FindingCategory)
                else str(finding.category)
            )
            if category_value not in categories:
                return False

        # --- severity floor check ---
        severity_min = rule.get("severity_min")
        if severity_min is not None:
            if finding_severity_weight < severity_weight(severity_min):
                return False

        # --- tool check (empty list = match any) ---
        tools = rule.get("tools") or []
        if tools and finding.source_tool not in tools:
            return False

        # --- port range check ---
        port_range = rule.get("port_range")
        if port_range:
            if finding.port is None:
                return False
            low, high = port_range[0], port_range[1]
            if not (low <= finding.port <= high):
                return False

        # --- tags_any check (empty list = match any) ---
        tags_any = rule.get("tags_any") or []
        if tags_any:
            finding_tags = set(finding.tags or [])
            if not finding_tags.intersection(tags_any):
                return False

        return True
