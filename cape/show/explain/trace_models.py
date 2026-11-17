"""CAPE Pillar A — Explainability trace data models.

These models capture, step by step, exactly how an Opportunity's score
and severity were derived: which rule conditions matched (and on which
finding), where every number in the scoring formula came from, and a
recomputed sanity check against the score that was actually shown to
the operator.
"""
from __future__ import annotations

from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from cape.show.remediation.models import RemediationPlan


class ConditionTrace(BaseModel):
    """The result of re-running a single rule condition against findings."""

    field: str
    operator: str
    expected_value: str
    matched: bool
    matched_finding_id: Optional[UUID] = None
    matched_finding_title: Optional[str] = None
    actual_value_seen: Optional[str] = None


class ScoreComponent(BaseModel):
    """One factor in the scoring formula, with provenance."""

    label: str  # "base_cvss", "avg_confidence", "domain_weight", "coverage_ratio"
    value: float
    source: str  # where this number came from, e.g. "rule.base_score (no attack pattern)"


class FindingTrace(BaseModel):
    """A supporting finding, with the evidence that justified the match."""

    finding_id: UUID
    title: str
    source_tool: str
    confidence: float
    severity: str
    evidence: str  # truncated raw evidence snippet
    raw_output_file: Optional[str] = None  # path to raw file, if --deep requested


class OpportunityTrace(BaseModel):
    """The full, auditable derivation of one Opportunity's score.

    `final_score` is always taken as given (what was actually shown to
    the operator); `recomputed_score` is independently rebuilt from the
    score formula as a consistency check. The two should agree within
    0.05 - if they don't, `score_consistent` is False and something in
    the scoring pipeline has drifted out of sync with what was reported.
    """

    opportunity_id: UUID
    opportunity_name: str
    rule_id: str
    target: str
    final_score: float
    final_severity: str
    conditions: list[ConditionTrace] = Field(default_factory=list)
    required_findings_met: bool
    required_findings_list: list[str] = Field(default_factory=list)
    score_components: list[ScoreComponent] = Field(default_factory=list)
    score_formula_string: str = (
        "score = base_cvss × avg_confidence × domain_weight × coverage_ratio"
    )
    supporting_findings: list[FindingTrace] = Field(default_factory=list)
    recomputed_score: float
    score_consistent: bool
    # Plain-language read on *why* the score landed in this severity band,
    # and what would have to change to move it into the next one up/down.
    severity_rationale: str = ""
    # Concrete countermeasures for this opportunity's attack pattern.
    remediation: Optional[RemediationPlan] = None

    def compute_check(self) -> float:
        """Recompute the score by multiplying all score_components together.

        Clamped to [0, 10] and rounded to 2 decimal places, mirroring
        OpportunityScorer's own clamping. This MUST match final_score
        (within tolerance) or something in the scoring pipeline has
        drifted out of sync with what was actually shown to the operator.
        """
        product = 1.0
        for component in self.score_components:
            product *= component.value
        return round(min(10.0, max(0.0, product)), 2)
