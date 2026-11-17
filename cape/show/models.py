"""Pydantic models for the show engine - opportunities and rule evaluation."""
from __future__ import annotations

import uuid
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from cape.shared.enums import AttackDomain, ConditionOp, FindingCategory, Severity


class Condition(BaseModel):
    """A single rule condition to match against a finding."""

    field: str  # Finding field path, e.g. "service", "port", "tags"
    operator: ConditionOp
    value: Any


class IndicatorRule(BaseModel):
    """A rule mapping finding conditions to attack pattern weight."""

    finding_category: FindingCategory
    conditions: list[Condition]
    weight: float = 1.0


class AttackPattern(BaseModel):
    """An attack technique template in the knowledge base."""

    id: str  # e.g. "web-sqli-001"
    name: str
    domain: AttackDomain
    description: str
    indicator_rules: list[IndicatorRule] = Field(default_factory=list)
    mitre_technique: Optional[str] = None
    cvss_base: Optional[float] = None
    references: list[str] = Field(default_factory=list)


class ServiceRule(BaseModel):
    """Maps service patterns to implied attack opportunities."""

    service_pattern: str  # regex on service name/banner
    port_range: Optional[tuple[int, int]] = None
    implied_opportunities: list[str] = Field(default_factory=list)
    risk_modifier: float = 1.0


class OpportunityRule(BaseModel):
    """Rule that identifies attack opportunities from findings."""

    id: str
    name: str
    domain: AttackDomain
    conditions: list[Condition] = Field(default_factory=list)
    required_findings: list[str] = Field(default_factory=list)  # FindingCategory values
    score_formula: str = "base * confidence * severity_weight"
    recommended_modules: list[str] = Field(default_factory=list)
    base_score: float = 5.0


class EvaluationResult(BaseModel):
    """Result of evaluating a rule against a set of findings.

    NOTE (CAPE Bug Fix #1): This evaluator does NOT score. The `score`
    field is always 0.0 here; OpportunityScorer.score() is the single
    source of truth for numeric scoring. Keeping a dead, unused score
    on this model previously misled anyone inspecting EvaluationResult
    into thinking it reflected the opportunity's final score.
    """

    rule_id: str
    matched: bool
    matched_findings: list[UUID] = Field(default_factory=list)
    score: float = 0.0  # Always 0.0. Evaluator does not score; scorer does.
    explanation: str = ""


class Opportunity(BaseModel):
    """An identified attack opportunity."""

    id: UUID = Field(default_factory=uuid.uuid4)
    target: str
    domain: AttackDomain
    attack_pattern_id: str
    rule_id: str = ""  # CAPE Bug Fix #2: direct, reliable link back to OpportunityRule.id
    name: str
    description: str
    score: float  # 0.0 - 10.0
    confidence: float
    severity: Severity
    supporting_findings: list[UUID] = Field(default_factory=list)
    recommended_modules: list[str] = Field(default_factory=list)
    mitre_technique: Optional[str] = None
    explanation: str

    model_config = {"arbitrary_types_allowed": True}

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        data = self.model_dump()
        data["id"] = str(data["id"])
        data["supporting_findings"] = [str(f) for f in data["supporting_findings"]]
        return data

