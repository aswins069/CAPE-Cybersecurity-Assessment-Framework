"""CAPE Pillar A(+) — Remediation guidance data models.

These models capture concrete countermeasures for a scored Opportunity:
what to do right now, what to fix properly, how to stop the whole class
of bug from recurring, and how to prove the fix actually worked.
"""
from __future__ import annotations

from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class Countermeasure(BaseModel):
    """One concrete action that reduces or removes a vulnerability."""

    title: str
    description: str
    stage: str  # "immediate" | "short_term" | "long_term"
    effort: str = "medium"  # "low" | "medium" | "high"
    mitre_mitigation: Optional[str] = None  # e.g. "M1042"
    references: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    """The full, prioritized remediation guidance for one Opportunity.

    `source` records where the guidance came from so operators can tell
    curated, pattern-level advice from a generic domain fallback or a
    one-off remediation string a scan tool happened to report.
    """

    opportunity_id: Optional[UUID] = None
    attack_pattern_id: str
    target: str = ""
    priority: str  # "Fix immediately" | "Fix this sprint" | "Schedule" | "Track"
    summary: str
    countermeasures: list[Countermeasure] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    residual_risk_note: Optional[str] = None
    source: str = "catalog"  # "catalog" | "domain-fallback" | "tool-supplied"

    def to_dict(self) -> dict:
        """Serialize to a plain dict (UUIDs as strings)."""
        data = self.model_dump()
        if data.get("opportunity_id"):
            data["opportunity_id"] = str(data["opportunity_id"])
        return data
