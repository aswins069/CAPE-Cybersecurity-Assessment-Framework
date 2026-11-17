"""Opportunity scorer for the show engine.

Implements the scoring formula:
  score = base_cvss * confidence * domain_weight * coverage_ratio
Clamped to 0.0-10.0, rounded to 2 decimal places.
"""
from __future__ import annotations

import uuid
from typing import Optional

from cape.shared.constants import DOMAIN_WEIGHTS, SEVERITY_WEIGHTS
from cape.shared.enums import AttackDomain, Severity
from cape.shared.finding import Finding
from cape.show.models import (
    AttackPattern,
    EvaluationResult,
    Opportunity,
    OpportunityRule,
)


class OpportunityScorer:
    """Converts evaluation results into scored Opportunity objects."""

    def score(
        self,
        evaluation: EvaluationResult,
        rule: OpportunityRule,
        findings: list[Finding],
        attack_pattern: Optional[AttackPattern] = None,
        target: str = "",
    ) -> Optional[Opportunity]:
        """Create a scored Opportunity from an evaluation result.

        Args:
            evaluation: Result from RuleEvaluator.
            rule: The OpportunityRule that was evaluated.
            findings: All findings (to look up matched ones).
            attack_pattern: Optional attack pattern for extra context.
            target: Target being assessed.

        Returns:
            Scored Opportunity, or None if evaluation did not match.
        """
        if not evaluation.matched:
            return None

        matched_findings = [f for f in findings if f.id in evaluation.matched_findings]

        # Compute domain weight
        domain_weight = DOMAIN_WEIGHTS.get(rule.domain.value, 1.0)

        # Compute coverage ratio
        total_conditions = max(len(rule.conditions), 1)
        coverage_ratio = min(len(matched_findings) / total_conditions, 1.0)

        # Average confidence from matched findings
        avg_confidence = (
            sum(f.confidence for f in matched_findings) / len(matched_findings)
            if matched_findings else 0.5
        )

        # Base CVSS from attack pattern or rule base score
        base_cvss = (
            attack_pattern.cvss_base
            if attack_pattern and attack_pattern.cvss_base
            else rule.base_score
        )

        # Final score
        raw_score = base_cvss * avg_confidence * domain_weight * coverage_ratio
        final_score = round(min(10.0, max(0.0, raw_score)), 2)

        # Determine severity from score
        severity = self._score_to_severity(final_score)

        # MITRE technique
        mitre = attack_pattern.mitre_technique if attack_pattern else None

        return Opportunity(
            id=uuid.uuid4(),
            target=target,
            domain=rule.domain,
            attack_pattern_id=attack_pattern.id if attack_pattern else rule.id,
            rule_id=rule.id,
            name=rule.name,
            description=(
                attack_pattern.description if attack_pattern else rule.name
            ),
            score=final_score,
            confidence=round(avg_confidence, 3),
            severity=severity,
            supporting_findings=evaluation.matched_findings,
            recommended_modules=rule.recommended_modules,
            mitre_technique=mitre,
            explanation=evaluation.explanation,
        )

    def _score_to_severity(self, score: float) -> Severity:
        """Convert numeric score to Severity enum."""
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score >= 2.0:
            return Severity.LOW
        return Severity.INFO
