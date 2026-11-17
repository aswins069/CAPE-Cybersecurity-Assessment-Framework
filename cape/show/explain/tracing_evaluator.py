"""CAPE Pillar A — TracingEvaluator.

Rebuilds, step-by-step, exactly how an opportunity's rule conditions
were matched and exactly how its score was computed. This module
NEVER decides the final score - it takes final_score as a parameter
(the number that was actually shown to the operator) and independently
recomputes a candidate score purely as a consistency check.
"""
from __future__ import annotations

import re
from typing import Optional

from cape.shared.constants import DOMAIN_WEIGHTS
from cape.shared.enums import ConditionOp
from cape.shared.finding import Finding
from cape.show.explain.trace_models import (
    ConditionTrace,
    FindingTrace,
    OpportunityTrace,
    ScoreComponent,
)
from cape.show.models import AttackPattern, Opportunity, OpportunityRule
from cape.show.remediation.mapper import RemediationMapper

_SCORE_TOLERANCE = 0.05
_EVIDENCE_TRUNCATE_LEN = 300

# Mirrors OpportunityScorer._score_to_severity's thresholds, low to high,
# so _severity_rationale can explain distance to the next band without
# re-deriving the boundaries from scratch.
_SEVERITY_BANDS = [
    ("INFO", 0.0, 2.0),
    ("LOW", 2.0, 4.0),
    ("MEDIUM", 4.0, 7.0),
    ("HIGH", 7.0, 9.0),
    ("CRITICAL", 9.0, 10.0),
]


class TracingEvaluator:
    """Re-derives an OpportunityTrace from a rule, findings, and a final score.

    This class deliberately duplicates the condition-matching logic of
    RuleEvaluator._match_condition and the scoring arithmetic of
    OpportunityScorer.score(), but in "explain mode": every intermediate
    value is captured rather than discarded. It never recomputes the
    final score and silently presents that as truth - the final_score
    parameter is always what's shown, and the recomputed value is only
    ever a cross-check against it.
    """

    def __init__(self, remediation_mapper: Optional[RemediationMapper] = None) -> None:
        """Initialize, optionally with a custom RemediationMapper (mainly for tests)."""
        self.remediation_mapper = remediation_mapper or RemediationMapper()

    def trace_rule(
        self,
        opportunity: Opportunity,
        rule: OpportunityRule,
        findings: list[Finding],
        attack_pattern: Optional[AttackPattern] = None,
        deep: bool = False,
    ) -> OpportunityTrace:
        """Build a full OpportunityTrace for one opportunity.

        Args:
            opportunity: The Opportunity to explain (provides final_score,
                final_severity, target, name, rule_id as actually persisted).
            rule: The OpportunityRule that produced this opportunity.
            findings: The findings to re-run conditions against (should
                include at least all of opportunity.supporting_findings).
            attack_pattern: Optional attack pattern used in scoring.
            deep: If True, FindingTrace.raw_output_file is populated so
                the renderer can show raw tool output.

        Returns:
            A fully populated OpportunityTrace.
        """
        matched_categories: set[str] = set()
        condition_traces: list[ConditionTrace] = []

        # Re-run EVERY condition check, recording each step.
        for condition in rule.conditions:
            condition_traces.append(
                self._trace_condition(condition, findings, matched_categories)
            )

        required_findings_met = all(
            cat in matched_categories for cat in rule.required_findings
        )

        matched_finding_ids = set(opportunity.supporting_findings)
        matched_findings = [f for f in findings if f.id in matched_finding_ids]

        # Rebuild every score component from OpportunityScorer's formula:
        #   final_score = base_cvss * avg_confidence * domain_weight * coverage_ratio
        score_components = self._rebuild_score_components(
            rule=rule,
            matched_findings=matched_findings,
            attack_pattern=attack_pattern,
        )

        supporting = [
            self._trace_finding(f, deep=deep) for f in matched_findings
        ]

        trace = OpportunityTrace(
            opportunity_id=opportunity.id,
            opportunity_name=opportunity.name,
            rule_id=opportunity.rule_id or rule.id,
            target=opportunity.target,
            final_score=opportunity.score,
            final_severity=opportunity.severity.value,
            conditions=condition_traces,
            required_findings_met=required_findings_met,
            required_findings_list=list(rule.required_findings),
            score_components=score_components,
            supporting_findings=supporting,
            recomputed_score=0.0,  # placeholder, set below
            score_consistent=False,  # placeholder, set below
        )

        # Recompute as a sanity check ONLY - never used as the displayed score.
        recomputed = trace.compute_check()
        trace.recomputed_score = recomputed
        trace.score_consistent = abs(recomputed - opportunity.score) <= _SCORE_TOLERANCE

        trace.severity_rationale = self._severity_rationale(opportunity.score, opportunity.severity.value)

        # Attach concrete countermeasures for this opportunity's attack
        # pattern (or its domain, if no specific catalog entry exists).
        trace.remediation = self.remediation_mapper.build_plan(
            opportunity=opportunity,
            attack_pattern=attack_pattern,
            findings=matched_findings,
        )

        return trace

    def _severity_rationale(self, score: float, severity: str) -> str:
        """Plain-language explanation of why the score landed in this band.

        Names the current band's bounds and, where relevant, how far the
        score sits from the next band up or down - so an operator can see
        exactly what would need to change (e.g. more supporting findings,
        higher confidence) to shift the severity.
        """
        band = next((b for b in _SEVERITY_BANDS if b[0] == severity), None)
        if band is None:
            return f"Score {score:.2f} maps to severity {severity}."

        _, low, high = band
        idx = _SEVERITY_BANDS.index(band)

        parts = [f"Score {score:.2f} falls in the {severity} band ({low:.1f}-{high:.1f})."]

        if idx < len(_SEVERITY_BANDS) - 1:
            next_label, next_low, _ = _SEVERITY_BANDS[idx + 1]
            gap = next_low - score
            if gap > 0:
                parts.append(f"{gap:.2f} more would push it into {next_label}.")
        if idx > 0:
            prev_label, _, prev_high = _SEVERITY_BANDS[idx - 1]
            cushion = score - low
            parts.append(f"It is {cushion:.2f} above the {prev_label}/{severity} boundary.")

        return " ".join(parts)

    def _trace_condition(
        self,
        condition,
        findings: list[Finding],
        matched_categories: set[str],
    ) -> ConditionTrace:
        """Re-run one condition against every finding, recording the first match."""
        expected_str = str(condition.value)

        for finding in findings:
            actual_value = self._get_field_value(finding, condition.field)
            if self._match_condition(actual_value, condition.operator, condition.value):
                matched_categories.add(finding.category.value)
                return ConditionTrace(
                    field=condition.field,
                    operator=condition.operator.value,
                    expected_value=expected_str,
                    matched=True,
                    matched_finding_id=finding.id,
                    matched_finding_title=finding.title,
                    actual_value_seen=str(actual_value),
                )

        # No finding satisfied this condition.
        last_seen = (
            str(self._get_field_value(findings[-1], condition.field))
            if findings else None
        )
        return ConditionTrace(
            field=condition.field,
            operator=condition.operator.value,
            expected_value=expected_str,
            matched=False,
            matched_finding_id=None,
            matched_finding_title=None,
            actual_value_seen=last_seen,
        )

    def _rebuild_score_components(
        self,
        rule: OpportunityRule,
        matched_findings: list[Finding],
        attack_pattern: Optional[AttackPattern],
    ) -> list[ScoreComponent]:
        """Rebuild each factor of OpportunityScorer's scoring formula."""
        domain_weight = DOMAIN_WEIGHTS.get(rule.domain.value, 1.0)

        total_conditions = max(len(rule.conditions), 1)
        coverage_ratio = min(len(matched_findings) / total_conditions, 1.0)

        avg_confidence = (
            sum(f.confidence for f in matched_findings) / len(matched_findings)
            if matched_findings else 0.5
        )

        if attack_pattern and attack_pattern.cvss_base:
            base_cvss = attack_pattern.cvss_base
            base_source = f"attack_pattern '{attack_pattern.id}'.cvss_base"
        else:
            base_cvss = rule.base_score
            base_source = f"rule '{rule.id}'.base_score (no attack pattern cvss_base)"

        return [
            ScoreComponent(label="base_cvss", value=round(base_cvss, 3), source=base_source),
            ScoreComponent(
                label="avg_confidence",
                value=round(avg_confidence, 3),
                source=(
                    f"mean confidence across {len(matched_findings)} supporting finding(s)"
                    if matched_findings else "default 0.5 (no supporting findings)"
                ),
            ),
            ScoreComponent(
                label="domain_weight",
                value=round(domain_weight, 3),
                source=f"DOMAIN_WEIGHTS['{rule.domain.value}']",
            ),
            ScoreComponent(
                label="coverage_ratio",
                value=round(coverage_ratio, 3),
                source=(
                    f"{len(matched_findings)} matched / {total_conditions} "
                    f"condition(s) on rule, capped at 1.0"
                ),
            ),
        ]

    def _trace_finding(self, finding: Finding, deep: bool) -> FindingTrace:
        """Build a FindingTrace for one supporting finding."""
        evidence = finding.evidence or ""
        truncated = (
            evidence[:_EVIDENCE_TRUNCATE_LEN] + "..."
            if len(evidence) > _EVIDENCE_TRUNCATE_LEN else evidence
        )
        raw_path = None
        if deep and finding.raw_output_file:
            raw_path = str(finding.raw_output_file)

        return FindingTrace(
            finding_id=finding.id,
            title=finding.title,
            source_tool=finding.source_tool,
            confidence=finding.confidence,
            severity=finding.severity.value,
            evidence=truncated,
            raw_output_file=raw_path,
        )

    # --- Condition matching, duplicated in "explain mode" from RuleEvaluator ---
    # Kept in lockstep with show/rule_evaluator.py._match_condition /
    # ._get_field_value so that the trace reflects exactly what the real
    # evaluation pipeline does. If those methods change, this must change too.

    def _get_field_value(self, finding: Finding, field_path: str):
        """Get a field value from a finding, supporting dot-notation paths."""
        parts = field_path.split(".")
        obj = finding
        for part in parts:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            elif isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return None
        return obj

    def _match_condition(self, field_value, op: ConditionOp, expected) -> bool:
        """Evaluate a single condition - mirrors RuleEvaluator._match_condition."""
        try:
            if op == ConditionOp.EXISTS:
                return field_value is not None and field_value != "" and field_value != []

            if field_value is None:
                return False

            if op == ConditionOp.EQUALS:
                if isinstance(field_value, str) and isinstance(expected, str):
                    return field_value.lower() == expected.lower()
                return field_value == expected

            elif op == ConditionOp.CONTAINS:
                if isinstance(field_value, list):
                    return any(
                        str(expected).lower() in str(item).lower()
                        for item in field_value
                    )
                return str(expected).lower() in str(field_value).lower()

            elif op == ConditionOp.REGEX:
                return bool(re.search(str(expected), str(field_value), re.IGNORECASE))

            elif op == ConditionOp.IN:
                if isinstance(expected, list):
                    if isinstance(field_value, list):
                        return any(
                            str(v).lower() in [str(e).lower() for e in expected]
                            for v in field_value
                        )
                    return str(field_value).lower() in [str(e).lower() for e in expected]
                return False

            elif op == ConditionOp.GT:
                return float(field_value) > float(expected)

            elif op == ConditionOp.LT:
                return float(field_value) < float(expected)

        except (ValueError, TypeError):
            return False

        return False
