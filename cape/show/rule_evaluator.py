"""Deterministic rule evaluator for the show engine.

Evaluates OpportunityRules against normalized findings to identify
attack opportunities. No AI/ML - pure deterministic rule matching.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

from cape.shared.finding import Finding
from cape.shared.enums import ConditionOp, FindingCategory
from cape.show.models import Condition, EvaluationResult, OpportunityRule

logger = logging.getLogger(__name__)


class RuleEvaluator:
    """Evaluates opportunity rules against a set of findings.

    Uses deterministic condition matching - EQUALS, CONTAINS, REGEX,
    IN, GT, LT, EXISTS operators. No probabilistic scoring here;
    that is handled by OpportunityScorer.
    """

    def evaluate(
        self,
        findings: list[Finding],
        rules: list[OpportunityRule],
    ) -> list[EvaluationResult]:
        """Evaluate all rules against the findings.

        Args:
            findings: Normalized findings from scan engine.
            rules: Opportunity rules from knowledge base.

        Returns:
            List of EvaluationResult, one per rule.
        """
        results: list[EvaluationResult] = []
        for rule in rules:
            result = self._evaluate_rule(rule, findings)
            results.append(result)
        return results

    def _evaluate_rule(
        self,
        rule: OpportunityRule,
        findings: list[Finding],
    ) -> EvaluationResult:
        """Evaluate a single rule against findings."""
        matched_finding_ids = []
        matched_categories: set[str] = set()

        for finding in findings:
            if self._finding_matches_any_condition(finding, rule.conditions):
                matched_finding_ids.append(finding.id)
                matched_categories.add(finding.category.value)

        # Check required_findings categories
        required_met = all(
            cat in matched_categories
            for cat in rule.required_findings
        )

        matched = bool(matched_finding_ids) and required_met

        if matched:
            explanation = self._build_explanation(rule, findings, matched_finding_ids)
        else:
            explanation = self._build_miss_explanation(rule, matched_categories)

        return EvaluationResult(
            rule_id=rule.id,
            matched=matched,
            matched_findings=matched_finding_ids,
            score=0.0,  # CAPE Bug Fix #1: evaluator never scores; OpportunityScorer does.
            explanation=explanation,
        )

    def _finding_matches_any_condition(
        self,
        finding: Finding,
        conditions: list[Condition],
    ) -> bool:
        """Return True if finding matches ALL conditions (AND logic)."""
        if not conditions:
            return True
        return all(self._match_condition(finding, cond) for cond in conditions)

    def _match_condition(self, finding: Finding, condition: Condition) -> bool:
        """Evaluate a single condition against a finding."""
        field_value = self._get_field_value(finding, condition.field)

        op = condition.operator
        expected = condition.value

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

        except (ValueError, TypeError) as e:
            logger.debug(f"Condition match error (field={condition.field}): {e}")
            return False

        return False

    def _get_field_value(self, finding: Finding, field_path: str) -> Any:
        """Get a field value from a finding, supporting dot-notation paths."""
        parts = field_path.split(".")
        obj: Any = finding

        for part in parts:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            elif isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return None

        return obj

    def _build_explanation(
        self,
        rule: OpportunityRule,
        findings: list[Finding],
        matched_ids: list,
    ) -> str:
        """Build human-readable explanation for a match."""
        matched_findings = [f for f in findings if f.id in matched_ids]
        parts = [f"Rule '{rule.name}' matched {len(matched_findings)} finding(s):"]
        for f in matched_findings[:3]:  # Show top 3
            parts.append(f"  • {f.title} [{f.severity.value}]")
        if len(matched_findings) > 3:
            parts.append(f"  • ... and {len(matched_findings) - 3} more")
        return "\n".join(parts)

    def _build_miss_explanation(
        self,
        rule: OpportunityRule,
        matched_categories: set[str],
    ) -> str:
        """Explain why a rule did not match."""
        missing = [
            cat for cat in rule.required_findings
            if cat not in matched_categories
        ]
        if missing:
            return f"Rule '{rule.name}': missing required finding categories: {missing}"
        return f"Rule '{rule.name}': no findings matched conditions"
