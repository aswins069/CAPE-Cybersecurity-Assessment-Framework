"""Unit tests for the rule evaluator."""
from __future__ import annotations

import pytest

from cape.shared.enums import AttackDomain, ConditionOp, FindingCategory, Severity
from cape.shared.finding import FindingFactory
from cape.show.models import Condition, OpportunityRule
from cape.show.rule_evaluator import RuleEvaluator


class TestRuleEvaluator:
    """Tests for deterministic rule condition matching."""

    def setup_method(self):
        self.evaluator = RuleEvaluator()

    def _make_rule(self, conditions, required=None, base_score=5.0) -> OpportunityRule:
        return OpportunityRule(
            id="test-rule-001", name="Test Rule",
            domain=AttackDomain.WEB, conditions=conditions,
            required_findings=required or [], base_score=base_score,
            recommended_modules=["TestModule"],
        )

    def test_equals_condition_match(self):
        """EQUALS operator matches exact values case-insensitively."""
        finding = FindingFactory.create(service="http")
        rule = self._make_rule([Condition(field="service", operator=ConditionOp.EQUALS, value="HTTP")])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched

    def test_equals_condition_no_match(self):
        """EQUALS operator does not match different values."""
        finding = FindingFactory.create(service="ssh")
        rule = self._make_rule([Condition(field="service", operator=ConditionOp.EQUALS, value="http")])
        results = self.evaluator.evaluate([finding], [rule])
        assert not results[0].matched

    def test_contains_condition_list(self):
        """CONTAINS operator works on list fields like tags."""
        finding = FindingFactory.create(tags=["smb", "signing", "relay"])
        rule = self._make_rule([Condition(field="tags", operator=ConditionOp.CONTAINS, value="signing")])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched

    def test_contains_condition_string(self):
        """CONTAINS operator works on string fields."""
        finding = FindingFactory.create(title="SMB Signing Disabled")
        rule = self._make_rule([Condition(field="title", operator=ConditionOp.CONTAINS, value="Signing")])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched

    def test_in_condition_match(self):
        """IN operator matches when value is in list."""
        finding = FindingFactory.create(port=80)
        rule = self._make_rule([Condition(field="port", operator=ConditionOp.IN, value=[80, 443, 8080])])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched

    def test_in_condition_no_match(self):
        """IN operator does not match when value not in list."""
        finding = FindingFactory.create(port=22)
        rule = self._make_rule([Condition(field="port", operator=ConditionOp.IN, value=[80, 443])])
        results = self.evaluator.evaluate([finding], [rule])
        assert not results[0].matched

    def test_gt_condition(self):
        """GT operator matches when field value is greater than threshold."""
        finding = FindingFactory.create(port=443)
        rule = self._make_rule([Condition(field="port", operator=ConditionOp.GT, value=80)])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched

    def test_lt_condition(self):
        """LT operator matches when field value is less than threshold."""
        finding = FindingFactory.create(port=22)
        rule = self._make_rule([Condition(field="port", operator=ConditionOp.LT, value=80)])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched

    def test_exists_condition(self):
        """EXISTS operator matches when field has a value."""
        finding = FindingFactory.create(service="http")
        rule = self._make_rule([Condition(field="service", operator=ConditionOp.EXISTS, value=None)])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched

    def test_regex_condition(self):
        """REGEX operator matches on pattern."""
        finding = FindingFactory.create(service="nginx/1.18.0")
        rule = self._make_rule([Condition(field="service", operator=ConditionOp.REGEX, value=r"nginx/\d+")])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched

    def test_multiple_conditions_all_must_match(self):
        """All conditions in a rule must match (AND logic)."""
        finding = FindingFactory.create(port=80, service="http")
        rule = self._make_rule([
            Condition(field="port", operator=ConditionOp.EQUALS, value=80),
            Condition(field="service", operator=ConditionOp.EQUALS, value="http"),
        ])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched

    def test_multiple_conditions_partial_fail(self):
        """Rule fails if any condition does not match."""
        finding = FindingFactory.create(port=80, service="ssh")
        rule = self._make_rule([
            Condition(field="port", operator=ConditionOp.EQUALS, value=80),
            Condition(field="service", operator=ConditionOp.EQUALS, value="http"),
        ])
        results = self.evaluator.evaluate([finding], [rule])
        assert not results[0].matched

    def test_required_findings_not_met(self):
        """Rule fails if required finding category is missing."""
        finding = FindingFactory.create(category=FindingCategory.PORT)
        rule = self._make_rule(
            conditions=[Condition(field="port", operator=ConditionOp.GT, value=0)],
            required=["SMB"],
        )
        results = self.evaluator.evaluate([finding], [rule])
        assert not results[0].matched

    def test_matched_findings_in_result(self):
        """Matched finding IDs are included in evaluation result."""
        finding = FindingFactory.create(port=80, service="http")
        rule = self._make_rule([Condition(field="service", operator=ConditionOp.EQUALS, value="http")])
        results = self.evaluator.evaluate([finding], [rule])
        assert finding.id in results[0].matched_findings

    def test_score_always_zero_evaluator_does_not_score(self):
        """CAPE Bug Fix #1: RuleEvaluator never scores - score is always 0.0
        regardless of match status. OpportunityScorer is the sole source
        of truth for numeric scoring."""
        finding = FindingFactory.create(port=80, service="http")
        rule = self._make_rule([Condition(field="service", operator=ConditionOp.EQUALS, value="http")])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].matched is True
        assert results[0].score == 0.0

    def test_score_zero_when_not_matched(self):
        """Score should be 0 when rule does not match."""
        finding = FindingFactory.create(service="ssh")
        rule = self._make_rule([Condition(field="service", operator=ConditionOp.EQUALS, value="http")])
        results = self.evaluator.evaluate([finding], [rule])
        assert results[0].score == 0.0
