"""Unit tests for CAPE Pillar A: TracingEvaluator / OpportunityTrace."""
from __future__ import annotations

import json
import uuid

from cape.shared.enums import AttackDomain, ConditionOp, FindingCategory, Severity
from cape.shared.finding import FindingFactory
from cape.show.explain.tracing_evaluator import TracingEvaluator
from cape.show.models import Condition, Opportunity, OpportunityRule
from cape.show.rule_evaluator import RuleEvaluator
from cape.show.scorer import OpportunityScorer


def _build_matching_rule() -> OpportunityRule:
    return OpportunityRule(
        id="test-explain-rule",
        name="Test Explain Rule",
        domain=AttackDomain.WEB,
        conditions=[
            Condition(field="service", operator=ConditionOp.EQUALS, value="http"),
        ],
        required_findings=[],
        base_score=8.0,
    )


class TestTracingEvaluator:
    def setup_method(self) -> None:
        self.tracer = TracingEvaluator()
        self.rule_evaluator = RuleEvaluator()
        self.scorer = OpportunityScorer()

    def _build_real_opportunity(self):
        """Run the real pipeline (evaluator + scorer) to get a genuine Opportunity."""
        finding = FindingFactory.create(
            category=FindingCategory.SERVICE, port=80, service="http", confidence=0.9,
        )
        rule = _build_matching_rule()
        evaluation = self.rule_evaluator.evaluate([finding], [rule])[0]
        opportunity = self.scorer.score(
            evaluation=evaluation, rule=rule, findings=[finding], target="10.0.0.5",
        )
        return finding, rule, opportunity

    def test_trace_matches_score(self) -> None:
        """Recomputed score must equal the opportunity's final_score within 0.05."""
        finding, rule, opp = self._build_real_opportunity()
        trace = self.tracer.trace_rule(opp, rule, [finding])
        assert abs(trace.recomputed_score - trace.final_score) <= 0.05
        assert trace.score_consistent is True

    def test_condition_trace_records_match(self) -> None:
        """A matched condition must record the finding id that satisfied it."""
        finding, rule, opp = self._build_real_opportunity()
        trace = self.tracer.trace_rule(opp, rule, [finding])
        matched = [c for c in trace.conditions if c.matched]
        assert len(matched) == 1
        assert matched[0].matched_finding_id == finding.id
        assert matched[0].matched_finding_title == finding.title

    def test_condition_trace_records_miss(self) -> None:
        """An unmatched condition must NOT have a finding id attached."""
        finding = FindingFactory.create(service="ssh")  # won't match "http" condition
        rule = _build_matching_rule()
        evaluation = self.rule_evaluator.evaluate([finding], [rule])[0]
        assert evaluation.matched is False

        # Build a synthetic opportunity for tracing purposes even though
        # scorer.score() would return None for a non-match.
        opp = Opportunity(
            id=uuid.uuid4(), target="10.0.0.5", domain=rule.domain,
            attack_pattern_id=rule.id, rule_id=rule.id, name=rule.name,
            description="n/a", score=0.0, confidence=0.5, severity=Severity.INFO,
            supporting_findings=[], recommended_modules=[], explanation="",
        )
        trace = self.tracer.trace_rule(opp, rule, [finding])
        assert trace.conditions[0].matched is False
        assert trace.conditions[0].matched_finding_id is None
        assert trace.conditions[0].matched_finding_title is None

    def test_score_components_multiply_to_final(self) -> None:
        """The product of score_components must equal compute_check()'s result."""
        finding, rule, opp = self._build_real_opportunity()
        trace = self.tracer.trace_rule(opp, rule, [finding])
        product = 1.0
        for comp in trace.score_components:
            product *= comp.value
        expected = round(min(10.0, max(0.0, product)), 2)
        assert trace.compute_check() == expected

    def test_json_export_serializable(self) -> None:
        """trace.model_dump(mode='json') must be JSON-serializable."""
        finding, rule, opp = self._build_real_opportunity()
        trace = self.tracer.trace_rule(opp, rule, [finding])
        dumped = trace.model_dump(mode="json")
        serialized = json.dumps(dumped)  # must not raise
        assert "opportunity_id" in serialized

    def test_inconsistency_flagged(self) -> None:
        """If final_score is tampered to differ from the real computation, flag it."""
        finding, rule, opp = self._build_real_opportunity()
        opp.score = opp.score + 5.0  # simulate a stale/tampered final_score
        trace = self.tracer.trace_rule(opp, rule, [finding])
        assert trace.score_consistent is False
