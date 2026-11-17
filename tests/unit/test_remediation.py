"""Unit tests for CAPE's remediation guidance layer (catalog + mapper),
and its integration into TracingEvaluator / OpportunityTrace.
"""
from __future__ import annotations

import json
import uuid

from cape.shared.enums import AttackDomain, ConditionOp, FindingCategory, Severity
from cape.shared.finding import FindingFactory
from cape.show.explain.tracing_evaluator import TracingEvaluator
from cape.show.knowledge.loader import KnowledgeBaseLoader
from cape.show.models import Condition, Opportunity, OpportunityRule
from cape.show.remediation.mapper import RemediationMapper
from cape.show.rule_evaluator import RuleEvaluator
from cape.show.scorer import OpportunityScorer


def _build_opportunity(attack_pattern_id: str, domain: AttackDomain, severity: Severity, score: float) -> Opportunity:
    return Opportunity(
        id=uuid.uuid4(), target="10.0.0.5", domain=domain,
        attack_pattern_id=attack_pattern_id, rule_id="test-rule", name="Test Opportunity",
        description="n/a", score=score, confidence=0.8, severity=severity,
        supporting_findings=[], recommended_modules=[], explanation="",
    )


class TestRemediationCatalog:
    def setup_method(self) -> None:
        self.mapper = RemediationMapper()
        self.loader = KnowledgeBaseLoader()

    def test_every_attack_pattern_has_a_catalog_entry(self) -> None:
        """Every pattern in the knowledge base should have curated countermeasures."""
        patterns = self.loader.load_attack_patterns()
        catalog = self.mapper.load_catalog()
        for pattern in patterns:
            assert pattern.id in catalog["patterns"], f"missing catalog entry for {pattern.id}"
            entry = catalog["patterns"][pattern.id]
            assert len(entry["countermeasures"]) > 0

    def test_known_pattern_uses_catalog_source(self) -> None:
        opp = _build_opportunity("web-sqli-001", AttackDomain.WEB, Severity.HIGH, 8.58)
        plan = self.mapper.build_plan(opp)
        assert plan.source == "catalog"
        assert len(plan.countermeasures) >= 1
        assert plan.priority == "Fix this sprint"

    def test_unknown_pattern_falls_back_to_domain(self) -> None:
        opp = _build_opportunity("totally-unknown-pattern", AttackDomain.WIRELESS, Severity.MEDIUM, 5.0)
        plan = self.mapper.build_plan(opp)
        assert plan.source == "domain-fallback"
        assert len(plan.countermeasures) >= 1

    def test_severity_maps_to_priority(self) -> None:
        critical = _build_opportunity("web-sqli-001", AttackDomain.WEB, Severity.CRITICAL, 9.5)
        low = _build_opportunity("web-sqli-001", AttackDomain.WEB, Severity.LOW, 2.5)
        assert self.mapper.build_plan(critical).priority == "Fix immediately"
        assert self.mapper.build_plan(low).priority == "Track"

    def test_tool_reported_remediation_is_preserved(self) -> None:
        """A finding's own remediation text must show up as an extra countermeasure, not be dropped."""
        finding = FindingFactory.create(
            category=FindingCategory.VULNERABILITY, service="http",
        )
        finding.remediation = "Upgrade the affected library to version 4.2 or later."
        opp = _build_opportunity("web-sqli-001", AttackDomain.WEB, Severity.HIGH, 8.0)
        plan = self.mapper.build_plan(opp, findings=[finding])
        tool_titles = [cm.title for cm in plan.countermeasures if cm.title.startswith("As reported by")]
        assert any(finding.source_tool in t for t in tool_titles)

    def test_plan_serializes_to_json(self) -> None:
        opp = _build_opportunity("web-sqli-001", AttackDomain.WEB, Severity.HIGH, 8.0)
        plan = self.mapper.build_plan(opp)
        serialized = json.dumps(plan.to_dict())
        assert "countermeasures" in serialized


class TestTracingEvaluatorRemediationIntegration:
    def setup_method(self) -> None:
        self.tracer = TracingEvaluator()
        self.rule_evaluator = RuleEvaluator()
        self.scorer = OpportunityScorer()

    def _build_real_opportunity(self):
        finding = FindingFactory.create(
            category=FindingCategory.SERVICE, port=80, service="http", confidence=0.9,
        )
        rule = OpportunityRule(
            id="test-explain-rule", name="Test Explain Rule", domain=AttackDomain.WEB,
            conditions=[Condition(field="service", operator=ConditionOp.EQUALS, value="http")],
            required_findings=[], base_score=8.0,
        )
        evaluation = self.rule_evaluator.evaluate([finding], [rule])[0]
        opportunity = self.scorer.score(
            evaluation=evaluation, rule=rule, findings=[finding], target="10.0.0.5",
        )
        return finding, rule, opportunity

    def test_trace_includes_remediation_plan(self) -> None:
        finding, rule, opp = self._build_real_opportunity()
        trace = self.tracer.trace_rule(opp, rule, [finding])
        assert trace.remediation is not None
        # This rule's id has no catalog entry, so it must fall back to the domain.
        assert trace.remediation.source == "domain-fallback"
        assert len(trace.remediation.countermeasures) >= 1

    def test_trace_includes_severity_rationale(self) -> None:
        finding, rule, opp = self._build_real_opportunity()
        trace = self.tracer.trace_rule(opp, rule, [finding])
        assert trace.severity_rationale != ""
        assert opp.severity.value in trace.severity_rationale

    def test_trace_json_export_includes_remediation(self) -> None:
        finding, rule, opp = self._build_real_opportunity()
        trace = self.tracer.trace_rule(opp, rule, [finding])
        dumped = trace.model_dump(mode="json")
        serialized = json.dumps(dumped)
        assert "countermeasures" in serialized
        assert "severity_rationale" in serialized
