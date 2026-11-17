"""Unit tests for OpportunityScorer."""
from __future__ import annotations

from cape.show.scorer import OpportunityScorer
from cape.show.models import EvaluationResult, OpportunityRule
from cape.shared.enums import AttackDomain
from cape.shared.finding import FindingFactory
import uuid


class TestOpportunityScorer:
    """Tests for the opportunity scoring formula."""

    def setup_method(self):
        self.scorer = OpportunityScorer()

    def _make_rule(self, base_score=8.0) -> OpportunityRule:
        return OpportunityRule(
            id="test-rule-001", name="Test Rule",
            domain=AttackDomain.WEB, base_score=base_score,
            recommended_modules=["TestModule"],
        )

    def test_returns_none_when_not_matched(self):
        """Returns None for unmatched evaluation."""
        rule = self._make_rule()
        eval_result = EvaluationResult(rule_id="test-rule-001", matched=False, score=0.0)
        result = self.scorer.score(eval_result, rule, [], target="192.168.1.1")
        assert result is None

    def test_returns_opportunity_when_matched(self):
        """Returns Opportunity when evaluation matched."""
        finding = FindingFactory.create(confidence=0.9)
        rule = self._make_rule(base_score=8.0)
        eval_result = EvaluationResult(
            rule_id="test-rule-001", matched=True,
            matched_findings=[finding.id], score=6.0,
        )
        result = self.scorer.score(eval_result, rule, [finding], target="192.168.1.1")
        assert result is not None
        assert result.score > 0.0

    def test_score_clamped_to_10(self):
        """Score is always <= 10.0."""
        finding = FindingFactory.create(confidence=1.0)
        rule = self._make_rule(base_score=10.0)
        eval_result = EvaluationResult(
            rule_id="test-rule-001", matched=True,
            matched_findings=[finding.id], score=10.0,
        )
        result = self.scorer.score(eval_result, rule, [finding], target="192.168.1.1")
        assert result is not None
        assert result.score <= 10.0

    def test_score_is_non_negative(self):
        """Score is always >= 0.0."""
        finding = FindingFactory.create(confidence=0.1)
        rule = self._make_rule(base_score=1.0)
        eval_result = EvaluationResult(
            rule_id="test-rule-001", matched=True,
            matched_findings=[finding.id], score=1.0,
        )
        result = self.scorer.score(eval_result, rule, [finding], target="192.168.1.1")
        assert result is not None
        assert result.score >= 0.0

    def test_higher_confidence_gives_higher_score(self):
        """Higher confidence findings lead to higher scores."""
        rule = self._make_rule(base_score=8.0)

        low_conf = FindingFactory.create(confidence=0.2)
        high_conf = FindingFactory.create(confidence=0.95)

        eval_low = EvaluationResult(rule_id="test-rule-001", matched=True, matched_findings=[low_conf.id], score=4.0)
        eval_high = EvaluationResult(rule_id="test-rule-001", matched=True, matched_findings=[high_conf.id], score=7.0)

        result_low = self.scorer.score(eval_low, rule, [low_conf], target="t")
        result_high = self.scorer.score(eval_high, rule, [high_conf], target="t")

        assert result_low is not None
        assert result_high is not None
        assert result_high.score > result_low.score

    def test_score_rounded_to_2_decimals(self):
        """Score is rounded to 2 decimal places."""
        finding = FindingFactory.create(confidence=0.7777)
        rule = self._make_rule(base_score=7.333)
        eval_result = EvaluationResult(rule_id="test-rule-001", matched=True, matched_findings=[finding.id], score=5.5)
        result = self.scorer.score(eval_result, rule, [finding], target="192.168.1.1")
        assert result is not None
        assert result.score == round(result.score, 2)


class TestTargetValidator:
    """Tests for target input validation."""

    def setup_method(self):
        from cape.core.target_validator import TargetValidator
        self.validator = TargetValidator()

    def test_valid_ipv4(self):
        assert self.validator.validate("192.168.1.1") == "192.168.1.1"

    def test_valid_ipv6(self):
        assert self.validator.validate("::1") == "::1"

    def test_valid_hostname(self):
        assert self.validator.validate("example.com") == "example.com"

    def test_valid_hostname_subdomain(self):
        assert self.validator.validate("sub.example.com") == "sub.example.com"

    def test_valid_cidr(self):
        assert self.validator.validate("192.168.0.0/24") == "192.168.0.0/24"

    def test_valid_url(self):
        assert self.validator.validate("http://example.com") == "http://example.com"

    def test_valid_https_url(self):
        assert self.validator.validate("https://example.com/path") == "https://example.com/path"

    def test_rejects_shell_metachar_semicolon(self):
        from cape.core.exceptions import TargetValidationError
        with pytest.raises(TargetValidationError):
            self.validator.validate("192.168.1.1; id")

    def test_rejects_shell_metachar_pipe(self):
        from cape.core.exceptions import TargetValidationError
        with pytest.raises(TargetValidationError):
            self.validator.validate("192.168.1.1|ls")

    def test_rejects_shell_metachar_backtick(self):
        from cape.core.exceptions import TargetValidationError
        with pytest.raises(TargetValidationError):
            self.validator.validate("192.168.1.1`whoami`")

    def test_rejects_empty_string(self):
        from cape.core.exceptions import TargetValidationError
        with pytest.raises(TargetValidationError):
            self.validator.validate("")

    def test_target_type_ip(self):
        assert self.validator.target_type("192.168.1.1") == "ip"

    def test_target_type_hostname(self):
        assert self.validator.target_type("example.com") == "hostname"

    def test_target_type_cidr(self):
        assert self.validator.target_type("10.0.0.0/8") == "cidr"

    def test_target_type_url(self):
        assert self.validator.target_type("http://example.com") == "url"


class TestSession:
    """Tests for the simplified session-identity helper (formerly the
    scope gate authorization system, now removed)."""

    def test_operator_is_a_string(self):
        from cape.core.session import get_operator
        assert isinstance(get_operator(), str)
        assert get_operator()

    def test_new_session_returns_operator_and_token(self):
        from cape.core.session import new_session
        operator, token = new_session("192.168.1.1")
        assert isinstance(operator, str) and operator
        assert isinstance(token, str)
        assert len(token) == 32

    def test_new_session_needs_no_scope_file_or_prompt(self):
        """The whole point of removing the scope gate: starting a session
        for any target just works, with no file/prompt/expiry involved."""
        from cape.core.session import new_session
        for target in ("192.168.1.1", "10.0.0.0/8", "example.com"):
            operator, token = new_session(target)
            assert operator and token


class TestFindingSchema:
    """Tests for Finding model serialization and validation."""

    def test_create_finding(self):
        """Test creating a Finding with defaults."""
        from cape.shared.finding import FindingFactory
        f = FindingFactory.create()
        assert f.target == "192.168.1.1"
        assert f.source_tool == "nmap"
        assert 0.0 <= f.confidence <= 1.0

    def test_confidence_clamped(self):
        """Confidence validates boundary values correctly."""
        from cape.shared.finding import FindingFactory
        f = FindingFactory.create(confidence=1.0)
        assert f.confidence == 1.0
        f2 = FindingFactory.create(confidence=0.0)
        assert f2.confidence == 0.0

    def test_cvss_clamped(self):
        """CVSS score is clamped to 0-10."""
        from cape.shared.finding import Finding
        from cape.shared.enums import FindingCategory, Severity
        f = Finding(
            target="t", source_tool="t", scan_profile="t",
            category=FindingCategory.VULNERABILITY, severity=Severity.CRITICAL,
            confidence=0.9, title="t", description="t", evidence="t", host="t",
            cvss_score=15.0,
        )
        assert f.cvss_score == 10.0

    def test_to_dict_serialization(self):
        """to_dict returns serializable dict."""
        from cape.shared.finding import FindingFactory
        f = FindingFactory.create()
        d = f.to_dict()
        import json
        json_str = json.dumps(d)  # Should not raise
        assert isinstance(json_str, str)

    def test_uuid_auto_generated(self):
        """ID is auto-generated as UUID."""
        from cape.shared.finding import FindingFactory
        f1 = FindingFactory.create()
        f2 = FindingFactory.create()
        assert f1.id != f2.id


import pytest
