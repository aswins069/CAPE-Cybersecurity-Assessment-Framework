"""Unit tests for DependencyChecker."""
from __future__ import annotations
import pytest
from cape.core.dependency_checker import DependencyChecker
from cape.shared.enums import CheckStatus

class TestDependencyChecker:
    def setup_method(self):
        self.checker = DependencyChecker()

    def test_python_version_ok(self):
        result = self.checker.check_python_version()
        assert result.status == CheckStatus.OK
        assert result.version is not None

    def test_check_nonexistent_tool(self):
        result = self.checker.check_tool("definitely_not_a_real_tool_xyz123")
        assert result.status == CheckStatus.FAIL
        assert result.status.value == "FAIL"

    def test_run_all_checks_returns_list(self):
        results = self.checker.run_all_checks()
        assert isinstance(results, list)
        assert len(results) > 0

    def test_all_results_have_name(self):
        results = self.checker.run_all_checks()
        for r in results:
            assert r.name
            assert r.status in CheckStatus
