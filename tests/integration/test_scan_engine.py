"""Integration tests for the scan engine.

These tests require actual tools installed.
Skip with: pytest -m "not integration"
"""
from __future__ import annotations

import pytest
from pathlib import Path


@pytest.mark.integration
class TestScanEngineIntegration:
    """Integration tests that require real tools installed."""

    def test_scan_localhost_quick(self, tmp_path: Path) -> None:
        """Test quick scan against localhost."""
        from cape.core.workspace import WorkspaceManager
        from cape.scan.engine import ScanEngine

        workspace_mgr = WorkspaceManager(workspace_root=tmp_path / "workspaces")
        engine = ScanEngine(workspace_manager=workspace_mgr)

        import uuid
        result = engine.run_scan(
            target="127.0.0.1",
            profile_name="quick",
            scope_token="test-token",
            operator="test-operator",
            scan_id=uuid.uuid4(),
        )

        assert result.target == "127.0.0.1"
        assert result.profile == "quick"
        # Findings may be empty if nmap not installed, but no exception
        assert isinstance(result.findings, list)

    def test_end_to_end_scan_show_plan(self, tmp_path: Path) -> None:
        """End-to-end test: scan → show → plan with fixture findings."""
        from cape.shared.finding import FindingFactory
        from cape.shared.enums import FindingCategory, Severity
        from cape.show.engine import ShowEngine
        from cape.plan.engine import PlanEngine

        target = "192.168.1.100"

        # Create fixture findings
        findings = [
            FindingFactory.create(target=target, port=80, service="http",
                                   category=FindingCategory.PORT, severity=Severity.INFO),
            FindingFactory.create(target=target, port=443, service="https",
                                   category=FindingCategory.SERVICE, severity=Severity.INFO),
            FindingFactory.create(target=target, port=445, service="smb",
                                   category=FindingCategory.SMB, severity=Severity.HIGH,
                                   tags=["smb", "signing"]),
            FindingFactory.create(target=target, category=FindingCategory.CMS,
                                   severity=Severity.LOW, tags=["wordpress", "cms"]),
        ]

        # Show engine analysis
        show_engine = ShowEngine()
        opportunities = show_engine.analyze(target=target, findings=findings)

        assert isinstance(opportunities, list)
        # Should find at least some opportunities from the findings

        # Plan engine
        plan_engine = PlanEngine()
        plan = plan_engine.build_plan(target=target, opportunities=opportunities)

        assert plan.target == target
        assert isinstance(plan.steps, list)
