"""Demo mode: run the CAPE pipeline end-to-end on bundled sample data.

This reuses the *real* plugin parsers/normalizers (NmapPlugin, NiktoPlugin,
WhatWebPlugin, WpscanPlugin) and the real ShowEngine/ComplianceMapper/audit
logger — the only thing demo mode fakes is tool execution. Everything
downstream (findings, opportunities, explainability, compliance mapping,
audit events) is produced by the same code path a live scan uses.
"""
from __future__ import annotations

import logging
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import UUID

from cape.core.audit_logger import get_audit_logger
from cape.core.workspace import WorkspaceManager
from cape.scan.engine import ScanEngine
from cape.scan.plugins.nikto import NiktoPlugin
from cape.scan.plugins.nmap import NmapPlugin
from cape.scan.plugins.whatweb import WhatWebPlugin
from cape.scan.plugins.wpscan import WpscanPlugin
from cape.shared.finding import Finding
from cape.show.engine import ShowEngine

logger = logging.getLogger(__name__)

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
DEMO_TARGET_PREFIX = "demo-"


class DemoResult:
    """Summary of a completed demo run, for the TUI/CLI to display."""

    def __init__(
        self,
        target: str,
        scan_id: UUID,
        findings: list[Finding],
        opportunities: list,
        workspace_root: Path,
    ) -> None:
        self.target = target
        self.scan_id = scan_id
        self.findings = findings
        self.opportunities = opportunities
        self.workspace_root = workspace_root

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts


def _tag_as_demo(findings: list[Finding]) -> None:
    """Mark every finding as demo data (Section 28: never claim a real scan ran)."""
    for f in findings:
        if "demo_data" not in f.tags:
            f.tags = [*f.tags, "demo_data"]
        f.extra = {**(f.extra or {}), "demo": True}


def run_demo(
    target_label: str = "lab-target.demo",
    operator: str = "demo-operator",
    workspace_manager: Optional[WorkspaceManager] = None,
) -> DemoResult:
    """Run the full SCAN(fixture) -> SHOW -> EXPLAIN -> COMPLIANCE pipeline.

    Args:
        target_label: A human-readable stand-in target name. Always
            prefixed with "demo-" so it can never be confused with a
            real assessment target in the workspace listing or DB.
        operator: Recorded in the audit trail as who ran the demo.
        workspace_manager: Optional injected workspace manager (tests).

    Returns:
        DemoResult with the findings and opportunities produced.
    """
    target = f"{DEMO_TARGET_PREFIX}{target_label}"
    scan_id = uuid.uuid4()
    audit = get_audit_logger()
    engine = ScanEngine(workspace_manager=workspace_manager)
    workspace = engine.workspace_manager.get_workspace(target)

    audit.log_scan_start(target, operator, "demo")
    logger.info(f"Starting DEMO run (no real tools executed): target={target}")

    findings: list[Finding] = []

    fixture_plugins = [
        ("nmap", NmapPlugin(), FIXTURES_DIR / "nmap" / "sample_scan.xml", "sample_scan.xml"),
        ("nikto", NiktoPlugin(), FIXTURES_DIR / "nikto" / "sample_output.txt", "sample_output.txt"),
        ("whatweb", WhatWebPlugin(), FIXTURES_DIR / "whatweb" / "sample_output.json", "sample_output.json"),
        ("wpscan", WpscanPlugin(), FIXTURES_DIR / "wpscan" / "sample_output.json", "sample_output.json"),
    ]

    for tool_name, plugin, fixture_path, filename in fixture_plugins:
        if not fixture_path.exists():
            logger.warning(f"Demo fixture missing for {tool_name}: {fixture_path}")
            continue

        # Copy the fixture into the workspace raw/ dir, same layout a real
        # scan would use, so "Open Workspace" shows exactly where the
        # (labeled) demo data came from.
        raw_dir = workspace.raw / tool_name
        raw_dir.mkdir(parents=True, exist_ok=True)
        dest = raw_dir / f"DEMO_{filename}"
        shutil.copy2(fixture_path, dest)

        try:
            items = plugin.parse_output(dest)
            tool_findings = plugin.normalize_findings(items, target, scan_id)
            findings.extend(tool_findings)
        except Exception as e:
            logger.error(f"Demo parsing failed for {tool_name}: {e}")

    _tag_as_demo(findings)

    # Create the Target + Scan rows first so FindingModel.scan_id's foreign
    # key is satisfied when _persist_findings() runs next. Still tagged as
    # a demo run via profile="demo" (never claims a real scan happened).
    try:
        from cape.db.session import db_session
        from cape.db.models import Scan, Target

        with db_session() as session:
            target_obj = session.query(Target).filter_by(hostname_or_ip=target).first()
            if not target_obj:
                target_obj = Target(hostname_or_ip=target, created_at=datetime.utcnow())
                session.add(target_obj)
                session.flush()

            session.add(Scan(
                id=str(scan_id),
                target_id=target_obj.id,
                profile="demo",
                status="COMPLETED",
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
            ))
    except Exception as e:
        logger.error(f"Failed to persist demo scan record: {e}")

    # Reuse the exact same DB persistence path a live scan uses.
    engine._persist_findings(findings, target, str(scan_id))

    audit.log_scan_complete(target, operator, len(findings))

    # Run the real SHOW -> EXPLAIN -> COMPLIANCE pipeline on the demo findings.
    opportunities = ShowEngine().analyze(target, findings)

    return DemoResult(
        target=target,
        scan_id=scan_id,
        findings=findings,
        opportunities=opportunities,
        workspace_root=workspace.root,
    )
