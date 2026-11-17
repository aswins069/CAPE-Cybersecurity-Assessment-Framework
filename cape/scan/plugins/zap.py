"""ZAP API scanner plugin for CAPE."""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from uuid import UUID

from cape.core.tool_resolver import resolve_tool_path
from cape.scan.plugins.base import BasePlugin, DependencyResult, ExecutionResult, PermissionResult, PluginOptions
from cape.shared.enums import FindingCategory, PermissionType, Severity
from cape.shared.finding import Finding, RawParsedItem


class ZapPlugin(BasePlugin):
    """OWASP ZAP API/web vulnerability scanner plugin."""

    name = "zap"
    version = "1.0.0"
    required_tool = "zaproxy"
    required_permissions = [PermissionType.NETWORK]
    supported_profiles = ["web", "api", "vuln", "full"]

    def check_dependency(self) -> DependencyResult:
        path = resolve_tool_path("zaproxy") or shutil.which("zap.sh")
        if not path:
            return DependencyResult(installed=False, missing="zaproxy not found in PATH")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        return PermissionResult(sufficient=True, message="No special permissions required")

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        output_file = options.custom.get("output_file", "/tmp/zap_output.json")
        zap_path = resolve_tool_path("zaproxy") or "zaproxy"
        return [
            zap_path,
            "-cmd",
            "-quickurl", target,
            "-quickout", output_file,
            "-quickprogress",
        ] + options.extra_args

    def execute(self, target: str, workspace: any, options: PluginOptions, timeout: int) -> ExecutionResult:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_file = workspace.raw / f"zap_{timestamp}.json"
        if options.custom is None:
            options.custom = {}
        options.custom["output_file"] = str(raw_file)
        argv = self.build_command(target, options)
        result = self._run_subprocess(argv, workspace.raw, timeout)
        result.raw_file_path = raw_file if raw_file.exists() else None
        return result

    def parse_output(self, raw_file: Path) -> list[RawParsedItem]:
        if not raw_file.exists():
            return []
        try:
            data = json.loads(raw_file.read_text(encoding="utf-8", errors="replace"))
            alerts = data.get("site", [{}])[0].get("alerts", []) if isinstance(data, dict) else []
            if not alerts and isinstance(data, list):
                alerts = data
            return [RawParsedItem(tool="zap", raw_data=a, source_file=raw_file) for a in alerts]
        except Exception:
            return []

    def normalize_findings(self, items: list[RawParsedItem], target: str, scan_id: UUID) -> list[Finding]:
        findings: list[Finding] = []
        risk_map = {"high": Severity.HIGH, "medium": Severity.MEDIUM,
                    "low": Severity.LOW, "informational": Severity.INFO}
        for item in items:
            d = item.raw_data
            risk = risk_map.get(d.get("riskdesc", "").split(" ")[0].lower(), Severity.MEDIUM)
            findings.append(Finding(
                target=target, source_tool="zap", scan_profile="web",
                category=FindingCategory.VULNERABILITY, severity=risk, confidence=0.8,
                title=d.get("alert", "ZAP Finding"),
                description=d.get("desc", d.get("description", "")),
                evidence=d.get("evidence", d.get("solution", ""))[:300],
                host=target, port=80, protocol="tcp", service="http",
                cve_ids=[d["cweid"]] if d.get("cweid") else [],
                references=[ref.get("url", "") for ref in d.get("reference", []) if isinstance(ref, dict)],
                remediation=d.get("solution", None),
                tags=["zap", "web", d.get("riskdesc", "").lower()],
            ))
        return findings
