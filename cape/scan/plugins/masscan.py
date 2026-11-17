"""Masscan high-speed port scanner plugin."""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from uuid import UUID

from cape.core.tool_resolver import resolve_tool_path
from cape.scan.plugins.base import (
    BasePlugin, DependencyResult, ExecutionResult, PermissionResult, PluginOptions,
)
from cape.shared.enums import FindingCategory, PermissionType, Severity
from cape.shared.finding import Finding, RawParsedItem


class MasscanPlugin(BasePlugin):
    """Masscan high-speed port scanner plugin."""

    name = "masscan"
    version = "1.0.0"
    required_tool = "masscan"
    required_permissions = [PermissionType.ROOT]
    supported_profiles = ["recon", "network", "full"]
    skip_on_insufficient_permissions = True  # masscan raw sockets need root; no point launching

    def check_dependency(self) -> DependencyResult:
        path = resolve_tool_path("masscan")
        if not path:
            return DependencyResult(installed=False, missing="masscan not found in PATH")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        import os
        if os.geteuid() == 0:
            return PermissionResult(sufficient=True, message="Running as root")
        return PermissionResult(sufficient=False, required=[PermissionType.ROOT],
                                message="masscan requires root privileges")

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        output_file = options.custom.get("output_file", "/tmp/masscan_output.json")
        ports = options.ports or "1-65535"
        rate = options.rate or 1000
        return ["masscan", target, "-p", ports, "--rate", str(rate),
                "--output-format", "json", "--output-filename", output_file]

    def execute(self, target: str, workspace: any, options: PluginOptions, timeout: int) -> ExecutionResult:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_file = workspace.raw / f"masscan_{timestamp}.json"
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
            content = raw_file.read_text(encoding="utf-8", errors="replace").strip()
            # masscan JSON has a trailing comma issue sometimes
            content = content.rstrip(",").strip()
            if not content.startswith("["):
                content = f"[{content}]"
            data = json.loads(content)
            return [RawParsedItem(tool="masscan", raw_data=entry, source_file=raw_file) for entry in data if entry]
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Masscan parse error: {e}")
            return []

    def normalize_findings(self, items: list[RawParsedItem], target: str, scan_id: UUID) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            d = item.raw_data
            ip = d.get("ip", target)
            for port_info in d.get("ports", []):
                port = port_info.get("port", 0)
                proto = port_info.get("proto", "tcp")
                status = port_info.get("status", "open")
                if status != "open":
                    continue
                findings.append(Finding(
                    target=target, source_tool="masscan", scan_profile="recon",
                    category=FindingCategory.PORT, severity=Severity.INFO, confidence=0.95,
                    title=f"Open Port {port}/{proto}",
                    description=f"Masscan discovered open port {port}/{proto} on {ip}",
                    evidence=f"{ip}:{port}/{proto} -> open",
                    host=ip, port=port, protocol=proto, service="unknown",
                    tags=["masscan", "port", proto],
                ))
        return findings
