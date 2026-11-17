"""Nikto web vulnerability scanner plugin."""
from __future__ import annotations

import csv
import io
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from cape.core.tool_resolver import resolve_tool_path
from cape.scan.plugins.base import (
    BasePlugin,
    DependencyResult,
    ExecutionResult,
    PermissionResult,
    PluginOptions,
)
from cape.shared.enums import FindingCategory, PermissionType, Severity
from cape.shared.finding import Finding, RawParsedItem


class NiktoPlugin(BasePlugin):
    """Nikto web server scanner plugin."""

    name = "nikto"
    version = "1.0.0"
    required_tool = "nikto"
    required_permissions = [PermissionType.NETWORK]
    supported_profiles = ["web", "vuln", "full"]

    def check_dependency(self) -> DependencyResult:
        path = resolve_tool_path("nikto")
        if not path:
            return DependencyResult(installed=False, missing="nikto not found in PATH")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        return PermissionResult(sufficient=True, message="No special permissions required")

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        output_file = options.custom.get("output_file", "/tmp/nikto_output.csv")
        port = options.ports or "80"

        cmd = [
            "nikto",
            "-h", target,
            "-port", str(port),
            "-output", output_file,
            "-Format", "csv",
            "-nointeractive",
        ]
        cmd += options.extra_args
        return cmd

    def execute(
        self,
        target: str,
        workspace: Any,
        options: PluginOptions,
        timeout: int,
    ) -> ExecutionResult:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_file = workspace.raw / f"nikto_{timestamp}.csv"

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

        items: list[RawParsedItem] = []
        try:
            content = raw_file.read_text(encoding="utf-8", errors="replace")
            # Skip comment lines starting with #
            lines = [l for l in content.splitlines() if not l.startswith("#")]
            if not lines:
                return []

            reader = csv.DictReader(io.StringIO("\n".join(lines)))
            for row in reader:
                if row:
                    items.append(
                        RawParsedItem(
                            tool="nikto",
                            raw_data=dict(row),
                            source_file=raw_file,
                        )
                    )
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Nikto parse error: {e}")

        return items

    def normalize_findings(
        self,
        items: list[RawParsedItem],
        target: str,
        scan_id: UUID,
    ) -> list[Finding]:
        findings: list[Finding] = []

        osvdb_to_cve: dict[str, str] = {}  # Could be populated from a mapping file

        for item in items:
            d = item.raw_data
            host = d.get("Host", target)
            osvdb = d.get("OSVDB", "")
            method = d.get("method", "GET")
            url = d.get("URL", "/")
            msg = d.get("msg", d.get("description", ""))

            if not msg:
                continue

            severity = Severity.MEDIUM
            category = FindingCategory.VULNERABILITY

            msg_lower = msg.lower()
            if "sql" in msg_lower or "injection" in msg_lower:
                severity = Severity.HIGH
                category = FindingCategory.VULNERABILITY
            elif "header" in msg_lower or "x-" in msg_lower:
                severity = Severity.LOW
                category = FindingCategory.HEADER
            elif "directory" in msg_lower or "index of" in msg_lower:
                severity = Severity.MEDIUM
                category = FindingCategory.DIRECTORY
            elif "default" in msg_lower and "password" in msg_lower:
                severity = Severity.HIGH
                category = FindingCategory.CREDENTIAL_HINT

            findings.append(
                Finding(
                    target=target,
                    source_tool="nikto",
                    scan_profile="web",
                    category=category,
                    severity=severity,
                    confidence=0.75,
                    title=f"Nikto: {msg[:80]}",
                    description=msg,
                    evidence=f"[{method}] {url}: {msg}",
                    host=host,
                    port=int(d.get("port", 80) or 80),
                    protocol="tcp",
                    service="http",
                    tags=["nikto", "web"],
                    extra={"osvdb": osvdb, "method": method, "url": url},
                )
            )

        return findings
