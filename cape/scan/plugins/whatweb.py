"""WhatWeb web technology fingerprinting plugin."""
from __future__ import annotations

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


class WhatWebPlugin(BasePlugin):
    """WhatWeb web technology fingerprinting plugin."""

    name = "whatweb"
    version = "1.0.0"
    required_tool = "whatweb"
    required_permissions = [PermissionType.NETWORK]
    supported_profiles = ["quick", "recon", "web", "cms", "full"]

    def check_dependency(self) -> DependencyResult:
        path = resolve_tool_path("whatweb")
        if not path:
            return DependencyResult(installed=False, missing="whatweb not found in PATH")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        return PermissionResult(sufficient=True, message="No special permissions required")

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        output_file = options.custom.get("output_file", "/tmp/whatweb_output.json")
        cmd = [
            "whatweb",
            "--log-json", output_file,
            "--aggression", "1",
            "--no-errors",
            target,
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
        raw_file = workspace.raw / f"whatweb_{timestamp}.json"

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
            content = raw_file.read_text(encoding="utf-8", errors="replace").strip()
            # WhatWeb outputs one JSON object per line
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, list):
                        for entry in data:
                            items.append(RawParsedItem(tool="whatweb", raw_data=entry, source_file=raw_file))
                    elif isinstance(data, dict):
                        items.append(RawParsedItem(tool="whatweb", raw_data=data, source_file=raw_file))
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"WhatWeb parse error: {e}")

        return items

    def normalize_findings(
        self,
        items: list[RawParsedItem],
        target: str,
        scan_id: UUID,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for item in items:
            d = item.raw_data
            target_url = d.get("target", target)
            plugins = d.get("plugins", {})

            for plugin_name, plugin_data in plugins.items():
                if not isinstance(plugin_data, dict):
                    continue

                versions = plugin_data.get("version", [])
                strings = plugin_data.get("string", [])

                version_str = ", ".join(versions) if versions else ""
                detail = f"{plugin_name}"
                if version_str:
                    detail += f" {version_str}"

                category = FindingCategory.SERVICE
                severity = Severity.INFO

                if plugin_name.lower() in ("wordpress", "drupal", "joomla", "magento"):
                    category = FindingCategory.CMS
                    severity = Severity.LOW
                elif plugin_name.lower() in ("apache", "nginx", "iis", "lighttpd"):
                    category = FindingCategory.SERVICE
                elif plugin_name.lower() == "php":
                    category = FindingCategory.SERVICE
                    if version_str:
                        severity = Severity.LOW

                evidence = f"{plugin_name}: {strings[0] if strings else version_str or 'detected'}"

                findings.append(
                    Finding(
                        target=target,
                        source_tool="whatweb",
                        scan_profile="recon",
                        category=category,
                        severity=severity,
                        confidence=0.85,
                        title=f"Technology Detected: {detail}",
                        description=f"WhatWeb identified {detail} on {target_url}",
                        evidence=evidence,
                        host=target,
                        port=443 if "https" in target_url else 80,
                        protocol="tcp",
                        service="http",
                        tags=["whatweb", "fingerprint", plugin_name.lower()],
                        extra={"plugin": plugin_name, "versions": versions, "strings": strings},
                    )
                )

        return findings
