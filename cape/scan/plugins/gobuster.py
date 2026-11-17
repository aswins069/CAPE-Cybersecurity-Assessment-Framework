"""Gobuster directory/file enumeration plugin."""
from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path
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


class GobusterPlugin(BasePlugin):
    """Gobuster directory/file brute-force scanner."""

    name = "gobuster"
    version = "1.0.0"
    required_tool = "gobuster"
    required_permissions = [PermissionType.NETWORK]
    supported_profiles = ["web", "api", "full"]

    _DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
    _API_WORDLIST = "/usr/share/wordlists/dirb/big.txt"

    def check_dependency(self) -> DependencyResult:
        path = resolve_tool_path("gobuster")
        if not path:
            return DependencyResult(installed=False, missing="gobuster not found in PATH")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        return PermissionResult(sufficient=True, message="No special permissions required")

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        output_file = options.custom.get("output_file", "/tmp/gobuster_output.txt")
        mode = options.custom.get("mode", "dir")
        wordlist = options.wordlist or self._DEFAULT_WORDLIST
        if mode == "api":
            wordlist = options.wordlist or self._API_WORDLIST

        cmd = [
            "gobuster", mode,
            "-u", target,
            "-w", wordlist,
            "-o", output_file,
            "-q",
            "--no-error",
            "-t", "20",
        ]
        cmd += options.extra_args
        return cmd

    def execute(self, target: str, workspace: any, options: PluginOptions, timeout: int) -> ExecutionResult:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_file = workspace.raw / f"gobuster_{timestamp}.txt"
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
        pattern = re.compile(r"^(/.+?)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]")
        for line in raw_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            match = pattern.match(line)
            if match:
                items.append(RawParsedItem(
                    tool="gobuster",
                    raw_data={"path": match.group(1), "status": int(match.group(2)), "size": int(match.group(3))},
                    source_file=raw_file,
                ))
            elif line.startswith("/") or line.startswith("http"):
                items.append(RawParsedItem(tool="gobuster", raw_data={"path": line, "status": 200, "size": 0}, source_file=raw_file))
        return items

    def normalize_findings(self, items: list[RawParsedItem], target: str, scan_id: UUID) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            d = item.raw_data
            path = d.get("path", "/")
            status = d.get("status", 200)
            severity = Severity.LOW
            if status == 200:
                severity = Severity.MEDIUM
            elif status in (301, 302):
                severity = Severity.LOW
            findings.append(Finding(
                target=target, source_tool="gobuster", scan_profile="web",
                category=FindingCategory.DIRECTORY, severity=severity, confidence=0.9,
                title=f"Directory Found: {path} [{status}]",
                description=f"Directory/file {path} returned HTTP {status}",
                evidence=f"GET {target}{path} -> {status}",
                host=target, port=80, protocol="tcp", service="http",
                tags=["gobuster", "directory", f"status_{status}"],
                extra={"path": path, "status": status},
            ))
        return findings
