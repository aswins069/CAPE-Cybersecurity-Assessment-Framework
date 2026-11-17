"""Dependency checker for CAPE.

Verifies that all required external tools are installed and accessible.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

from cape.core.tool_resolver import resolve_tool_path
from cape.shared.enums import CheckStatus


@dataclass
class CheckResult:
    """Result of a single dependency check."""

    name: str
    status: CheckStatus
    version: Optional[str] = None
    path: Optional[str] = None
    message: str = ""
    remediation: Optional[str] = None


class DependencyChecker:
    """Checks that required tools and dependencies are available."""

    TOOL_CHECKS: dict[str, dict] = {
        "nmap": {
            "version_args": ["--version"],
            "version_grep": r"Nmap version ([\d.]+)",
            "remediation": "sudo apt-get install nmap",
        },
        "masscan": {
            "version_args": ["--version"],
            "version_grep": r"masscan V([\d.]+)",
            "remediation": "sudo apt-get install masscan",
        },
        "nikto": {
            "version_args": ["-Version"],
            "version_grep": r"Nikto v([\d.]+)",
            "remediation": "sudo apt-get install nikto",
        },
        "whatweb": {
            "version_args": ["--version"],
            "version_grep": r"WhatWeb version ([\d.]+)",
            "remediation": "sudo apt-get install whatweb",
        },
        "gobuster": {
            "version_args": ["version"],
            "version_grep": r"gobuster v([\d.]+)",
            "remediation": "sudo apt-get install gobuster",
        },
        "dirb": {
            "version_args": [],
            "version_grep": r"DIRB v([\d.]+)",
            "remediation": "sudo apt-get install dirb",
        },
        "wpscan": {
            "version_args": ["--version"],
            "version_grep": r"WPScan v([\d.]+)",
            "remediation": "sudo apt-get install wpscan",
        },
        "enum4linux": {
            "version_args": [],
            "version_grep": r"",
            "remediation": "sudo apt-get install enum4linux",
        },
        "nbtscan": {
            "version_args": [],
            "version_grep": r"NBTscan ([\d.]+)",
            "remediation": "sudo apt-get install nbtscan",
        },
        "snmp-check": {
            "version_args": ["--version"],
            "version_grep": r"snmp-check v([\d.]+)",
            "remediation": "sudo apt-get install snmp",
        },
        "zaproxy": {
            "version_args": ["-version"],
            "version_grep": r"[\d.]+",
            "remediation": "sudo apt-get install zaproxy",
        },
        "aircrack-ng": {
            "version_args": ["--version"],
            "version_grep": r"Aircrack-ng ([\d.]+)",
            "remediation": "sudo apt-get install aircrack-ng",
        },
        "kismet": {
            "version_args": ["--version"],
            "version_grep": r"[\d-]+",
            "remediation": "sudo apt-get install kismet",
        },
        "nc": {
            "version_args": ["-h"],
            "version_grep": r"",
            "remediation": "sudo apt-get install netcat",
        },
        "droopescan": {
            "version_args": ["--version"],
            "version_grep": r"droopescan ([\d.]+)",
            "remediation": "pip install droopescan",
        },
    }

    def check_tool(self, tool: str) -> CheckResult:
        """Check if a specific tool is installed and get its version.

        Args:
            tool: Tool name to check.

        Returns:
            CheckResult with status, version, and path.
        """
        import re

        tool_config = self.TOOL_CHECKS.get(tool, {})
        tool_path = resolve_tool_path(tool)

        if not tool_path:
            return CheckResult(
                name=tool,
                status=CheckStatus.FAIL,
                message=f"{tool} not found in PATH",
                remediation=tool_config.get("remediation", f"Install {tool}"),
            )

        version: Optional[str] = None
        version_args = tool_config.get("version_args", ["--version"])
        version_pattern = tool_config.get("version_grep", r"")

        if version_args is not None:
            try:
                result = subprocess.run(
                    [tool] + version_args,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                output = result.stdout + result.stderr
                if version_pattern:
                    match = re.search(version_pattern, output)
                    if match:
                        version = match.group(1) if match.lastindex else match.group(0)
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                pass

        return CheckResult(
            name=tool,
            status=CheckStatus.OK,
            version=version,
            path=tool_path,
            message=f"{tool} is available",
        )

    def check_python_version(self) -> CheckResult:
        """Check Python version is 3.11+."""
        version = sys.version_info
        version_str = f"{version.major}.{version.minor}.{version.micro}"

        if version >= (3, 11):
            return CheckResult(
                name="python",
                status=CheckStatus.OK,
                version=version_str,
                path=sys.executable,
                message="Python 3.11+ detected",
            )
        return CheckResult(
            name="python",
            status=CheckStatus.FAIL,
            version=version_str,
            path=sys.executable,
            message=f"Python {version_str} is too old",
            remediation="Install Python 3.11 or newer",
        )

    def check_nmap_permissions(self) -> CheckResult:
        """Check if nmap can run privileged scans."""
        if os.geteuid() == 0:
            return CheckResult(
                name="nmap-root",
                status=CheckStatus.OK,
                message="Running as root, full nmap capability available",
            )

        # Check for cap_net_raw capability
        try:
            result = subprocess.run(
                ["getcap", shutil.which("nmap") or "nmap"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "cap_net_raw" in result.stdout:
                return CheckResult(
                    name="nmap-root",
                    status=CheckStatus.OK,
                    message="nmap has cap_net_raw capability",
                )
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        return CheckResult(
            name="nmap-root",
            status=CheckStatus.WARN,
            message="Not running as root, SYN scans (-sS) unavailable",
            remediation="Run with sudo, or: sudo setcap cap_net_raw+eip $(which nmap)",
        )

    def check_db_connectivity(self) -> CheckResult:
        """Check database connectivity."""
        try:
            from cape.core.config import get_config
            cfg = get_config()
            db_path = Path(cfg.db_url.replace("sqlite:///", ""))
            db_path.parent.mkdir(parents=True, exist_ok=True)
            # Try creating/opening the DB
            import sqlite3
            conn = sqlite3.connect(str(db_path))
            conn.close()
            return CheckResult(
                name="database",
                status=CheckStatus.OK,
                path=str(db_path),
                message="SQLite database accessible",
            )
        except Exception as e:
            return CheckResult(
                name="database",
                status=CheckStatus.FAIL,
                message=f"Database error: {e}",
                remediation="Check permissions on ~/.cape/db/",
            )

    def check_workspace_writable(self) -> CheckResult:
        """Check that workspace directory is writable."""
        try:
            from cape.core.config import get_config
            cfg = get_config()
            cfg.workspace_root.mkdir(parents=True, exist_ok=True)
            test_file = cfg.workspace_root / ".write_test"
            test_file.write_text("test")
            test_file.unlink()
            return CheckResult(
                name="workspace",
                status=CheckStatus.OK,
                path=str(cfg.workspace_root),
                message="Workspace directory is writable",
            )
        except OSError as e:
            return CheckResult(
                name="workspace",
                status=CheckStatus.FAIL,
                message=f"Workspace not writable: {e}",
                remediation="Check directory permissions",
            )

    def check_kb_files(self) -> CheckResult:
        """Check that knowledge base files are present and valid."""
        from cape.core.config import get_config
        cfg = get_config()
        required_files = [
            "attack_patterns.json",
            "service_rules.yaml",
            "opportunity_rules.yaml",
        ]
        missing = []
        for fname in required_files:
            if not (cfg.kb_dir / fname).exists():
                missing.append(fname)

        if missing:
            return CheckResult(
                name="knowledge-base",
                status=CheckStatus.FAIL,
                message=f"Missing KB files: {', '.join(missing)}",
                remediation="Reinstall or check show/knowledge/ directory",
            )
        return CheckResult(
            name="knowledge-base",
            status=CheckStatus.OK,
            path=str(cfg.kb_dir),
            message="Knowledge base files present",
        )

    def check_audit_chain_valid(self) -> CheckResult:
        """CAPE Pillar D: verify the tamper-evident audit chain is intact."""
        try:
            from cape.core.audit_chain import get_audit_logger
            result = get_audit_logger().verify_chain()
            if result.valid:
                return CheckResult(
                    name="audit-chain",
                    status=CheckStatus.OK,
                    message=result.message,
                )
            return CheckResult(
                name="audit-chain",
                status=CheckStatus.FAIL,
                message=result.message,
                remediation=(
                    "The audit log has been tampered with or entries were deleted. "
                    "Investigate immediately; do not trust entries after the reported sequence."
                ),
            )
        except Exception as e:
            return CheckResult(
                name="audit-chain",
                status=CheckStatus.FAIL,
                message=f"Could not verify audit chain: {e}",
                remediation="Check that the audit log file is readable.",
            )

    def check_compliance_kb(self) -> CheckResult:
        """CAPE Pillar B: verify the compliance mappings knowledge base loads cleanly."""
        try:
            from cape.show.compliance.mapper import ComplianceMapper
            mapper = ComplianceMapper()
            rule_count = len(mapper._rules)
            if rule_count < 20:
                return CheckResult(
                    name="compliance-kb",
                    status=CheckStatus.WARN,
                    message=f"Compliance KB loaded but only has {rule_count} rules (expected 20+)",
                    path=str(mapper.mappings_file),
                )
            return CheckResult(
                name="compliance-kb",
                status=CheckStatus.OK,
                path=str(mapper.mappings_file),
                message=f"Compliance mappings loaded cleanly ({rule_count} rules)",
            )
        except Exception as e:
            return CheckResult(
                name="compliance-kb",
                status=CheckStatus.FAIL,
                message=f"Compliance mappings failed to load: {e}",
                remediation="Check show/compliance/mappings.yaml for syntax errors.",
            )

    def check_client_isolation(self) -> CheckResult:
        """CAPE multi-tenant isolation: if CAPE_CLIENT_ID is set, verify that client exists."""
        from cape.core.config import get_config
        cfg = get_config()

        if not cfg.current_client:
            return CheckResult(
                name="client-isolation",
                status=CheckStatus.OK,
                message="No CAPE_CLIENT_ID set; operating in default (non-multi-tenant) mode",
            )

        try:
            from cape.core.workspace import validate_client_id
            validate_client_id(cfg.current_client)
        except ValueError as e:
            return CheckResult(
                name="client-isolation",
                status=CheckStatus.FAIL,
                message=f"CAPE_CLIENT_ID is invalid: {e}",
                remediation="Set CAPE_CLIENT_ID to an alphanumeric+hyphen value, or unset it.",
            )

        try:
            from cape.db.session import db_session
            from cape.db.models import Client

            with db_session() as session:
                client = session.get(Client, cfg.current_client)
                if client is None:
                    return CheckResult(
                        name="client-isolation",
                        status=CheckStatus.FAIL,
                        message=f"CAPE_CLIENT_ID='{cfg.current_client}' does not match any registered client",
                        remediation=f"Run: cape clients create {cfg.current_client}",
                    )
                return CheckResult(
                    name="client-isolation",
                    status=CheckStatus.OK,
                    message=f"Operating as client '{cfg.current_client}' ({client.name or 'no name set'})",
                )
        except Exception as e:
            return CheckResult(
                name="client-isolation",
                status=CheckStatus.FAIL,
                message=f"Could not verify client: {e}",
            )

    def run_all_checks(self) -> list[CheckResult]:
        """Run all dependency checks and return results."""
        results: list[CheckResult] = []

        results.append(self.check_python_version())
        results.append(self.check_db_connectivity())
        results.append(self.check_workspace_writable())
        results.append(self.check_kb_files())
        results.append(self.check_nmap_permissions())
        # CAPE additions
        results.append(self.check_audit_chain_valid())
        results.append(self.check_compliance_kb())
        results.append(self.check_client_isolation())

        for tool in self.TOOL_CHECKS:
            results.append(self.check_tool(tool))

        return results


# Import at bottom to avoid circular
from pathlib import Path
