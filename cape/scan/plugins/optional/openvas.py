"""Optional OpenVAS plugin for CAPE."""
from __future__ import annotations
from pathlib import Path
from uuid import UUID
from cape.scan.plugins.base import BasePlugin, DependencyResult, ExecutionResult, PermissionResult, PluginOptions
from cape.shared.enums import PermissionType
from cape.shared.finding import Finding, RawParsedItem
import shutil


class OpenVASPlugin(BasePlugin):
    """OpenVAS vulnerability scanner (optional plugin)."""

    name = "openvas"
    version = "1.0.0"
    required_tool = "openvas"
    required_permissions = [PermissionType.ROOT]
    supported_profiles = ["vuln", "full"]

    def check_dependency(self) -> DependencyResult:
        path = shutil.which("openvas") or shutil.which("gvm-cli")
        if not path:
            return DependencyResult(installed=False, missing="openvas/gvm-cli not found. Install: sudo apt-get install openvas")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        import os
        if os.geteuid() == 0:
            return PermissionResult(sufficient=True)
        return PermissionResult(sufficient=False, required=[PermissionType.ROOT], message="OpenVAS requires root")

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        return ["gvm-cli", "--gmp-username", "admin", "--gmp-password", "admin",
                "socket", "--xml", f"<create_task><name>CO Scan {target}</name></create_task>"]

    def execute(self, target: str, workspace: any, options: PluginOptions, timeout: int) -> ExecutionResult:
        return ExecutionResult(stdout="", stderr="OpenVAS integration not configured", returncode=1,
                               raw_file_path=None, duration=0.0)

    def parse_output(self, raw_file: Path) -> list[RawParsedItem]:
        return []

    def normalize_findings(self, items: list[RawParsedItem], target: str, scan_id: UUID) -> list[Finding]:
        return []
