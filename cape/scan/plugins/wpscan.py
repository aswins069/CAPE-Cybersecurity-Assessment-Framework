"""WPScan WordPress vulnerability scanner plugin."""
from __future__ import annotations

import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from uuid import UUID

from cape.core.tool_resolver import resolve_tool_path
from cape.scan.plugins.base import BasePlugin, DependencyResult, ExecutionResult, PermissionResult, PluginOptions
from cape.shared.enums import FindingCategory, PermissionType, Severity
from cape.shared.finding import Finding, RawParsedItem


class WpscanPlugin(BasePlugin):
    """WPScan WordPress vulnerability scanner."""

    name = "wpscan"
    version = "1.0.0"
    required_tool = "wpscan"
    required_permissions = [PermissionType.NETWORK]
    supported_profiles = ["cms", "full"]

    def check_dependency(self) -> DependencyResult:
        path = resolve_tool_path("wpscan")
        if not path:
            return DependencyResult(installed=False, missing="wpscan not found")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        return PermissionResult(sufficient=True, message="No special permissions required")

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        output_file = options.custom.get("output_file", "/tmp/wpscan_output.json")
        return ["wpscan", "--url", target, "--output", output_file, "--format", "json",
                "--no-banner", "--enumerate", "p,t,u,tt,cb,dbe"] + options.extra_args

    def execute(self, target: str, workspace: any, options: PluginOptions, timeout: int) -> ExecutionResult:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_file = workspace.raw / f"wpscan_{timestamp}.json"
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
            return [RawParsedItem(tool="wpscan", raw_data=data, source_file=raw_file)]
        except Exception:
            return []

    def normalize_findings(self, items: list[RawParsedItem], target: str, scan_id: UUID) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            d = item.raw_data
            version_data = d.get("version", {})
            if version_data:
                ver = version_data.get("number", "unknown")
                findings.append(Finding(
                    target=target, source_tool="wpscan", scan_profile="cms",
                    category=FindingCategory.CMS, severity=Severity.LOW, confidence=0.95,
                    title=f"WordPress Version {ver} Detected",
                    description=f"WordPress version {ver} detected on {target}",
                    evidence=f"WordPress {ver}",
                    host=target, port=80, protocol="tcp", service="http",
                    tags=["wpscan", "wordpress", "cms"],
                    extra={"wordpress_version": ver},
                ))
                for vuln in version_data.get("vulnerabilities", []):
                    cves = [ref.get("url", "").split("/")[-1] for ref in vuln.get("references", {}).get("cve", [])]
                    findings.append(Finding(
                        target=target, source_tool="wpscan", scan_profile="cms",
                        category=FindingCategory.VULNERABILITY, severity=Severity.HIGH, confidence=0.85,
                        title=f"WordPress Vulnerability: {vuln.get('title', 'Unknown')}",
                        description=vuln.get("title", ""), evidence=str(vuln.get("references", {}))[:300],
                        host=target, port=80, protocol="tcp", service="http",
                        cve_ids=[c for c in cves if c], tags=["wpscan", "wordpress", "vulnerability"],
                    ))
            for plugin_slug, plugin_data in d.get("plugins", {}).items():
                findings.append(Finding(
                    target=target, source_tool="wpscan", scan_profile="cms",
                    category=FindingCategory.CMS, severity=Severity.INFO, confidence=0.9,
                    title=f"WordPress Plugin: {plugin_slug}",
                    description=f"Plugin {plugin_slug} detected",
                    evidence=f"Plugin: {plugin_slug} v{plugin_data.get('version', {}).get('number', 'unknown')}",
                    host=target, port=80, protocol="tcp", service="http",
                    tags=["wpscan", "wordpress", "plugin"],
                ))
        return findings


class Enum4linuxPlugin(BasePlugin):
    """Enum4linux SMB enumeration plugin."""

    name = "enum4linux"
    version = "1.0.0"
    required_tool = "enum4linux"
    required_permissions = [PermissionType.NETWORK]
    supported_profiles = ["smb", "recon", "full"]

    def check_dependency(self) -> DependencyResult:
        path = resolve_tool_path("enum4linux")
        if not path:
            return DependencyResult(installed=False, missing="enum4linux not found")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        return PermissionResult(sufficient=True)

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        return ["enum4linux", "-a", target] + options.extra_args

    def execute(self, target: str, workspace: any, options: PluginOptions, timeout: int) -> ExecutionResult:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_file = workspace.raw / f"enum4linux_{timestamp}.txt"
        argv = self.build_command(target, options)
        result = self._run_subprocess(argv, workspace.raw, timeout)
        if result.stdout:
            raw_file.write_text(result.stdout, encoding="utf-8")
        result.raw_file_path = raw_file if raw_file.exists() else None
        return result

    def parse_output(self, raw_file: Path) -> list[RawParsedItem]:
        if not raw_file.exists():
            return []
        content = raw_file.read_text(encoding="utf-8", errors="replace")
        sections: dict[str, list[str]] = {}
        current = "general"
        for line in content.splitlines():
            if line.startswith(" ==="):
                current = line.strip(" =").strip()
                sections[current] = []
            elif current in sections:
                sections[current].append(line)
        return [RawParsedItem(tool="enum4linux", raw_data={"sections": sections, "raw": content}, source_file=raw_file)]

    def normalize_findings(self, items: list[RawParsedItem], target: str, scan_id: UUID) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            raw = item.raw_data.get("raw", "")
            if "Signing is NOT required" in raw or "message_signing: disabled" in raw.lower():
                findings.append(Finding(
                    target=target, source_tool="enum4linux", scan_profile="smb",
                    category=FindingCategory.SMB, severity=Severity.HIGH, confidence=0.9,
                    title="SMB Signing Disabled",
                    description="SMB message signing is not required, enabling relay attacks.",
                    evidence="Signing is NOT required",
                    host=target, port=445, protocol="tcp", service="smb",
                    tags=["smb", "signing", "relay"],
                ))
            shares_section = item.raw_data.get("sections", {})
            for section_name, lines in shares_section.items():
                if "share" in section_name.lower():
                    for line in lines:
                        share_match = re.search(r"\s(\w+)\s+Disk\s+(.*)", line)
                        if share_match:
                            findings.append(Finding(
                                target=target, source_tool="enum4linux", scan_profile="smb",
                                category=FindingCategory.SMB, severity=Severity.MEDIUM, confidence=0.85,
                                title=f"SMB Share: {share_match.group(1)}",
                                description=f"SMB share '{share_match.group(1)}' found: {share_match.group(2)}",
                                evidence=line.strip(),
                                host=target, port=445, protocol="tcp", service="smb",
                                tags=["smb", "share"],
                            ))
        return findings


class DirbPlugin(BasePlugin):
    """Dirb web content scanner plugin."""

    name = "dirb"
    version = "1.0.0"
    required_tool = "dirb"
    required_permissions = [PermissionType.NETWORK]
    supported_profiles = ["web", "full"]

    def check_dependency(self) -> DependencyResult:
        path = resolve_tool_path("dirb")
        if not path:
            return DependencyResult(installed=False, missing="dirb not found")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        return PermissionResult(sufficient=True)

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        output_file = options.custom.get("output_file", "/tmp/dirb_output.txt")
        wordlist = options.wordlist or "/usr/share/dirb/wordlists/common.txt"
        return ["dirb", target, wordlist, "-o", output_file, "-S", "-r"] + options.extra_args

    def execute(self, target: str, workspace: any, options: PluginOptions, timeout: int) -> ExecutionResult:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_file = workspace.raw / f"dirb_{timestamp}.txt"
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
        url_pattern = re.compile(r"\+ (https?://\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)")
        for line in raw_file.read_text(encoding="utf-8", errors="replace").splitlines():
            match = url_pattern.match(line.strip())
            if match:
                items.append(RawParsedItem(
                    tool="dirb",
                    raw_data={"url": match.group(1), "status": int(match.group(2)), "size": int(match.group(3))},
                    source_file=raw_file,
                ))
        return items

    def normalize_findings(self, items: list[RawParsedItem], target: str, scan_id: UUID) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            d = item.raw_data
            url = d.get("url", "")
            status = d.get("status", 200)
            findings.append(Finding(
                target=target, source_tool="dirb", scan_profile="web",
                category=FindingCategory.DIRECTORY, severity=Severity.LOW, confidence=0.85,
                title=f"Directory Found: {url} [{status}]",
                description=f"dirb found {url} returning HTTP {status}",
                evidence=f"+ {url} (CODE:{status})",
                host=target, port=80, protocol="tcp", service="http",
                tags=["dirb", "directory"],
                extra={"url": url, "status": status},
            ))
        return findings


class SnmpCheckPlugin(BasePlugin):
    """snmp-check SNMP enumeration plugin."""

    name = "snmp-check"
    version = "1.0.0"
    required_tool = "snmp-check"
    required_permissions = [PermissionType.NETWORK]
    supported_profiles = ["network", "full"]

    def check_dependency(self) -> DependencyResult:
        path = resolve_tool_path("snmp-check")
        if not path:
            return DependencyResult(installed=False, missing="snmp-check not found")
        return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        return PermissionResult(sufficient=True)

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        return ["snmp-check", target, "-c", "public", "-v", "2c"] + options.extra_args

    def execute(self, target: str, workspace: any, options: PluginOptions, timeout: int) -> ExecutionResult:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_file = workspace.raw / f"snmp_check_{timestamp}.txt"
        argv = self.build_command(target, options)
        result = self._run_subprocess(argv, workspace.raw, timeout)
        if result.stdout:
            raw_file.write_text(result.stdout, encoding="utf-8")
        result.raw_file_path = raw_file if raw_file.exists() else None
        return result

    def parse_output(self, raw_file: Path) -> list[RawParsedItem]:
        if not raw_file.exists():
            return []
        content = raw_file.read_text(encoding="utf-8", errors="replace")
        return [RawParsedItem(tool="snmp-check", raw_data={"raw": content}, source_file=raw_file)]

    def normalize_findings(self, items: list[RawParsedItem], target: str, scan_id: UUID) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            raw = item.raw_data.get("raw", "")
            if "public" in raw.lower() and ("snmp" in raw.lower() or "system" in raw.lower()):
                findings.append(Finding(
                    target=target, source_tool="snmp-check", scan_profile="network",
                    category=FindingCategory.VULNERABILITY, severity=Severity.HIGH, confidence=0.9,
                    title="SNMP Default Community String 'public' Accessible",
                    description="SNMP is accessible using the default community string 'public', exposing system information.",
                    evidence=raw[:500],
                    host=target, port=161, protocol="udp", service="snmp",
                    tags=["snmp", "default-credentials", "community-string"],
                    remediation="Change SNMP community string and restrict access by IP.",
                ))
            if raw and "snmp" in raw.lower():
                findings.append(Finding(
                    target=target, source_tool="snmp-check", scan_profile="network",
                    category=FindingCategory.SERVICE, severity=Severity.MEDIUM, confidence=0.85,
                    title="SNMP Service Detected",
                    description="SNMP service is running on UDP port 161.",
                    evidence=raw[:300],
                    host=target, port=161, protocol="udp", service="snmp",
                    tags=["snmp"],
                ))
        return findings
