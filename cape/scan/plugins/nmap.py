"""Nmap scan plugin for CAPE."""
from __future__ import annotations

import shutil
import xml.etree.ElementTree as ET
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


class NmapPlugin(BasePlugin):
    """Nmap network scanner plugin.

    Runs nmap and parses XML output into normalized findings.
    """

    name = "nmap"
    version = "1.0.0"
    required_tool = "nmap"
    required_permissions = [PermissionType.NETWORK]
    supported_profiles = ["quick", "recon", "network", "smb", "vuln", "full"]

    def check_dependency(self) -> DependencyResult:
        """Check if nmap is installed."""
        import subprocess
        path = resolve_tool_path("nmap")
        if not path:
            return DependencyResult(installed=False, missing="nmap not found in PATH")
        try:
            result = subprocess.run(
                ["nmap", "--version"], capture_output=True, text=True, timeout=5
            )
            import re
            match = re.search(r"Nmap version ([\d.]+)", result.stdout)
            version = match.group(1) if match else "unknown"
            return DependencyResult(installed=True, version=version, path=path)
        except Exception:
            return DependencyResult(installed=True, path=path)

    def check_permissions(self) -> PermissionResult:
        """Check if we have sufficient permissions."""
        import os
        if os.geteuid() == 0:
            return PermissionResult(sufficient=True, message="Running as root")
        return PermissionResult(
            sufficient=True,
            required=[PermissionType.NETWORK],
            message="Running as non-root, SYN scans unavailable (use -T4 -sV instead)",
        )

    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        """Build nmap command argv list.

        The -T timing template is driven by the Configuration Manager's
        scan degree/intensity setting (light/normal/aggressive) rather
        than being hardcoded, so the same profile can be run quieter or
        more thoroughly without editing the profile YAML.
        """
        output_file = options.custom.get("output_file", "/tmp/nmap_output")
        profile = options.custom.get("profile", "quick")
        intensity = options.custom.get("scan_intensity", "normal")
        timing = {"light": "-T2", "normal": "-T4", "aggressive": "-T5"}.get(intensity, "-T4")

        cmd = ["nmap", timing]

        if profile == "quick":
            cmd += ["-F", "--top-ports", "1000", "-sV"]
            if intensity != "light":
                cmd += ["-sC"]
        elif profile == "recon":
            cmd += ["-p-", "-sV", "--open"]
            if intensity != "light":
                cmd += ["-sC"]
        elif profile == "network":
            cmd += ["-p-", "-sV"]
            cmd += ["-sC", "-A"] if intensity != "light" else ["-sC"]
        elif profile == "smb":
            cmd += [
                "-p", "139,445",
                "--script", "smb-vuln-ms17-010,smb-security-mode,smb2-security-mode,smb-enum-shares",
            ]
        elif profile == "vuln":
            cmd += ["--script", "vuln", "-sV"]
        else:
            cmd += ["-sV", "--open"]

        if intensity == "aggressive" and "-A" not in cmd:
            cmd += ["-A"]

        cmd += ["-oX", output_file, target]
        cmd += options.extra_args

        return cmd

    def execute(
        self,
        target: str,
        workspace: Any,
        options: PluginOptions,
        timeout: int,
    ) -> ExecutionResult:
        """Run nmap and save XML output."""
        from datetime import datetime
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        raw_file = workspace.raw / f"nmap_{timestamp}.xml"

        if options.custom is None:
            options.custom = {}
        options.custom["output_file"] = str(raw_file)

        argv = self.build_command(target, options)
        result = self._run_subprocess(argv, workspace.raw, timeout)
        result.raw_file_path = raw_file if raw_file.exists() else None
        return result

    def parse_output(self, raw_file: Path) -> list[RawParsedItem]:
        """Parse nmap XML output."""
        if not raw_file.exists():
            return []

        items: list[RawParsedItem] = []
        try:
            tree = ET.parse(str(raw_file))
            root = tree.getroot()

            for host in root.findall("host"):
                host_data: dict[str, Any] = {}

                # Get address
                addr_el = host.find("address")
                if addr_el is not None:
                    host_data["ip"] = addr_el.get("addr", "")

                # Get hostname
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hn = hostnames.find("hostname")
                    if hn is not None:
                        host_data["hostname"] = hn.get("name", "")

                # Get status
                status = host.find("status")
                if status is not None:
                    host_data["state"] = status.get("state", "")

                # Get ports
                ports_el = host.find("ports")
                if ports_el is not None:
                    for port_el in ports_el.findall("port"):
                        port_data = dict(host_data)
                        port_data["port"] = int(port_el.get("portid", "0"))
                        port_data["protocol"] = port_el.get("protocol", "tcp")

                        state_el = port_el.find("state")
                        if state_el is not None:
                            port_data["port_state"] = state_el.get("state", "")

                        service_el = port_el.find("service")
                        if service_el is not None:
                            port_data["service"] = service_el.get("name", "")
                            port_data["product"] = service_el.get("product", "")
                            port_data["version"] = service_el.get("version", "")
                            port_data["extrainfo"] = service_el.get("extrainfo", "")
                            port_data["tunnel"] = service_el.get("tunnel", "")
                            cpes = [
                                cpe.text or ""
                                for cpe in service_el.findall("cpe")
                            ]
                            port_data["cpes"] = cpes

                        # Script output
                        scripts = {}
                        for script_el in port_el.findall("script"):
                            scripts[script_el.get("id", "")] = script_el.get("output", "")
                        port_data["scripts"] = scripts

                        if port_data.get("port_state") == "open":
                            items.append(
                                RawParsedItem(
                                    tool="nmap",
                                    raw_data=port_data,
                                    source_file=raw_file,
                                )
                            )

        except ET.ParseError as e:
            import logging
            logging.getLogger(__name__).error(f"Nmap XML parse error: {e}")

        return items

    def normalize_findings(
        self,
        items: list[RawParsedItem],
        target: str,
        scan_id: UUID,
    ) -> list[Finding]:
        """Convert parsed nmap items to Finding instances."""
        findings: list[Finding] = []

        for item in items:
            d = item.raw_data
            host = d.get("ip") or d.get("hostname") or target
            port = d.get("port")
            service = d.get("service", "")
            product = d.get("product", "")
            version = d.get("version", "")
            protocol = d.get("protocol", "tcp")

            service_str = service
            if product:
                service_str += f" ({product}"
                if version:
                    service_str += f" {version}"
                service_str += ")"

            # Base port/service finding
            findings.append(
                Finding(
                    target=target,
                    source_tool="nmap",
                    scan_profile="nmap",
                    category=FindingCategory.PORT,
                    severity=Severity.INFO,
                    confidence=0.99,
                    title=f"Open Port {port}/{protocol}: {service}",
                    description=f"Port {port}/{protocol} is open running {service_str}",
                    evidence=d.get("extrainfo", f"{port}/{protocol} open {service}"),
                    host=host,
                    port=port,
                    protocol=protocol,
                    service=service,
                    tags=["nmap", "port", protocol],
                    extra={
                        "product": product,
                        "version": version,
                        "cpes": d.get("cpes", []),
                    },
                )
            )

            # Script findings for vulnerabilities
            for script_id, script_output in d.get("scripts", {}).items():
                if not script_output:
                    continue

                severity = Severity.INFO
                category = FindingCategory.VULNERABILITY

                if "VULNERABLE" in script_output.upper():
                    severity = Severity.HIGH
                elif "smb-security-mode" in script_id:
                    category = FindingCategory.SMB
                    if "message_signing: disabled" in script_output.lower():
                        severity = Severity.HIGH
                    else:
                        severity = Severity.LOW

                findings.append(
                    Finding(
                        target=target,
                        source_tool="nmap",
                        scan_profile="nmap",
                        category=category,
                        severity=severity,
                        confidence=0.85,
                        title=f"Nmap Script: {script_id}",
                        description=f"Nmap script {script_id} result on {host}:{port}",
                        evidence=script_output[:500],
                        host=host,
                        port=port,
                        protocol=protocol,
                        service=service,
                        tags=["nmap", "script", script_id],
                    )
                )

        return findings
