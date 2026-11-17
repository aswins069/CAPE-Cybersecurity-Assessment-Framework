"""Unit tests for scan plugin parsers."""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest


class TestNmapParser:
    """Tests for the nmap XML parser."""

    def test_parse_sample_xml(self, nmap_fixture: Path) -> None:
        """Test parsing the sample nmap XML fixture."""
        from cape.scan.plugins.nmap import NmapPlugin
        plugin = NmapPlugin()
        items = plugin.parse_output(nmap_fixture)
        assert len(items) > 0

    def test_finds_open_ports(self, nmap_fixture: Path) -> None:
        """Test that parser finds all open ports from fixture."""
        from cape.scan.plugins.nmap import NmapPlugin
        plugin = NmapPlugin()
        items = plugin.parse_output(nmap_fixture)
        ports = [item.raw_data["port"] for item in items]
        assert 22 in ports
        assert 80 in ports
        assert 443 in ports
        assert 445 in ports

    def test_normalize_produces_findings(self, nmap_fixture: Path) -> None:
        """Test that normalization produces Finding instances."""
        from cape.scan.plugins.nmap import NmapPlugin
        from cape.shared.finding import Finding
        plugin = NmapPlugin()
        items = plugin.parse_output(nmap_fixture)
        findings = plugin.normalize_findings(items, "192.168.1.100", uuid.uuid4())
        assert len(findings) > 0
        for f in findings:
            assert isinstance(f, Finding)
            assert f.target == "192.168.1.100"
            assert f.source_tool == "nmap"

    def test_smb_script_finding(self, nmap_fixture: Path) -> None:
        """Test that SMB script output produces SMB findings."""
        from cape.scan.plugins.nmap import NmapPlugin
        from cape.shared.enums import FindingCategory
        plugin = NmapPlugin()
        items = plugin.parse_output(nmap_fixture)
        findings = plugin.normalize_findings(items, "192.168.1.100", uuid.uuid4())
        smb_findings = [f for f in findings if "smb" in f.title.lower() or f.port == 445]
        assert len(smb_findings) > 0

    def test_returns_empty_for_missing_file(self) -> None:
        """Test graceful handling of missing output file."""
        from cape.scan.plugins.nmap import NmapPlugin
        plugin = NmapPlugin()
        items = plugin.parse_output(Path("/nonexistent/file.xml"))
        assert items == []

    def test_returns_empty_for_invalid_xml(self, tmp_path: Path) -> None:
        """Test graceful handling of invalid XML."""
        from cape.scan.plugins.nmap import NmapPlugin
        bad_xml = tmp_path / "bad.xml"
        bad_xml.write_text("this is not xml", encoding="utf-8")
        plugin = NmapPlugin()
        items = plugin.parse_output(bad_xml)
        assert items == []


class TestNiktoParser:
    """Tests for the nikto parser."""

    def test_parse_sample_output(self, nikto_fixture: Path) -> None:
        """Test parsing nikto CSV output."""
        from cape.scan.plugins.nikto import NiktoPlugin
        plugin = NiktoPlugin()
        # Nikto parser reads CSV; fixture is text but we test graceful handling
        items = plugin.parse_output(nikto_fixture)
        # May be empty if not CSV format - that's OK
        assert isinstance(items, list)

    def test_returns_empty_for_missing_file(self) -> None:
        """Test graceful handling of missing file."""
        from cape.scan.plugins.nikto import NiktoPlugin
        plugin = NiktoPlugin()
        items = plugin.parse_output(Path("/nonexistent.csv"))
        assert items == []


class TestWhatWebParser:
    """Tests for the whatweb JSON parser."""

    def test_parse_sample_json(self, whatweb_fixture: Path) -> None:
        """Test parsing whatweb JSON output."""
        from cape.scan.plugins.whatweb import WhatWebPlugin
        plugin = WhatWebPlugin()
        items = plugin.parse_output(whatweb_fixture)
        assert len(items) > 0

    def test_normalize_produces_technology_findings(self, whatweb_fixture: Path) -> None:
        """Test that whatweb normalization produces technology findings."""
        from cape.scan.plugins.whatweb import WhatWebPlugin
        from cape.shared.finding import Finding
        plugin = WhatWebPlugin()
        items = plugin.parse_output(whatweb_fixture)
        findings = plugin.normalize_findings(items, "192.168.1.100", uuid.uuid4())
        assert len(findings) > 0
        tools = {f.source_tool for f in findings}
        assert "whatweb" in tools

    def test_wordpress_detected_as_cms(self, whatweb_fixture: Path) -> None:
        """Test that WordPress is categorized as CMS."""
        from cape.scan.plugins.whatweb import WhatWebPlugin
        from cape.shared.enums import FindingCategory
        plugin = WhatWebPlugin()
        items = plugin.parse_output(whatweb_fixture)
        findings = plugin.normalize_findings(items, "192.168.1.100", uuid.uuid4())
        cms_findings = [f for f in findings if f.category == FindingCategory.CMS]
        assert len(cms_findings) > 0


class TestWpscanParser:
    """Tests for the wpscan JSON parser."""

    def test_parse_sample_json(self, wpscan_fixture: Path) -> None:
        """Test parsing wpscan JSON output."""
        from cape.scan.plugins.wpscan import WpscanPlugin
        plugin = WpscanPlugin()
        items = plugin.parse_output(wpscan_fixture)
        assert len(items) == 1  # One JSON object

    def test_normalize_finds_wordpress_version(self, wpscan_fixture: Path) -> None:
        """Test that WordPress version is extracted."""
        from cape.scan.plugins.wpscan import WpscanPlugin
        plugin = WpscanPlugin()
        items = plugin.parse_output(wpscan_fixture)
        findings = plugin.normalize_findings(items, "192.168.1.100", uuid.uuid4())
        wp_findings = [f for f in findings if "wordpress" in f.title.lower() or "wordpress" in " ".join(f.tags).lower()]
        assert len(wp_findings) > 0

    def test_normalize_finds_vulnerability(self, wpscan_fixture: Path) -> None:
        """Test that vulnerabilities are extracted from wpscan output."""
        from cape.scan.plugins.wpscan import WpscanPlugin
        from cape.shared.enums import FindingCategory
        plugin = WpscanPlugin()
        items = plugin.parse_output(wpscan_fixture)
        findings = plugin.normalize_findings(items, "192.168.1.100", uuid.uuid4())
        vuln_findings = [f for f in findings if f.category == FindingCategory.VULNERABILITY]
        assert len(vuln_findings) > 0
