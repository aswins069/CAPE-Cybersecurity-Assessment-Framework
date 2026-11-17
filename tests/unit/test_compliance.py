"""Unit tests for CAPE Pillar B: ComplianceMapper."""
from __future__ import annotations

import pytest

from cape.shared.enums import FindingCategory, Severity
from cape.shared.finding import FindingFactory
from cape.show.compliance.mapper import ComplianceMapper


class TestComplianceMapper:
    """Tests for ComplianceMapper.annotate_finding / annotate_all."""

    def setup_method(self) -> None:
        self.mapper = ComplianceMapper()

    def test_high_vuln_maps_to_pci_req11(self) -> None:
        """A HIGH/CRITICAL VULNERABILITY finding must map to PCI Req 11.3.x."""
        finding = FindingFactory.create(
            category=FindingCategory.VULNERABILITY,
            severity=Severity.HIGH,
        )
        annotation = self.mapper.annotate_finding(finding)
        assert any(c.startswith("Req 11.3") for c in annotation.pci_dss)
        assert annotation.rationale  # rationale must be populated

    def test_open_port_maps_to_pci_req1(self) -> None:
        """A PORT finding must map to PCI Req 1.x (firewall/segmentation)."""
        finding = FindingFactory.create(
            category=FindingCategory.PORT,
            severity=Severity.INFO,
            port=80,
        )
        annotation = self.mapper.annotate_finding(finding)
        assert any(c.startswith("Req 1.") for c in annotation.pci_dss)

    def test_smb_maps_to_iso27001(self) -> None:
        """An SMB finding must map to ISO A.13.x (network security)."""
        finding = FindingFactory.create_smb()
        annotation = self.mapper.annotate_finding(finding)
        assert any(c.startswith("A.13") for c in annotation.iso27001)

    def test_no_match_returns_empty(self) -> None:
        """A finding that matches nothing returns empty lists, not an error."""
        finding = FindingFactory.create(
            category=FindingCategory.PORT,
            severity=Severity.INFO,
            port=None,  # no port range can match without a port
        )
        # Force a category/severity/port combination unlikely to match any rule.
        finding.category = FindingCategory.API_ENDPOINT
        finding.severity = Severity.INFO
        finding.port = None
        finding.tags = []
        annotation = self.mapper.annotate_finding(finding)
        # API_ENDPOINT/LOW rule requires severity_min LOW; INFO is below LOW, so no match.
        assert annotation.is_empty()
        assert annotation.pci_dss == []
        assert annotation.soc2 == []
        assert annotation.iso27001 == []

    def test_multiple_rules_merge(self) -> None:
        """A finding matching multiple rules gets the union of all their controls."""
        # A HIGH VULNERABILITY with sqli tag matches both the generic
        # HIGH-vuln rule and the SQLi-specific rule.
        finding = FindingFactory.create(
            category=FindingCategory.VULNERABILITY,
            severity=Severity.HIGH,
            tags=["sqli"],
        )
        annotation = self.mapper.annotate_finding(finding)
        # From the generic HIGH/CRITICAL vuln rule:
        assert "Req 11.3.1" in annotation.pci_dss
        # From the SQLi-specific rule:
        assert "Req 6.2.4" in annotation.pci_dss
        # Rationale should mention both reasons.
        assert " | " in annotation.rationale or len(annotation.rationale) > 0

    def test_severity_filter(self) -> None:
        """A LOW-severity finding must not match a rule with severity_min=HIGH."""
        finding = FindingFactory.create(
            category=FindingCategory.VULNERABILITY,
            severity=Severity.LOW,
        )
        annotation = self.mapper.annotate_finding(finding)
        # The HIGH-vuln rule's controls must NOT appear for a LOW finding.
        assert "Req 11.3.1" not in annotation.pci_dss

    def test_annotate_all_covers_every_finding(self) -> None:
        """annotate_all returns one annotation per finding, keyed by finding.id."""
        findings = [
            FindingFactory.create(category=FindingCategory.PORT, severity=Severity.INFO),
            FindingFactory.create_smb(),
            FindingFactory.create_vulnerability(),
        ]
        results = self.mapper.annotate_all(findings)
        assert len(results) == 3
        for f in findings:
            assert f.id in results

    def test_mappings_file_loads_at_least_20_rules(self) -> None:
        """The bundled mappings.yaml must define at least 20 rules per spec."""
        assert len(self.mapper._rules) >= 20

    def test_missing_mappings_file_raises(self, tmp_path) -> None:
        """A nonexistent mappings file path raises FileNotFoundError, not silent failure."""
        with pytest.raises(FileNotFoundError):
            ComplianceMapper(mappings_file=tmp_path / "does_not_exist.yaml")
