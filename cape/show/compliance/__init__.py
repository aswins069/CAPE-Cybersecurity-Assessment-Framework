"""CAPE Pillar B — Compliance control mapping.

Maps normalized findings to PCI-DSS, SOC2, and ISO27001 controls using a
declarative YAML knowledge base, so every finding in a report can show
*which* compliance requirement it implicates and *why*.
"""
from cape.show.compliance.mapper import ComplianceControlAnnotation, ComplianceMapper

__all__ = ["ComplianceMapper", "ComplianceControlAnnotation"]
