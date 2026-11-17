"""Universal normalized finding schema for CAPE.

All parsers MUST produce Finding instances. No parser may return arbitrary dicts.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from cape.shared.enums import FindingCategory, Severity


class Finding(BaseModel):
    """Normalized security finding produced by any scan plugin parser.

    This is the universal data contract. Every parser must map its
    tool-specific output to this schema.
    """

    id: UUID = Field(default_factory=uuid.uuid4)
    target: str = Field(..., description="Target hostname/IP/URL")
    source_tool: str = Field(..., description="Tool that produced this finding, e.g. 'nmap'")
    scan_profile: str = Field(..., description="Scan profile name used")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    category: FindingCategory
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    title: str
    description: str
    evidence: str = Field(..., description="Raw snippet from tool output")
    host: str
    port: Optional[int] = None
    protocol: Optional[str] = None  # tcp, udp
    service: Optional[str] = None   # http, smb, ssh...
    cve_ids: list[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    raw_output_file: Optional[Path] = None
    tags: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        """Clamp confidence to valid range."""
        return max(0.0, min(1.0, v))

    @field_validator("cvss_score")
    @classmethod
    def validate_cvss(cls, v: Optional[float]) -> Optional[float]:
        """Clamp CVSS score to 0-10."""
        if v is not None:
            return max(0.0, min(10.0, v))
        return v

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict with string representations."""
        data = self.model_dump()
        data["id"] = str(data["id"])
        data["timestamp"] = data["timestamp"].isoformat()
        data["raw_output_file"] = str(data["raw_output_file"]) if data["raw_output_file"] else None
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Deserialize from dict."""
        return cls(**data)


class RawParsedItem(BaseModel):
    """Intermediate parsed data before normalization to Finding.

    Each plugin's parse_output() returns these, then normalize_findings()
    converts them to Finding instances.
    """

    tool: str
    raw_data: dict[str, Any]
    source_file: Optional[Path] = None

    model_config = {"arbitrary_types_allowed": True}


class FindingFactory:
    """Test utility for generating realistic Finding instances."""

    @staticmethod
    def create(
        target: str = "192.168.1.1",
        source_tool: str = "nmap",
        scan_profile: str = "quick",
        category: FindingCategory = FindingCategory.PORT,
        severity: Severity = Severity.MEDIUM,
        title: str = "Open Port Detected",
        description: str = "An open port was found during scanning.",
        evidence: str = "80/tcp open http",
        host: str = "192.168.1.1",
        port: Optional[int] = 80,
        protocol: str = "tcp",
        service: str = "http",
        confidence: float = 0.95,
        **kwargs: Any,
    ) -> Finding:
        """Create a Finding with sensible defaults for testing."""
        return Finding(
            target=target,
            source_tool=source_tool,
            scan_profile=scan_profile,
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            host=host,
            port=port,
            protocol=protocol,
            service=service,
            confidence=confidence,
            **kwargs,
        )

    @staticmethod
    def create_vulnerability(
        target: str = "192.168.1.1",
        cve_ids: Optional[list[str]] = None,
        cvss_score: float = 7.5,
        **kwargs: Any,
    ) -> Finding:
        """Create a vulnerability Finding."""
        return FindingFactory.create(
            target=target,
            category=FindingCategory.VULNERABILITY,
            severity=Severity.HIGH,
            cve_ids=cve_ids or ["CVE-2021-44228"],
            cvss_score=cvss_score,
            **kwargs,
        )

    @staticmethod
    def create_smb(target: str = "192.168.1.1", **kwargs: Any) -> Finding:
        """Create an SMB-related Finding."""
        return FindingFactory.create(
            target=target,
            category=FindingCategory.SMB,
            severity=Severity.HIGH,
            title="SMB Signing Disabled",
            description="SMB message signing is not enforced, enabling relay attacks.",
            evidence="SMB Signing: disabled",
            port=445,
            protocol="tcp",
            service="smb",
            tags=["smb", "signing", "relay"],
            **kwargs,
        )
