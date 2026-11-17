"""Pydantic models for the scan engine."""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel

from cape.shared.enums import ScanStatus
from cape.shared.finding import Finding


class ScanResult(BaseModel):
    """Result of a scan run."""

    scan_id: UUID
    target: str
    profile: str
    status: ScanStatus
    findings: list[Finding]
    started_at: datetime
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    dry_run: bool = False

    model_config = {"arbitrary_types_allowed": True}

    @property
    def duration_seconds(self) -> Optional[float]:
        """Duration of scan in seconds."""
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity."""
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            key = f.severity.value
            result.setdefault(key, []).append(f)
        return result
