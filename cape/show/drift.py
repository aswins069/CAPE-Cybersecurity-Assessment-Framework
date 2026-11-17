"""CAPE Pillar C — Drift Detection.

Compares findings across two (or more) scans of the same target to
identify what's NEW, FIXED, REGRESSED, IMPROVED, or PERSISTENT. Findings
are matched across scans by a semantic fingerprint (host, port,
protocol, category, normalized title), not by UUID, since every scan
generates fresh UUIDs for what may be the exact same underlying issue.
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Ordinal severity weights for detecting regression/improvement direction.
_SEVERITY_ORDER: dict[str, int] = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}

# Strips things like dates, times, and long hex/numeric IDs out of titles
# so two scans of the same logical issue fingerprint identically even if
# a tool embeds a timestamp or session ID in the finding title.
_NORMALIZE_PATTERNS = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(\.\d+)?z?\b"),  # ISO timestamps
    re.compile(r"\b[0-9a-f]{8,}\b"),  # long hex IDs/hashes
    re.compile(r"\b\d{6,}\b"),  # long numeric IDs
]


class FindingStatus(str, Enum):
    """Lifecycle status of a finding across two scans."""

    NEW = "NEW"               # in later scan, not in earlier
    FIXED = "FIXED"            # in earlier scan, absent in later
    REGRESSED = "REGRESSED"    # present in both, severity increased
    PERSISTENT = "PERSISTENT"  # present in both, unchanged
    IMPROVED = "IMPROVED"      # present in both, severity decreased


class DriftEntry(BaseModel):
    """A single finding's drift status between two scans."""

    finding_title: str
    host: str
    port: Optional[int] = None
    service: Optional[str] = None
    status: FindingStatus
    severity_before: Optional[str] = None  # None for NEW
    severity_after: Optional[str] = None   # None for FIXED
    source_tool: str
    days_open: Optional[int] = None        # populated for PERSISTENT findings
    first_seen_scan_id: str
    last_seen_scan_id: str


class DriftReport(BaseModel):
    """Full drift comparison between two scans of a target."""

    target: str
    scan_from: str
    scan_to: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    new_count: int = 0
    fixed_count: int = 0
    regressed_count: int = 0
    persistent_count: int = 0
    improved_count: int = 0
    entries: list[DriftEntry] = Field(default_factory=list)
    trend_score: float = 0.0  # positive = improving, negative = regressing


class ScanDiffer:
    """Compares findings between scans to detect drift over time."""

    def compare(
        self,
        target: str,
        scan_id_from: str,
        scan_id_to: str,
    ) -> DriftReport:
        """Compare two specific scans of the same target.

        Args:
            target: The target hostname/IP/URL these scans belong to.
            scan_id_from: The earlier scan's ID (baseline).
            scan_id_to: The later scan's ID (comparison point).

        Returns:
            A DriftReport describing what changed between the two scans.
        """
        from cape.db.session import db_session
        from cape.db.models import FindingModel

        with db_session() as session:
            findings_from = (
                session.query(FindingModel)
                .filter(FindingModel.scan_id == scan_id_from, FindingModel.target == target)
                .all()
            )
            findings_to = (
                session.query(FindingModel)
                .filter(FindingModel.scan_id == scan_id_to, FindingModel.target == target)
                .all()
            )

            return self._diff_finding_models(
                target=target,
                scan_id_from=scan_id_from,
                scan_id_to=scan_id_to,
                findings_from=findings_from,
                findings_to=findings_to,
            )

    def compare_last_n(self, target: str, n: int) -> list[DriftReport]:
        """Compare each consecutive pair across the last N scans of a target.

        Args:
            target: The target hostname/IP/URL.
            n: Number of most recent scans to consider (n-1 reports returned).

        Returns:
            List of DriftReport, oldest-pair-first, one per consecutive
            scan pair among the last n scans.
        """
        from cape.db.session import db_session
        from cape.db.models import FindingModel

        with db_session() as session:
            scan_ids = (
                session.query(FindingModel.scan_id)
                .filter(FindingModel.target == target, FindingModel.scan_id.isnot(None))
                .distinct()
                .all()
            )
            # FindingModel has no direct started_at; order via the Scan table instead.
            from cape.db.models import Scan
            scans = (
                session.query(Scan)
                .join(FindingModel, FindingModel.scan_id == Scan.id)
                .filter(FindingModel.target == target)
                .distinct()
                .order_by(Scan.started_at.asc())
                .limit(n)
                .all()
            )
            ordered_ids = [s.id for s in scans]

        reports = []
        for earlier, later in zip(ordered_ids, ordered_ids[1:]):
            reports.append(self.compare(target, earlier, later))
        return reports

    def _diff_finding_models(
        self,
        target: str,
        scan_id_from: str,
        scan_id_to: str,
        findings_from: list,
        findings_to: list,
    ) -> DriftReport:
        """Core diff logic, operating on raw FindingModel rows."""
        fp_from = {self._fingerprint_model(f): f for f in findings_from}
        fp_to = {self._fingerprint_model(f): f for f in findings_to}

        all_fingerprints = set(fp_from.keys()) | set(fp_to.keys())
        entries: list[DriftEntry] = []

        counts = {s: 0 for s in FindingStatus}

        for fp in all_fingerprints:
            before = fp_from.get(fp)
            after = fp_to.get(fp)

            if before is None and after is not None:
                status = FindingStatus.NEW
                entry = DriftEntry(
                    finding_title=after.title, host=after.host, port=after.port,
                    service=after.service, status=status, severity_before=None,
                    severity_after=after.severity, source_tool=after.source_tool,
                    days_open=None, first_seen_scan_id=scan_id_to, last_seen_scan_id=scan_id_to,
                )
            elif before is not None and after is None:
                status = FindingStatus.FIXED
                entry = DriftEntry(
                    finding_title=before.title, host=before.host, port=before.port,
                    service=before.service, status=status, severity_before=before.severity,
                    severity_after=None, source_tool=before.source_tool,
                    days_open=None, first_seen_scan_id=scan_id_from, last_seen_scan_id=scan_id_from,
                )
            else:
                # Present in both - compare severity.
                before_weight = _SEVERITY_ORDER.get(before.severity, 0)
                after_weight = _SEVERITY_ORDER.get(after.severity, 0)

                if after_weight > before_weight:
                    status = FindingStatus.REGRESSED
                elif after_weight < before_weight:
                    status = FindingStatus.IMPROVED
                else:
                    status = FindingStatus.PERSISTENT

                days_open = None
                if status == FindingStatus.PERSISTENT:
                    days_open = self._days_between(before.timestamp, after.timestamp)

                entry = DriftEntry(
                    finding_title=after.title, host=after.host, port=after.port,
                    service=after.service, status=status, severity_before=before.severity,
                    severity_after=after.severity, source_tool=after.source_tool,
                    days_open=days_open, first_seen_scan_id=scan_id_from, last_seen_scan_id=scan_id_to,
                )

            counts[status] += 1
            entries.append(entry)

        # Sort entries: by status group, then severity descending.
        severity_for_sort = lambda e: _SEVERITY_ORDER.get(e.severity_after or e.severity_before or "INFO", 0)
        entries.sort(key=lambda e: (e.status.value, -severity_for_sort(e)))

        report = DriftReport(
            target=target,
            scan_from=scan_id_from,
            scan_to=scan_id_to,
            new_count=counts[FindingStatus.NEW],
            fixed_count=counts[FindingStatus.FIXED],
            regressed_count=counts[FindingStatus.REGRESSED],
            persistent_count=counts[FindingStatus.PERSISTENT],
            improved_count=counts[FindingStatus.IMPROVED],
            entries=entries,
        )
        report.trend_score = self._compute_trend_score(report)
        return report

    def _fingerprint(self, finding) -> str:
        """Canonical identifier for a finding across scans.

        = SHA-256 of (host, port, protocol, category, normalized title).
        This is THE key design decision: findings are matched by semantic
        identity, not UUID (which changes every scan).

        Works on either a Finding (pydantic) or FindingModel (SQLAlchemy)
        instance, since both expose the same attribute names.
        """
        return self._fingerprint_model(finding)

    @staticmethod
    def _normalize_title(title: str) -> str:
        """Lowercase a title and strip embedded timestamps/IDs."""
        normalized = title.lower().strip()
        for pattern in _NORMALIZE_PATTERNS:
            normalized = pattern.sub("", normalized)
        return re.sub(r"\s+", " ", normalized).strip()

    def _fingerprint_model(self, finding) -> str:
        """Compute the SHA-256 fingerprint for any finding-like object."""
        host = getattr(finding, "host", "") or ""
        port = getattr(finding, "port", None)
        protocol = getattr(finding, "protocol", "") or ""
        category = getattr(finding, "category", "")
        category_value = category.value if hasattr(category, "value") else str(category)
        title = self._normalize_title(getattr(finding, "title", ""))

        canonical = f"{host}|{port}|{protocol}|{category_value}|{title}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _days_between(earlier: datetime, later: datetime) -> int:
        """Days elapsed between two timestamps, floor, non-negative."""
        if earlier is None or later is None:
            return 0
        delta = later - earlier
        return max(delta.days, 0)

    def _compute_trend_score(self, report: DriftReport) -> float:
        """Compute the overall trend score for a DriftReport.

        formula: (fixed * 1.0 + improved * 0.5) - (new * 1.0 + regressed * 1.5)
        normalized by total findings considered. Positive = improving,
        negative = regressing, 0.0 = no signal (e.g. no findings at all).
        """
        total = (
            report.new_count + report.fixed_count + report.regressed_count
            + report.persistent_count + report.improved_count
        )
        if total == 0:
            return 0.0

        raw = (
            (report.fixed_count * 1.0 + report.improved_count * 0.5)
            - (report.new_count * 1.0 + report.regressed_count * 1.5)
        )
        return round(raw / total, 3)
