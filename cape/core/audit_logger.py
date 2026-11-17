"""Audit logging for CAPE.

Every target access attempt, tool execution, and scope decision is logged.
"""
from __future__ import annotations

import json
import logging
import socket
from datetime import datetime
from pathlib import Path
from typing import Optional

from cape.shared.enums import EventType


class AuditLogger:
    """Structured audit logger writing to the audit log file.

    Logs every significant operation: scope decisions, scans, tool executions,
    report generation. Each entry is a JSON line.
    """

    def __init__(self, audit_log_file: Path) -> None:
        """Initialize audit logger with path to audit log file."""
        self.audit_log_file = audit_log_file
        self.audit_log_file.parent.mkdir(parents=True, exist_ok=True)
        self._hostname = socket.gethostname()

    def _write(self, entry: dict) -> None:
        """Append a JSON audit entry to the log file."""
        try:
            with self.audit_log_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            logging.error(f"Failed to write audit log: {e}")

    def log(
        self,
        event_type: EventType,
        target: str,
        operator: str,
        detail: str,
        ip_address: Optional[str] = None,
    ) -> None:
        """Write a structured audit log entry."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type.value,
            "target": target,
            "operator": operator,
            "detail": detail,
            "ip_address": ip_address or self._hostname,
        }
        self._write(entry)

    def log_scope_authorized(self, target: str, operator: str, scope_file: str) -> None:
        """Log a successful scope authorization."""
        self.log(
            EventType.SCOPE_AUTHORIZED,
            target=target,
            operator=operator,
            detail=f"Target authorized via scope file: {scope_file}",
        )

    def log_scope_refused(self, target: str, operator: str, reason: str) -> None:
        """Log a refused scope check."""
        self.log(
            EventType.SCOPE_REFUSED,
            target=target,
            operator=operator,
            detail=f"Authorization refused: {reason}",
        )

    def log_tool_execute(self, target: str, operator: str, argv: list[str]) -> None:
        """Log a tool execution with exact argv."""
        self.log(
            EventType.TOOL_EXECUTE,
            target=target,
            operator=operator,
            detail=f"Executing: {' '.join(argv)}",
        )

    def log_scan_start(self, target: str, operator: str, profile: str) -> None:
        """Log scan start."""
        self.log(
            EventType.SCAN_START,
            target=target,
            operator=operator,
            detail=f"Starting scan profile: {profile}",
        )

    def log_scan_complete(self, target: str, operator: str, finding_count: int) -> None:
        """Log scan completion."""
        self.log(
            EventType.SCAN_COMPLETE,
            target=target,
            operator=operator,
            detail=f"Scan complete. Findings: {finding_count}",
        )

    def log_scan_fail(self, target: str, operator: str, error: str) -> None:
        """Log scan failure."""
        self.log(
            EventType.SCAN_FAIL,
            target=target,
            operator=operator,
            detail=f"Scan failed: {error}",
        )

    def log_attack_start(self, target: str, operator: str, module: str) -> None:
        """Log attack session start."""
        self.log(
            EventType.ATTACK_START,
            target=target,
            operator=operator,
            detail=f"Attack session started, module: {module}",
        )

    def log_attack_complete(self, target: str, operator: str, session_id: str) -> None:
        """Log attack session completion."""
        self.log(
            EventType.ATTACK_COMPLETE,
            target=target,
            operator=operator,
            detail=f"Attack session completed: {session_id}",
        )

    def log_report_generated(self, target: str, operator: str, fmt: str, path: str) -> None:
        """Log report generation."""
        self.log(
            EventType.REPORT_GENERATED,
            target=target,
            operator=operator,
            detail=f"Report generated [{fmt}]: {path}",
        )


_audit_logger: Optional["AuditLogger"] = None


def get_audit_logger():
    """Get or create the global audit logger singleton.

    CAPE Pillar D: this now returns a ChainedAuditLogger, a drop-in
    replacement for AuditLogger that adds a tamper-evident hash chain.
    Every call site that previously did `get_audit_logger().log_xxx(...)`
    keeps working unmodified, since ChainedAuditLogger implements the
    exact same method surface as the AuditLogger class defined above.
    """
    from cape.core.audit_chain import get_audit_logger as get_chained_audit_logger
    return get_chained_audit_logger()
