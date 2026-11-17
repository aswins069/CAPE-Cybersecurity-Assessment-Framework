"""CAPE Pillar D — Tamper-Evident, Hash-Chained Audit Log.

Replaces the flat-file AuditLogger with a hash chain: every entry embeds
the SHA-256 hash of the entry before it, so any retroactive edit,
deletion, or reordering of a past entry is cryptographically detectable
via verify_chain(). ChainedAuditLogger is a drop-in replacement that
implements the exact same method surface as AuditLogger.
"""
from __future__ import annotations

import hashlib
import json
import logging
import socket
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from cape.shared.enums import EventType

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64  # the first entry's prev_hash, by convention


class AuditEntry(BaseModel):
    """One entry in the hash-chained audit log."""

    sequence: int  # monotonic, starts at 1
    timestamp: str  # ISO 8601 UTC
    event_type: str
    target: str
    operator: str
    detail: str
    ip_address: str
    prev_hash: str  # SHA-256 of the previous entry's canonical JSON
    entry_hash: str  # SHA-256 of this entry's canonical JSON (excl. entry_hash itself)

    def canonical_payload(self) -> dict:
        """The dict that gets hashed - everything except entry_hash itself."""
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "target": self.target,
            "operator": self.operator,
            "detail": self.detail,
            "ip_address": self.ip_address,
            "prev_hash": self.prev_hash,
        }


class ChainVerificationResult(BaseModel):
    """Result of verifying the integrity of the entire audit chain."""

    valid: bool
    total_entries: int
    first_broken_sequence: Optional[int] = None
    broken_at_timestamp: Optional[str] = None
    corrupt_lines: list[int] = []
    message: str


def _hash_payload(payload: dict) -> str:
    """SHA-256 hex digest of a canonical (sorted-key) JSON encoding of payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ChainedAuditLogger:
    """Hash-chained, append-only audit logger.

    Drop-in replacement for AuditLogger: implements the same public
    method surface (log, log_scope_authorized, log_scan_start, etc.) so
    every existing call site keeps working unmodified, while gaining a
    cryptographically verifiable history.

    Security properties:
      - The log file is only ever opened in append ('a') mode - never
        truncated or rewritten by this class.
      - verify_chain() is strictly read-only and never modifies the log.
      - Every write also mirrors to the audit_chain DB table (best
        effort) so the chain can be queried without re-parsing the file.
    """

    def __init__(self, audit_log_file: Path) -> None:
        """Initialize the chained audit logger.

        Args:
            audit_log_file: Path to the append-only JSONL chain file.
        """
        self.audit_log_file = audit_log_file
        self.audit_log_file.parent.mkdir(parents=True, exist_ok=True)
        self._hostname = socket.gethostname()
        self._lock = threading.RLock()
        self._warned_corrupt: set[int] = set()
        self.corrupt_lines: list[int] = []

    # --- core chain operations -------------------------------------------------

    def _read_all_entries(self) -> list[AuditEntry]:
        """Read every valid entry from the log file, in file order.

        Lines that are not valid chain entries (garbage, legacy flat-format
        lines, partial writes) are skipped and recorded in
        ``self.corrupt_lines``. Each bad line is reported once per process
        instead of on every call, and verify_chain() still treats them as a
        failure, so tamper-evidence is not weakened.
        """
        self.corrupt_lines = []
        if not self.audit_log_file.exists():
            return []

        entries: list[AuditEntry] = []
        with self.audit_log_file.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(AuditEntry(**data))
                except (json.JSONDecodeError, TypeError, ValueError) as e:
                    self.corrupt_lines.append(line_no)
                    if line_no not in self._warned_corrupt:
                        self._warned_corrupt.add(line_no)
                        logger.debug(f"Corrupt audit chain line {line_no}: {e}")
        return entries

    def _last_entry(self) -> Optional[AuditEntry]:
        """Return the last entry in the file, or None if the file is empty."""
        entries = self._read_all_entries()
        return entries[-1] if entries else None

    def log(
        self,
        event_type: EventType,
        target: str,
        operator: str,
        detail: str,
        ip_address: Optional[str] = None,
        client_id: Optional[str] = None,
    ) -> AuditEntry:
        """Append a new hash-chained entry to the audit log.

        Steps (per spec):
          1. Read the last entry to get prev_hash and sequence.
          2. Build the entry payload WITHOUT entry_hash.
          3. Compute entry_hash = SHA256(json.dumps(payload, sort_keys=True)).
          4. Set entry_hash on the entry.
          5. Append the JSON line to the file (append-only).
          6. Return the entry.

        Args:
            event_type: The kind of event being logged.
            target: Target hostname/IP/URL this event concerns.
            operator: Operator name responsible for the action.
            detail: Free-text detail of what happened.
            ip_address: Optional source IP; defaults to local hostname.
            client_id: Optional CAPE multi-tenant client ID.

        Returns:
            The newly created, hash-chained AuditEntry.
        """
        with self._lock:
            return self._append_locked(event_type, target, operator, detail, ip_address, client_id)

    def _append_locked(
        self,
        event_type: EventType,
        target: str,
        operator: str,
        detail: str,
        ip_address: Optional[str],
        client_id: Optional[str],
    ) -> AuditEntry:
        """Read-last + append as one critical section (thread- and process-safe)."""
        last = self._last_entry()
        sequence = (last.sequence + 1) if last else 1
        prev_hash = last.entry_hash if last else GENESIS_HASH

        payload = {
            "sequence": sequence,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type.value if isinstance(event_type, EventType) else str(event_type),
            "target": target,
            "operator": operator,
            "detail": detail,
            "ip_address": ip_address or self._hostname,
            "prev_hash": prev_hash,
        }
        entry_hash = _hash_payload(payload)

        entry = AuditEntry(**payload, entry_hash=entry_hash)

        try:
            # Append-only: never 'w', so a previous run's history can never
            # be silently truncated by this process.
            with self.audit_log_file.open("a", encoding="utf-8") as f:
                try:
                    import fcntl
                    fcntl.flock(f, fcntl.LOCK_EX)
                except (ImportError, OSError):
                    pass
                f.write(entry.model_dump_json() + "\n")
                f.flush()
        except OSError as e:
            logger.error(f"Failed to write audit chain entry: {e}")

        self._mirror_to_db(entry, client_id)

        return entry

    def verify_chain(self) -> ChainVerificationResult:
        """Verify the integrity of the entire hash chain. Strictly read-only.

        For each entry after the first, recomputes the hash of the
        *previous* entry's canonical payload and compares it against the
        current entry's prev_hash. The first mismatch found is reported;
        everything after it is considered untrustworthy.

        Returns:
            ChainVerificationResult describing whether the chain is
            intact, and if not, exactly where it broke.
        """
        entries = self._read_all_entries()
        corrupt = list(self.corrupt_lines)

        if corrupt:
            return ChainVerificationResult(
                valid=False, total_entries=len(entries), corrupt_lines=corrupt,
                message=(
                    f"Audit log has {len(corrupt)} unreadable line(s) (first at line {corrupt[0]}). "
                    f"Run 'cape audit --repair' to archive it and start a fresh chain."
                ),
            )

        if not entries:
            return ChainVerificationResult(
                valid=True, total_entries=0, message="Audit chain is empty - nothing to verify."
            )

        if entries[0].prev_hash != GENESIS_HASH:
            return ChainVerificationResult(
                valid=False, total_entries=len(entries), first_broken_sequence=entries[0].sequence,
                broken_at_timestamp=entries[0].timestamp,
                message=(
                    f"Chain broken at entry #{entries[0].sequence}: "
                    f"genesis entry's prev_hash is not the expected all-zero genesis hash."
                ),
            )

        prev_computed_hash = _hash_payload(entries[0].canonical_payload())
        if prev_computed_hash != entries[0].entry_hash:
            return ChainVerificationResult(
                valid=False, total_entries=len(entries), first_broken_sequence=entries[0].sequence,
                broken_at_timestamp=entries[0].timestamp,
                message=f"Chain broken at entry #{entries[0].sequence}: entry_hash does not match its own content.",
            )

        for i in range(1, len(entries)):
            current = entries[i]
            previous = entries[i - 1]

            recomputed_prev_hash = _hash_payload(previous.canonical_payload())

            if recomputed_prev_hash != previous.entry_hash:
                return ChainVerificationResult(
                    valid=False, total_entries=len(entries), first_broken_sequence=previous.sequence,
                    broken_at_timestamp=previous.timestamp,
                    message=f"Chain broken at entry #{previous.sequence}: its content does not match its own entry_hash.",
                )

            if current.prev_hash != previous.entry_hash:
                return ChainVerificationResult(
                    valid=False, total_entries=len(entries), first_broken_sequence=current.sequence,
                    broken_at_timestamp=current.timestamp,
                    message=(
                        f"Chain broken at entry #{current.sequence} ({current.timestamp}): "
                        f"this entry's prev_hash does not match entry #{previous.sequence}. "
                        f"All entries after #{current.sequence} cannot be trusted."
                    ),
                )

            if current.sequence != previous.sequence + 1:
                return ChainVerificationResult(
                    valid=False, total_entries=len(entries), first_broken_sequence=current.sequence,
                    broken_at_timestamp=current.timestamp,
                    message=(
                        f"Chain broken: sequence jumps from #{previous.sequence} to "
                        f"#{current.sequence} - an entry appears to have been deleted."
                    ),
                )

        return ChainVerificationResult(
            valid=True, total_entries=len(entries),
            message=f"✓ Audit chain intact — {len(entries)} entries verified",
        )

    def repair(self) -> Optional[Path]:
        """Archive an unreadable/broken log and start a fresh chain.

        The original file is never deleted or edited: it is renamed to
        ``<name>.broken-<UTC timestamp>`` so the evidence is preserved, and a
        new chain begins at the genesis entry on the next log() call.

        Returns:
            Path of the archived file, or None if there was nothing to archive.
        """
        with self._lock:
            if not self.audit_log_file.exists() or self.audit_log_file.stat().st_size == 0:
                return None
            stamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            archive = self.audit_log_file.with_name(f"{self.audit_log_file.name}.broken-{stamp}")
            self.audit_log_file.rename(archive)
            self._warned_corrupt.clear()
            self.corrupt_lines = []
            self.log(
                EventType.TOOL_EXECUTE,
                target="audit-chain", operator="system",
                detail=f"Audit chain restarted; previous log archived to {archive.name}",
            )
            return archive

    def _mirror_to_db(self, entry: AuditEntry, client_id: Optional[str]) -> None:
        """Best-effort mirror of a chain entry into the audit_chain DB table."""
        try:
            from cape.db.session import db_session
            from cape.db.models import AuditChainEntry

            with db_session() as session:
                session.merge(AuditChainEntry(
                    sequence=entry.sequence, timestamp=entry.timestamp, event_type=entry.event_type,
                    target=entry.target, operator=entry.operator, detail=entry.detail,
                    ip_address=entry.ip_address, prev_hash=entry.prev_hash, entry_hash=entry.entry_hash,
                    client_id=client_id,
                ))
        except Exception as e:
            logger.error(f"Failed to mirror audit entry to DB: {e}")

    def tail(self, n: int) -> list[AuditEntry]:
        """Return the last n entries in the chain."""
        entries = self._read_all_entries()
        return entries[-n:] if n > 0 else entries

    def filter_entries(
        self,
        target: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> list[AuditEntry]:
        """Filter entries by target and/or a minimum timestamp."""
        entries = self._read_all_entries()
        if target:
            entries = [e for e in entries if e.target == target]
        if since:
            since_str = since.isoformat()
            entries = [e for e in entries if e.timestamp >= since_str]
        return entries

    # --- drop-in compatibility with AuditLogger's named helper methods ---------

    def log_scope_authorized(self, target: str, operator: str, scope_file: str) -> AuditEntry:
        """Log a successful scope authorization."""
        return self.log(
            EventType.SCOPE_AUTHORIZED, target=target, operator=operator,
            detail=f"Target authorized via scope file: {scope_file}",
        )

    def log_scope_refused(self, target: str, operator: str, reason: str) -> AuditEntry:
        """Log a refused scope check."""
        return self.log(
            EventType.SCOPE_REFUSED, target=target, operator=operator,
            detail=f"Authorization refused: {reason}",
        )

    def log_tool_execute(self, target: str, operator: str, argv: list[str]) -> AuditEntry:
        """Log a tool execution with exact argv."""
        return self.log(
            EventType.TOOL_EXECUTE, target=target, operator=operator,
            detail=f"Executing: {' '.join(argv)}",
        )

    def log_scan_start(self, target: str, operator: str, profile: str) -> AuditEntry:
        """Log scan start."""
        return self.log(
            EventType.SCAN_START, target=target, operator=operator,
            detail=f"Starting scan profile: {profile}",
        )

    def log_scan_complete(self, target: str, operator: str, finding_count: int) -> AuditEntry:
        """Log scan completion."""
        return self.log(
            EventType.SCAN_COMPLETE, target=target, operator=operator,
            detail=f"Scan complete. Findings: {finding_count}",
        )

    def log_scan_fail(self, target: str, operator: str, error: str) -> AuditEntry:
        """Log scan failure."""
        return self.log(
            EventType.SCAN_FAIL, target=target, operator=operator,
            detail=f"Scan failed: {error}",
        )

    def log_attack_start(self, target: str, operator: str, module: str) -> AuditEntry:
        """Log attack session start."""
        return self.log(
            EventType.ATTACK_START, target=target, operator=operator,
            detail=f"Attack session started, module: {module}",
        )

    def log_attack_complete(self, target: str, operator: str, session_id: str) -> AuditEntry:
        """Log attack session completion."""
        return self.log(
            EventType.ATTACK_COMPLETE, target=target, operator=operator,
            detail=f"Attack session completed: {session_id}",
        )

    def log_report_generated(self, target: str, operator: str, fmt: str, path: str) -> AuditEntry:
        """Log report generation."""
        return self.log(
            EventType.REPORT_GENERATED, target=target, operator=operator,
            detail=f"Report generated [{fmt}]: {path}",
        )


_audit_logger: Optional[ChainedAuditLogger] = None


def get_audit_logger() -> ChainedAuditLogger:
    """Get or create the global ChainedAuditLogger singleton.

    CAPE replaces the flat AuditLogger with ChainedAuditLogger here so
    every existing call site (scope_gate, scan/engine, attack/engine,
    cli/commands/report, scan/plugins/base) transparently gets
    tamper-evident logging with no code changes required.
    """
    global _audit_logger
    if _audit_logger is None:
        from cape.core.config import get_config
        cfg = get_config()
        _audit_logger = ChainedAuditLogger(cfg.audit_log_file)
    return _audit_logger
