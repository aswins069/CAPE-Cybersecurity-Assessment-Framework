"""Unit tests for CAPE Pillar D: ChainedAuditLogger / hash chain integrity."""
from __future__ import annotations

import json

import pytest

from cape.core.audit_chain import GENESIS_HASH, ChainedAuditLogger
from cape.shared.enums import EventType


@pytest.fixture
def chained_logger(tmp_path):
    """A ChainedAuditLogger writing to a temp file (no DB mirroring needed for these tests)."""
    return ChainedAuditLogger(tmp_path / "audit_chain.jsonl")


class TestChainedAuditLogger:
    def test_genesis_entry_has_zero_prev_hash(self, chained_logger) -> None:
        """The very first entry's prev_hash must be the all-zero genesis hash."""
        entry = chained_logger.log(EventType.SCAN_START, "10.0.0.1", "alice", "first entry")
        assert entry.sequence == 1
        assert entry.prev_hash == GENESIS_HASH

    def test_second_entry_prev_hash_matches_first(self, chained_logger) -> None:
        """Entry #2's prev_hash must equal entry #1's entry_hash."""
        e1 = chained_logger.log(EventType.SCAN_START, "10.0.0.1", "alice", "first")
        e2 = chained_logger.log(EventType.SCAN_COMPLETE, "10.0.0.1", "alice", "second")
        assert e2.sequence == 2
        assert e2.prev_hash == e1.entry_hash

    def test_chain_verifies_after_n_entries(self, chained_logger) -> None:
        """A freshly written chain of several entries verifies as valid."""
        for i in range(10):
            chained_logger.log(EventType.TOOL_EXECUTE, "10.0.0.1", "alice", f"step {i}")
        result = chained_logger.verify_chain()
        assert result.valid is True
        assert result.total_entries == 10
        assert result.first_broken_sequence is None

    def test_tampered_entry_fails_verification(self, chained_logger) -> None:
        """Modifying one entry's content (without recomputing the hash) breaks the chain."""
        for i in range(5):
            chained_logger.log(EventType.TOOL_EXECUTE, "10.0.0.1", "alice", f"step {i}")

        lines = chained_logger.audit_log_file.read_text().splitlines()
        tampered = json.loads(lines[2])
        tampered["detail"] = "TAMPERED detail, hash now stale"
        lines[2] = json.dumps(tampered)
        chained_logger.audit_log_file.write_text("\n".join(lines) + "\n")

        result = chained_logger.verify_chain()
        assert result.valid is False
        assert result.first_broken_sequence == 3  # the tampered entry itself

    def test_deleted_entry_fails_verification(self, chained_logger) -> None:
        """Deleting an entry from the middle of the chain breaks it at the next entry."""
        for i in range(6):
            chained_logger.log(EventType.TOOL_EXECUTE, "10.0.0.1", "alice", f"step {i}")

        lines = chained_logger.audit_log_file.read_text().splitlines()
        del lines[2]  # delete entry #3 (0-indexed position 2)
        chained_logger.audit_log_file.write_text("\n".join(lines) + "\n")

        result = chained_logger.verify_chain()
        assert result.valid is False
        # Entry #4 now immediately follows entry #2; its prev_hash won't match.
        assert result.first_broken_sequence == 4

    def test_appended_entry_verified_correctly(self, chained_logger) -> None:
        """A normal append after several entries keeps the chain valid."""
        for i in range(3):
            chained_logger.log(EventType.TOOL_EXECUTE, "10.0.0.1", "alice", f"step {i}")
        result_before = chained_logger.verify_chain()
        assert result_before.valid is True

        chained_logger.log(EventType.SCAN_COMPLETE, "10.0.0.1", "alice", "one more")
        result_after = chained_logger.verify_chain()
        assert result_after.valid is True
        assert result_after.total_entries == 4

    def test_verify_returns_broken_sequence_number(self, chained_logger) -> None:
        """verify_chain() must report exactly which sequence number broke."""
        for i in range(4):
            chained_logger.log(EventType.TOOL_EXECUTE, "10.0.0.1", "alice", f"step {i}")

        lines = chained_logger.audit_log_file.read_text().splitlines()
        tampered = json.loads(lines[1])
        tampered["operator"] = "mallory"
        lines[1] = json.dumps(tampered)
        chained_logger.audit_log_file.write_text("\n".join(lines) + "\n")

        result = chained_logger.verify_chain()
        assert result.valid is False
        assert isinstance(result.first_broken_sequence, int)
        assert result.first_broken_sequence == 2
        assert result.broken_at_timestamp is not None

    def test_verify_chain_is_read_only(self, chained_logger) -> None:
        """verify_chain() must not modify the log file."""
        for i in range(3):
            chained_logger.log(EventType.TOOL_EXECUTE, "10.0.0.1", "alice", f"step {i}")
        before = chained_logger.audit_log_file.read_text()
        chained_logger.verify_chain()
        after = chained_logger.audit_log_file.read_text()
        assert before == after

    def test_log_file_opened_append_only(self, chained_logger) -> None:
        """Logging twice must preserve earlier entries (append, never truncate)."""
        chained_logger.log(EventType.SCAN_START, "10.0.0.1", "alice", "first")
        chained_logger.log(EventType.SCAN_COMPLETE, "10.0.0.1", "alice", "second")
        lines = chained_logger.audit_log_file.read_text().splitlines()
        assert len(lines) == 2

    def test_drop_in_method_surface_matches_auditlogger(self, chained_logger) -> None:
        """ChainedAuditLogger must expose every helper method AuditLogger has."""
        from cape.core.audit_logger import AuditLogger

        expected_methods = [
            "log", "log_scope_authorized", "log_scope_refused", "log_tool_execute",
            "log_scan_start", "log_scan_complete", "log_scan_fail",
            "log_attack_start", "log_attack_complete", "log_report_generated",
        ]
        for method in expected_methods:
            assert hasattr(AuditLogger, method)
            assert hasattr(chained_logger, method)
