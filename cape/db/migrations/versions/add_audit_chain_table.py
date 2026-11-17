"""Add audit_chain table for the tamper-evident, hash-chained audit log.

CAPE Pillar D: mirrors the append-only JSONL chain file into a queryable
DB table (filter by target/date) without ever needing to re-parse the
flat file. The file remains the canonical, independently-verifiable
source of truth; this table is a best-effort, queryable mirror.

Revision ID: add_audit_chain_table
Revises: add_scan_fingerprints
Create Date: 2026-06-27
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "add_audit_chain_table"
down_revision = "add_scan_fingerprints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the audit_chain table."""
    op.create_table(
        "audit_chain",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("timestamp", sa.String(length=40), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("operator", sa.String(length=128), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_audit_chain_target_timestamp", "audit_chain", ["target", "timestamp"],
    )
    op.create_index("ix_audit_chain_client_id", "audit_chain", ["client_id"])


def downgrade() -> None:
    """Drop the audit_chain table."""
    op.drop_index("ix_audit_chain_client_id", table_name="audit_chain")
    op.drop_index("ix_audit_chain_target_timestamp", table_name="audit_chain")
    op.drop_table("audit_chain")
