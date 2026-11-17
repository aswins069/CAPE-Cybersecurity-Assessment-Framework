"""Add scan_fingerprints table for drift detection.

CAPE Pillar C: stores a canonical SHA-256 fingerprint per finding so
`cape diff` can match the same logical finding across scans by semantic
identity (host, port, protocol, category, normalized title) rather than
by UUID, which changes on every scan.

Revision ID: add_scan_fingerprints
Revises: add_compliance_columns
Create Date: 2026-06-27
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "add_scan_fingerprints"
down_revision = "add_compliance_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the scan_fingerprints table."""
    op.create_table(
        "scan_fingerprints",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_scan_fingerprints_scan_fp", "scan_fingerprints", ["scan_id", "fingerprint"],
    )


def downgrade() -> None:
    """Drop the scan_fingerprints table."""
    op.drop_index("ix_scan_fingerprints_scan_fp", table_name="scan_fingerprints")
    op.drop_table("scan_fingerprints")
