"""Add multi-tenant client_id columns and the clients table.

CAPE multi-tenant isolation: every major table gets a nullable
client_id column (nullable for backward compatibility with pre-CAPE
data, which is treated as "legacy / no client"), plus a new `clients`
table that registers each tenant.

Revision ID: add_client_id
Revises: add_audit_chain_table
Create Date: 2026-06-27
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "add_client_id"
down_revision = "add_audit_chain_table"
branch_labels = None
depends_on = None

_TABLES_WITH_CLIENT_ID = [
    "targets", "scans", "findings", "opportunities",
    "attack_plans", "attack_sessions", "audit_log", "reports",
]


def upgrade() -> None:
    """Add a nullable client_id column to every major table, and create clients."""
    op.create_table(
        "clients",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=256), nullable=False, server_default=""),
        sa.Column("contact", sa.String(length=256), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
    )

    for table_name in _TABLES_WITH_CLIENT_ID:
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.add_column(sa.Column("client_id", sa.String(length=64), nullable=True))
        op.create_index(f"ix_{table_name}_client_id", table_name, ["client_id"])


def downgrade() -> None:
    """Remove client_id columns and the clients table."""
    for table_name in reversed(_TABLES_WITH_CLIENT_ID):
        op.drop_index(f"ix_{table_name}_client_id", table_name=table_name)
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.drop_column("client_id")

    op.drop_table("clients")
