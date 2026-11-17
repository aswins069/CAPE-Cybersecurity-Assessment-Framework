"""Add compliance control mapping columns to findings.

CAPE Pillar B: stores the PCI-DSS, SOC2, and ISO27001 control IDs that
ComplianceMapper.annotate_finding() derives for each finding, plus the
rule_id link on opportunities used by CAPE Pillar A's explainability
engine (Bug Fix #2).

Revision ID: add_compliance_columns
Revises:
Create Date: 2026-06-27
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "add_compliance_columns"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add compliance_* JSON columns to findings, and rule_id to opportunities."""
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("compliance_pci_dss", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("compliance_soc2", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("compliance_iso27001", sa.JSON(), nullable=True))

    with op.batch_alter_table("opportunities") as batch_op:
        # CAPE Bug Fix #2: Opportunity.rule_id is now a first-class column
        # instead of being inferred via fragile attack_pattern_id prefix matching.
        batch_op.add_column(
            sa.Column("rule_id", sa.String(length=128), nullable=False, server_default="")
        )


def downgrade() -> None:
    """Remove compliance columns and rule_id."""
    with op.batch_alter_table("opportunities") as batch_op:
        batch_op.drop_column("rule_id")

    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("compliance_iso27001")
        batch_op.drop_column("compliance_soc2")
        batch_op.drop_column("compliance_pci_dss")
