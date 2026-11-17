"""Add NIST CSF and CIS Controls compliance columns to findings.

CAPE Pillar B: extends the compliance mapping engine (Section 15 of the
CAPE spec) beyond PCI-DSS/SOC2/ISO27001 to also store NIST CSF 2.0 and
CIS Controls v8 IDs that ComplianceMapper.annotate_finding() derives.

Revision ID: add_csf_cis_columns
Revises: add_compliance_columns
Create Date: 2026-08-15
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "add_csf_cis_columns"
down_revision = "add_compliance_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add compliance_nist_csf and compliance_cis_controls JSON columns."""
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("compliance_nist_csf", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("compliance_cis_controls", sa.JSON(), nullable=True))


def downgrade() -> None:
    """Remove the NIST CSF and CIS Controls columns."""
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("compliance_cis_controls")
        batch_op.drop_column("compliance_nist_csf")
