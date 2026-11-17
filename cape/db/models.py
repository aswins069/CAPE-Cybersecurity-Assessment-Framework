"""SQLAlchemy 2.x database models for CAPE.

All entities are stored here with full FK relationships and indexes.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.sqlite import TEXT
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all models."""
    pass


class Target(Base):
    """A scan target (hostname, IP, or URL)."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname_or_ip: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="target_obj", lazy="select")
    findings: Mapped[list["FindingModel"]] = relationship("FindingModel", back_populates="target_obj")
    attack_plans: Mapped[list["AttackPlan"]] = relationship("AttackPlan", back_populates="target_obj")
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="target_obj")


class Scan(Base):
    """A scan run against a target."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_target_started", "target_id", "started_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    profile: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="PENDING")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    checkpoint_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    target_obj: Mapped["Target"] = relationship("Target", back_populates="scans")
    findings: Mapped[list["FindingModel"]] = relationship("FindingModel", back_populates="scan_obj")


class FindingModel(Base):
    """Normalized security finding from any scan plugin."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_target_severity", "target", "severity"),

    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("targets.id"), nullable=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    source_tool: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_profile: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cve_ids: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    raw_output_file: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    tags: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    extra: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    # CAPE Pillar B: compliance control mapping annotations
    compliance_pci_dss: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    compliance_soc2: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    compliance_iso27001: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    compliance_nist_csf: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    compliance_cis_controls: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    # CAPE multi-tenant client isolation
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    target_obj: Mapped[Optional["Target"]] = relationship("Target", back_populates="findings")
    scan_obj: Mapped[Optional["Scan"]] = relationship("Scan", back_populates="findings")


class OpportunityModel(Base):
    """Attack opportunity identified by the show engine."""

    __tablename__ = "opportunities"
    __table_args__ = (
        Index("ix_opportunities_target_score", "target", "score"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(32), nullable=False)
    attack_pattern_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    supporting_findings: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    recommended_modules: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)


class AINarrativeCache(Base):
    """Cached AI-generated narrative for an Opportunity's explain/remediation trace.

    Keyed on opportunity_id + a hash of the trace's scoring inputs so a
    re-run of `cape explain --ai` against unchanged data doesn't re-hit
    the Gemini API. Never used for `attack`/`plan` — AI narration is
    scoped to explainability and remediation only.
    """

    __tablename__ = "ai_narrative_cache"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    opportunity_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    trace_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    narrative: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_ai_narrative_lookup", "opportunity_id", "trace_hash", "model"),
    )


class AttackPlan(Base):
    """Generated assessment plan."""

    __tablename__ = "attack_plans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    graph_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    step_count: Mapped[int] = mapped_column(Integer, default=0)
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    target_obj: Mapped["Target"] = relationship("Target", back_populates="attack_plans")
    steps: Mapped[list["WorkflowStepModel"]] = relationship("WorkflowStepModel", back_populates="plan")


class WorkflowStepModel(Base):
    """A single step in an attack plan workflow."""

    __tablename__ = "workflow_steps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(36), ForeignKey("attack_plans.id"), nullable=False)
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(32), nullable=False)
    tool: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    tool_args_template: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    prerequisites: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    produces: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    consumes: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    estimated_duration_seconds: Mapped[int] = mapped_column(Integer, default=0)
    operator_action_required: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")

    plan: Mapped["AttackPlan"] = relationship("AttackPlan", back_populates="steps")


class AttackSessionModel(Base):
    """Attack session state."""

    __tablename__ = "attack_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="IDLE")
    selected_modules: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    operator: Mapped[str] = mapped_column(String(128), nullable=False)
    scope_token: Mapped[str] = mapped_column(String(64), nullable=False)
    steps_completed: Mapped[Optional[list]] = mapped_column(JSON, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    evidence: Mapped[list["EvidenceModel"]] = relationship("EvidenceModel", back_populates="session_obj")


class EvidenceModel(Base):
    """Evidence collected during an attack session step."""

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_session_step", "session_id", "step_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), ForeignKey("attack_sessions.id"), nullable=False)
    step_id: Mapped[str] = mapped_column(String(36), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    command_run: Mapped[str] = mapped_column(Text, nullable=False)
    raw_output_file: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    finding_ids: Mapped[Optional[list]] = mapped_column(JSON, default=list)

    session_obj: Mapped["AttackSessionModel"] = relationship("AttackSessionModel", back_populates="evidence")


class AuditLogEntry(Base):
    """Audit log entry for every significant operation."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_timestamp_target", "timestamp", "target"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=func.now(), index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    operator: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)


class Report(Base):
    """Generated report record."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    session_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    audience: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, default="full")
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    target_obj: Mapped["Target"] = relationship("Target", back_populates="reports")


class ScanFingerprint(Base):
    """CAPE Pillar C: canonical fingerprint of a finding for drift detection.

    Findings are matched across scans by semantic identity (this
    fingerprint), not by UUID, since a finding's UUID changes every scan.
    """

    __tablename__ = "scan_fingerprints"
    __table_args__ = (
        Index("ix_scan_fingerprints_scan_fp", "scan_id", "fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())


class AuditChainEntry(Base):
    """CAPE Pillar D: hash-chained, tamper-evident audit log entry.

    Mirrors the append-only file-based chain so the chain can also be
    queried (filter by target/date) without re-parsing the flat file.
    """

    __tablename__ = "audit_chain"
    __table_args__ = (
        Index("ix_audit_chain_target_timestamp", "target", "timestamp"),
    )

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    timestamp: Mapped[str] = mapped_column(String(40), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    operator: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)


class Client(Base):
    """CAPE multi-tenant client record."""

    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    contact: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    notes: Mapped[str] = mapped_column(Text, default="")
