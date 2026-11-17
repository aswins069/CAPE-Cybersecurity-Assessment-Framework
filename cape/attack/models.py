"""Attack engine models for CAPE."""
from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from cape.shared.enums import AttackDomain, SessionState


class Evidence(BaseModel):
    """Evidence collected during an attack session step."""

    id: UUID = Field(default_factory=uuid.uuid4)
    session_id: UUID
    step_id: UUID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tool: str
    command_run: str  # Exact argv list joined to string
    raw_output_file: Path
    summary: str
    finding_ids: list[UUID] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}


class AttackSession(BaseModel):
    """Attack session state and metadata."""

    id: UUID = Field(default_factory=uuid.uuid4)
    target: str
    plan_id: UUID
    state: SessionState = SessionState.IDLE
    selected_modules: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    operator: str
    scope_token: str
    steps_completed: list[UUID] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    notes: str = ""

    model_config = {"arbitrary_types_allowed": True}

    def transition_to(self, new_state: SessionState) -> None:
        """Transition session state."""
        valid_transitions = {
            SessionState.IDLE: [SessionState.LOADED],
            SessionState.LOADED: [SessionState.ACTIVE],
            SessionState.ACTIVE: [SessionState.PAUSED, SessionState.COMPLETED, SessionState.ABORTED],
            SessionState.PAUSED: [SessionState.ACTIVE, SessionState.ABORTED],
            SessionState.COMPLETED: [],
            SessionState.ABORTED: [],
        }
        allowed = valid_transitions.get(self.state, [])
        if new_state not in allowed:
            raise ValueError(
                f"Invalid state transition: {self.state.value} -> {new_state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        self.state = new_state


class ModuleContext(BaseModel):
    """Context passed to attack modules during execution."""

    target: str
    session: AttackSession
    findings: list = Field(default_factory=list)
    opportunities: list = Field(default_factory=list)
    workspace_path: Optional[Path] = None

    model_config = {"arbitrary_types_allowed": True}


class ValidationResult(BaseModel):
    """Result of a module precondition check."""

    valid: bool
    missing_requirements: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ToolPreparationResult(BaseModel):
    """Result of module tool preparation."""

    ready: bool
    missing_tools: list[str] = Field(default_factory=list)
    messages: list[str] = Field(default_factory=list)
