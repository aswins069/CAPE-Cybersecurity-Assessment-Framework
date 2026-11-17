"""Plan engine models for CAPE."""
from __future__ import annotations

import uuid
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from cape.shared.enums import AttackDomain


class WorkflowStep(BaseModel):
    """A single step in an assessment workflow."""

    id: UUID = Field(default_factory=uuid.uuid4)
    plan_id: UUID
    step_number: int
    name: str
    description: str
    domain: AttackDomain
    tool: Optional[str] = None
    tool_args_template: Optional[str] = None  # e.g. "sqlmap -u {target_url} --dbs"
    prerequisites: list[UUID] = Field(default_factory=list)
    produces: list[str] = Field(default_factory=list)
    consumes: list[str] = Field(default_factory=list)
    estimated_duration_seconds: int = 300
    operator_action_required: bool = False
    notes: str = ""

    model_config = {"arbitrary_types_allowed": True}


class AttackPlan(BaseModel):
    """A complete assessment plan for a target."""

    id: UUID = Field(default_factory=uuid.uuid4)
    target: str
    steps: list[WorkflowStep] = Field(default_factory=list)
    graph_json: Optional[dict] = None
    created_at: Optional[str] = None

    model_config = {"arbitrary_types_allowed": True}

    @property
    def step_count(self) -> int:
        """Total number of steps."""
        return len(self.steps)

    def get_step(self, step_id: UUID) -> Optional[WorkflowStep]:
        """Get a step by ID."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None
