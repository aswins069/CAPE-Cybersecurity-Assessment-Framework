"""Base attack module class for CAPE."""
from __future__ import annotations

import shutil
from abc import ABC, abstractmethod

from cape.attack.models import (
    AttackSession,
    Evidence,
    ModuleContext,
    ToolPreparationResult,
    ValidationResult,
)
from cape.plan.models import WorkflowStep
from cape.scan.plugins.base import StepResult
from cape.shared.enums import AttackDomain
from cape.shared.finding import Finding


class BaseAttackModule(ABC):
    """Abstract base class for all attack modules.

    Each module handles one attack domain and is only shown in the menu
    when matching opportunities have been identified.
    """

    name: str = ""
    domain: AttackDomain = AttackDomain.WEB
    required_opportunity_ids: list[str] = []
    required_tools: list[str] = []

    @abstractmethod
    def load_context(
        self,
        target: str,
        session: AttackSession,
        findings: list[Finding],
    ) -> ModuleContext:
        """Load execution context for this module.

        Args:
            target: Target being assessed.
            session: Active attack session.
            findings: Findings from scan engine.

        Returns:
            ModuleContext with target, session, and findings.
        """

    @abstractmethod
    def validate_preconditions(self, ctx: ModuleContext) -> ValidationResult:
        """Check all preconditions before execution.

        Args:
            ctx: Module context.

        Returns:
            ValidationResult with valid flag and any missing requirements.
        """

    @abstractmethod
    def get_steps(self, ctx: ModuleContext) -> list[WorkflowStep]:
        """Return the workflow steps for this module.

        Args:
            ctx: Module context.

        Returns:
            List of WorkflowStep objects operator will review.
        """

    @abstractmethod
    def prepare_tools(self, ctx: ModuleContext) -> ToolPreparationResult:
        """Check and prepare required tools.

        Args:
            ctx: Module context.

        Returns:
            ToolPreparationResult indicating readiness.
        """

    @abstractmethod
    def execute_step(
        self,
        step: WorkflowStep,
        ctx: ModuleContext,
        operator_inputs: dict,
    ) -> StepResult:
        """Execute a single workflow step.

        Args:
            step: Step to execute.
            ctx: Module context.
            operator_inputs: Values provided by operator (URLs, params, etc.).

        Returns:
            StepResult with output, success flag, and findings.
        """

    @abstractmethod
    def collect_results(self, step_results: list[StepResult]) -> list[Finding]:
        """Collect and normalize findings from step results.

        Args:
            step_results: Results from executed steps.

        Returns:
            Normalized Finding list.
        """

    @abstractmethod
    def persist_results(
        self,
        findings: list[Finding],
        session: AttackSession,
    ) -> None:
        """Persist findings to the database.

        Args:
            findings: Findings to persist.
            session: Active attack session.
        """

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is installed."""
        return shutil.which(tool_name) is not None

    def _check_tools(self) -> ToolPreparationResult:
        """Check all required tools are available."""
        missing = [t for t in self.required_tools if not self._check_tool(t)]
        return ToolPreparationResult(
            ready=not missing,
            missing_tools=missing,
            messages=[f"Missing: {t}" for t in missing],
        )
