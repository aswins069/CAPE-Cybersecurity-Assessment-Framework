"""Plan engine - builds assessment plans from opportunities."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

import yaml

from cape.plan.dependency_resolver import DependencyResolver
from cape.plan.graph import AttackGraphGenerator
from cape.plan.models import AttackPlan, WorkflowStep
from cape.show.models import Opportunity
from cape.shared.enums import AttackDomain

logger = logging.getLogger(__name__)

WORKFLOWS_DIR = Path(__file__).parent / "workflows"


class ToolMapper:
    """Maps workflow template variables to concrete tool commands."""

    def interpolate(self, template: str, context: dict[str, Any]) -> str:
        """Replace {variable} placeholders in a template string.

        Args:
            template: Template string with {variable} placeholders.
            context: Dict of variable values.

        Returns:
            Interpolated string.
        """
        try:
            return template.format(**context)
        except KeyError as e:
            logger.warning(f"Template variable {e} not found in context")
            return template


class PlanEngine:
    """Builds assessment plans from opportunities.

    Loads workflow templates, instantiates steps, resolves dependencies,
    and generates the attack graph.
    """

    def __init__(self, workflows_dir: Optional[Path] = None) -> None:
        """Initialize plan engine."""
        self.workflows_dir = workflows_dir or WORKFLOWS_DIR
        self.resolver = DependencyResolver()
        self.graph_gen = AttackGraphGenerator()
        self.tool_mapper = ToolMapper()

    def build_plan(
        self,
        target: str,
        opportunities: list[Opportunity],
        opportunity_ids: Optional[list[str]] = None,
    ) -> AttackPlan:
        """Build an assessment plan from a list of opportunities.

        Args:
            target: Target being assessed.
            opportunities: Identified opportunities from show engine.
            opportunity_ids: Optional filter - only include these opportunity IDs.

        Returns:
            AttackPlan with ordered workflow steps.
        """
        if opportunity_ids:
            opportunities = [o for o in opportunities if str(o.id) in opportunity_ids]

        if not opportunities:
            logger.warning("No opportunities provided for plan building")
            return AttackPlan(id=uuid.uuid4(), target=target, steps=[])

        plan_id = uuid.uuid4()
        all_steps: list[WorkflowStep] = []
        step_number = 1

        # Group opportunities by domain
        domains_needed: set[AttackDomain] = {o.domain for o in opportunities}

        # Load and instantiate workflow templates for each domain
        for domain in domains_needed:
            template = self._load_domain_template(domain)
            if not template:
                logger.warning(f"No workflow template for domain: {domain.value}")
                continue

            context = self._build_context(target, opportunities, domain)
            steps = self._instantiate_template(template, plan_id, domain, context, step_number)
            all_steps.extend(steps)
            step_number += len(steps)

        # Resolve execution order
        try:
            ordered_steps = self.resolver.resolve(all_steps)
        except ValueError as e:
            logger.error(f"Dependency resolution failed: {e}")
            ordered_steps = all_steps  # Fall back to unordered

        # Renumber steps after sorting
        for idx, step in enumerate(ordered_steps, 1):
            step.step_number = idx

        # Build graph
        graph = None
        graph_json = None
        try:
            graph = self.graph_gen.build_graph(ordered_steps)
            graph_json = self.graph_gen.to_json(graph, ordered_steps)
        except Exception as e:
            logger.error(f"Graph generation failed: {e}")

        plan = AttackPlan(
            id=plan_id,
            target=target,
            steps=ordered_steps,
            graph_json=graph_json,
            created_at=datetime.utcnow().isoformat(),
        )

        # Persist to database
        self._persist_plan(plan, target)

        return plan

    def _load_domain_template(self, domain: AttackDomain) -> Optional[dict[str, Any]]:
        """Load workflow template YAML for a domain."""
        domain_file_map = {
            AttackDomain.WEB: "web_workflow.yaml",
            AttackDomain.SMB: "smb_workflow.yaml",
            AttackDomain.NETWORK: "network_workflow.yaml",
            AttackDomain.CMS: "cms_workflow.yaml",
            AttackDomain.API: "api_workflow.yaml",
            AttackDomain.WIRELESS: "wireless_workflow.yaml",
            AttackDomain.AUTH: "auth_workflow.yaml",
        }

        filename = domain_file_map.get(domain)
        if not filename:
            return None

        path = self.workflows_dir / filename
        if not path.exists():
            logger.warning(f"Workflow template not found: {path}")
            return None

        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _build_context(
        self,
        target: str,
        opportunities: list[Opportunity],
        domain: AttackDomain,
    ) -> dict[str, Any]:
        """Build template variable context from target and opportunities."""
        # Extract URL from target if available
        url = target
        if not target.startswith("http"):
            url = f"http://{target}"

        return {
            "target": target,
            "url": url,
            "domain": domain.value.lower(),
            "port": "80",
            "service": domain.value.lower(),
            "target_url": url,
        }

    def _instantiate_template(
        self,
        template: dict[str, Any],
        plan_id: UUID,
        domain: AttackDomain,
        context: dict[str, Any],
        start_number: int,
    ) -> list[WorkflowStep]:
        """Instantiate template steps as WorkflowStep objects."""
        steps: list[WorkflowStep] = []
        template_steps = template.get("steps", [])
        prev_step_id: Optional[UUID] = None

        for i, step_def in enumerate(template_steps):
            step_id = uuid.uuid4()
            tool_args = step_def.get("tool_args_template", "")
            if tool_args:
                tool_args = self.tool_mapper.interpolate(tool_args, context)

            prereqs = []
            if prev_step_id and step_def.get("requires_previous", True):
                prereqs = [prev_step_id]

            step = WorkflowStep(
                id=step_id,
                plan_id=plan_id,
                step_number=start_number + i,
                name=step_def.get("name", f"Step {start_number + i}"),
                description=step_def.get("description", ""),
                domain=domain,
                tool=step_def.get("tool"),
                tool_args_template=tool_args,
                prerequisites=prereqs,
                produces=step_def.get("produces", []),
                consumes=step_def.get("consumes", []),
                estimated_duration_seconds=step_def.get("duration_seconds", 300),
                operator_action_required=step_def.get("operator_action_required", False),
                notes=step_def.get("notes", ""),
            )
            steps.append(step)
            prev_step_id = step_id

        return steps

    def list_plans(self, target: str) -> list[dict[str, Any]]:
        """List all plans for a target from the database."""
        try:
            from cape.db.session import db_session
            from cape.db.models import AttackPlan as APModel
            plans = []
            with db_session() as session:
                rows = session.query(APModel).filter(
                    APModel.target_obj.has(hostname_or_ip=target)
                ).all()
                for row in rows:
                    plans.append({
                        "id": row.id,
                        "created_at": str(row.created_at),
                        "step_count": row.step_count,
                    })
            return plans
        except Exception as e:
            logger.error(f"Failed to list plans: {e}")
            return []

    def _persist_plan(self, plan: AttackPlan, target: str) -> None:
        """Persist the plan and its steps to the database."""
        try:
            from cape.db.session import db_session
            from cape.db.models import AttackPlan as APModel, Target, WorkflowStepModel
            from datetime import datetime as dt

            with db_session() as session:
                # Ensure target exists
                target_obj = session.query(Target).filter_by(hostname_or_ip=target).first()
                if not target_obj:
                    target_obj = Target(hostname_or_ip=target, created_at=dt.utcnow())
                    session.add(target_obj)
                    session.flush()

                ap = APModel(
                    id=str(plan.id),
                    target_id=target_obj.id,
                    created_at=dt.utcnow(),
                    graph_json=plan.graph_json,
                    step_count=len(plan.steps),
                )
                session.add(ap)

                for step in plan.steps:
                    ws = WorkflowStepModel(
                        id=str(step.id),
                        plan_id=str(plan.id),
                        step_number=step.step_number,
                        name=step.name,
                        description=step.description,
                        domain=step.domain.value,
                        tool=step.tool,
                        tool_args_template=step.tool_args_template,
                        prerequisites=[str(p) for p in step.prerequisites],
                        produces=step.produces,
                        consumes=step.consumes,
                        estimated_duration_seconds=step.estimated_duration_seconds,
                        operator_action_required=step.operator_action_required,
                        notes=step.notes,
                    )
                    session.add(ws)
        except Exception as e:
            logger.error(f"Failed to persist plan: {e}")
