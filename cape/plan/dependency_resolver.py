"""Dependency resolver for workflow steps using topological sort."""
from __future__ import annotations

import logging
from uuid import UUID

from cape.plan.models import WorkflowStep

logger = logging.getLogger(__name__)


class DependencyResolver:
    """Resolves prerequisite ordering for workflow steps.

    Uses Kahn's topological sort algorithm to produce a valid
    execution order that respects all prerequisite relationships.
    Detects and rejects cycles.
    """

    def resolve(self, steps: list[WorkflowStep]) -> list[WorkflowStep]:
        """Return steps in topologically sorted execution order.

        Args:
            steps: List of workflow steps with prerequisite relationships.

        Returns:
            Steps sorted so prerequisites always come before dependents.

        Raises:
            ValueError: If a cycle is detected in the dependency graph.
        """
        if not steps:
            return []

        step_map: dict[UUID, WorkflowStep] = {s.id: s for s in steps}

        # Build adjacency list and in-degree count
        in_degree: dict[UUID, int] = {s.id: 0 for s in steps}
        dependents: dict[UUID, list[UUID]] = {s.id: [] for s in steps}

        for step in steps:
            for prereq_id in step.prerequisites:
                if prereq_id in step_map:
                    in_degree[step.id] += 1
                    dependents[prereq_id].append(step.id)
                else:
                    logger.warning(f"Step '{step.name}' references unknown prereq {prereq_id}")

        # Kahn's algorithm
        queue = [sid for sid, deg in in_degree.items() if deg == 0]
        sorted_ids: list[UUID] = []

        while queue:
            current = queue.pop(0)
            sorted_ids.append(current)
            for dep_id in dependents.get(current, []):
                in_degree[dep_id] -= 1
                if in_degree[dep_id] == 0:
                    queue.append(dep_id)

        if len(sorted_ids) != len(steps):
            # Cycle detected
            cycle_steps = [s.name for s in steps if s.id not in sorted_ids]
            raise ValueError(
                f"Dependency cycle detected in workflow steps: {cycle_steps}. "
                "Check your knowledge base for circular prerequisites."
            )

        return [step_map[sid] for sid in sorted_ids]

    def validate_no_cycles(self, steps: list[WorkflowStep]) -> bool:
        """Return True if no cycles exist, False otherwise."""
        try:
            self.resolve(steps)
            return True
        except ValueError:
            return False
