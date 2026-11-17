"""Attack graph generator using networkx for the plan engine."""
from __future__ import annotations

import json
import logging
from typing import Any, Optional
from uuid import UUID

from cape.plan.models import WorkflowStep

logger = logging.getLogger(__name__)


class AttackGraphGenerator:
    """Generates attack graphs from workflow steps using networkx.

    Exports to DOT format, JSON adjacency list, and ASCII terminal display.
    """

    def build_graph(self, steps: list[WorkflowStep]) -> Any:
        """Build a networkx DiGraph from workflow steps.

        Args:
            steps: List of workflow steps.

        Returns:
            networkx.DiGraph with steps as nodes and prerequisites as edges.
        """
        try:
            import networkx as nx
        except ImportError:
            logger.error("networkx not installed: pip install networkx")
            return None

        G = nx.DiGraph()

        for step in steps:
            G.add_node(
                str(step.id),
                label=f"{step.step_number}. {step.name}",
                domain=step.domain.value,
                tool=step.tool or "",
                operator_required=step.operator_action_required,
            )

        for step in steps:
            for prereq_id in step.prerequisites:
                if any(str(s.id) == str(prereq_id) for s in steps):
                    G.add_edge(str(prereq_id), str(step.id))

        # Verify no cycles
        if not nx.is_directed_acyclic_graph(G):
            raise ValueError("Attack graph contains a cycle - check prerequisites")

        return G

    def to_dot(self, graph: Any, steps: list[WorkflowStep]) -> str:
        """Export graph to DOT format for graphviz rendering.

        Args:
            graph: networkx DiGraph.
            steps: Original steps list for label lookup.

        Returns:
            DOT format string.
        """
        if graph is None:
            return ""

        step_map = {str(s.id): s for s in steps}
        lines = ["digraph attack_plan {", '  rankdir=LR;', '  node [shape=box];']

        for node_id in graph.nodes:
            step = step_map.get(node_id)
            if step:
                label = f"{step.step_number}. {step.name}"
                color = "red" if step.operator_action_required else "lightblue"
                lines.append(f'  "{node_id}" [label="{label}" fillcolor="{color}" style=filled];')

        for u, v in graph.edges:
            lines.append(f'  "{u}" -> "{v}";')

        lines.append("}")
        return "\n".join(lines)

    def to_json(self, graph: Any, steps: list[WorkflowStep]) -> dict:
        """Export graph to JSON adjacency list.

        Args:
            graph: networkx DiGraph.
            steps: Original steps list.

        Returns:
            Dict with nodes and edges.
        """
        if graph is None:
            return {"nodes": [], "edges": []}

        step_map = {str(s.id): s for s in steps}
        nodes = []
        edges = []

        for node_id in graph.nodes:
            step = step_map.get(node_id)
            if step:
                nodes.append({
                    "id": node_id,
                    "step_number": step.step_number,
                    "name": step.name,
                    "domain": step.domain.value,
                    "tool": step.tool,
                    "operator_required": step.operator_action_required,
                })

        for u, v in graph.edges:
            edges.append({"from": u, "to": v})

        return {"nodes": nodes, "edges": edges}

    def to_ascii(self, steps: list[WorkflowStep], max_width: int = 80) -> str:
        """Generate ASCII representation of the graph for terminal display.

        Args:
            steps: Workflow steps in execution order.
            max_width: Maximum line width.

        Returns:
            ASCII string representation.
        """
        if not steps:
            return "(no steps)"

        lines = [
            "=" * max_width,
            "ATTACK PLAN GRAPH",
            "=" * max_width,
        ]

        for step in steps:
            prereq_nums = []
            step_map = {s.id: s for s in steps}
            for prereq_id in step.prerequisites:
                prereq = step_map.get(prereq_id)
                if prereq:
                    prereq_nums.append(str(prereq.step_number))

            prefix = "  ✦ " if step.operator_action_required else "  • "
            tool_str = f" [{step.tool}]" if step.tool else ""
            prereq_str = f" (after: {', '.join(prereq_nums)})" if prereq_nums else ""
            line = f"{prefix}Step {step.step_number}: {step.name}{tool_str}{prereq_str}"
            lines.append(line[:max_width])
            if step.description:
                desc = f"      {step.description[:max_width - 8]}"
                lines.append(desc)

            if step.operator_action_required:
                lines.append("      ⚠️  OPERATOR ACTION REQUIRED")

        lines.append("=" * max_width)
        lines.append(f"  ✦ = Operator action required   • = Automated")
        lines.append("=" * max_width)

        return "\n".join(lines)
