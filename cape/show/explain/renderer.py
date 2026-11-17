"""CAPE Pillar A — Rich terminal renderer for OpportunityTrace.

Renders a full, human-readable breakdown of why an opportunity got the
score it did: which rule conditions matched (and on what evidence),
every factor in the scoring formula, and the supporting findings.
"""
from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cape.show.explain.trace_models import OpportunityTrace

_SEVERITY_COLORS = {
    "INFO": "dim",
    "LOW": "cyan",
    "MEDIUM": "yellow",
    "HIGH": "bold red",
    "CRITICAL": "bold white on red",
}


def render_trace(trace: OpportunityTrace, console: Console, deep: bool = False) -> None:
    """Render one OpportunityTrace to the given Rich console.

    Args:
        trace: The trace to render.
        console: Rich Console to print to.
        deep: If True, show raw output file paths and evidence in full.
    """
    severity_style = _SEVERITY_COLORS.get(trace.final_severity, "white")

    header = Text()
    header.append(f"{trace.opportunity_name}\n", style="bold")
    header.append(f"rule_id: {trace.rule_id}\n", style="dim")
    header.append(f"target:  {trace.target}\n", style="dim")
    header.append("score:    ")
    header.append(f"{trace.final_score:.2f}", style=severity_style)
    header.append("   severity: ")
    header.append(trace.final_severity, style=severity_style)

    console.print(Panel(header, title="Opportunity", border_style="blue"))

    _render_conditions_section(trace, console)
    _render_score_section(trace, console)
    _render_evidence_section(trace, console, deep=deep)
    _render_remediation_section(trace, console)

    if not trace.score_consistent:
        console.print(
            Panel(
                f"[bold yellow]⚠ Inconsistency detected:[/bold yellow] recomputed score "
                f"{trace.recomputed_score:.2f} differs from the score shown to the operator "
                f"({trace.final_score:.2f}) by more than {0.05:.2f}. The scoring pipeline "
                f"may have changed since this opportunity was generated.",
                border_style="yellow",
            )
        )


def _render_conditions_section(trace: OpportunityTrace, console: Console) -> None:
    """Render the rule conditions table."""
    console.print("\n[bold]Rule Conditions[/bold]")

    table = Table(show_lines=False)
    table.add_column("Field")
    table.add_column("Operator")
    table.add_column("Expected")
    table.add_column("Result")
    table.add_column("Matched On")

    for cond in trace.conditions:
        result_text = Text("✓", style="green") if cond.matched else Text("✗", style="red")
        matched_on = cond.matched_finding_title or "—"
        table.add_row(cond.field, cond.operator, cond.expected_value, result_text, matched_on)

    console.print(table)

    if trace.required_findings_list:
        status = "✓" if trace.required_findings_met else "✗"
        style = "green" if trace.required_findings_met else "red"
        console.print(
            f"Required finding categories {trace.required_findings_list}: "
            f"[{style}]{status}[/{style}]"
        )


def _render_score_section(trace: OpportunityTrace, console: Console) -> None:
    """Render the score calculation table and formula."""
    console.print("\n[bold]Score Calculation[/bold]")
    console.print(f"[dim]{trace.score_formula_string}[/dim]")

    table = Table(show_lines=False)
    table.add_column("Component")
    table.add_column("Value", justify="right")
    table.add_column("Source")

    for comp in trace.score_components:
        table.add_row(comp.label, f"{comp.value:.3f}", comp.source)

    console.print(table)

    values_str = " × ".join(f"{c.value:.3f}" for c in trace.score_components)
    consistency_mark = "✓" if trace.score_consistent else "⚠"
    consistency_style = "green" if trace.score_consistent else "yellow"
    console.print(
        f"{values_str} = {trace.recomputed_score:.2f}  →  shown: {trace.final_score:.2f} "
        f"[{consistency_style}]{consistency_mark}[/{consistency_style}]"
    )

    if trace.severity_rationale:
        console.print(f"[dim]{trace.severity_rationale}[/dim]")


def _render_evidence_section(trace: OpportunityTrace, console: Console, deep: bool) -> None:
    """Render the supporting evidence section."""
    console.print("\n[bold]Supporting Evidence[/bold]")

    if not trace.supporting_findings:
        console.print("[dim]No supporting findings recorded.[/dim]")
        return

    for f in trace.supporting_findings:
        console.print(
            f"  • [bold]{f.title}[/bold]  "
            f"(tool: {f.source_tool}, confidence: {f.confidence:.2f}, severity: {f.severity})"
        )
        console.print(f"    [dim]{f.evidence}[/dim]")
        if deep and f.raw_output_file:
            console.print(f"    [dim]raw output: {f.raw_output_file}[/dim]")


_STAGE_LABELS = {
    "immediate": "Immediate",
    "short_term": "Short-term",
    "long_term": "Long-term",
}
_STAGE_ORDER = ["immediate", "short_term", "long_term"]


def _render_remediation_section(trace: OpportunityTrace, console: Console) -> None:
    """Render the countermeasures & verification section for this opportunity."""
    console.print("\n[bold]Remediation & Countermeasures[/bold]")

    plan = trace.remediation
    if plan is None or (not plan.countermeasures and not plan.residual_risk_note):
        console.print("[dim]No remediation guidance available for this opportunity.[/dim]")
        return

    console.print(f"[bold]{plan.priority}[/bold]  [dim]({plan.summary})[/dim]")

    if plan.residual_risk_note:
        console.print(f"[yellow]{plan.residual_risk_note}[/yellow]")

    by_stage: dict[str, list] = {s: [] for s in _STAGE_ORDER}
    for cm in plan.countermeasures:
        by_stage.setdefault(cm.stage, []).append(cm)

    for stage in _STAGE_ORDER + [s for s in by_stage if s not in _STAGE_ORDER]:
        items = by_stage.get(stage) or []
        if not items:
            continue
        console.print(f"\n[bold cyan]{_STAGE_LABELS.get(stage, stage.title())}[/bold cyan]")
        for cm in items:
            effort_tag = f"  [dim](effort: {cm.effort})[/dim]" if cm.effort else ""
            mitre_tag = f"  [dim]MITRE {cm.mitre_mitigation}[/dim]" if cm.mitre_mitigation else ""
            console.print(f"  • [bold]{cm.title}[/bold]{effort_tag}{mitre_tag}")
            console.print(f"    [dim]{cm.description}[/dim]")

    if plan.verification_steps:
        console.print("\n[bold]Verify the fix[/bold]")
        for step in plan.verification_steps:
            console.print(f"  ✓ {step}")


def render_traces_json(traces: list[OpportunityTrace]) -> str:
    """Serialize a list of traces to a JSON string for --format json."""
    return json.dumps([t.model_dump(mode="json") for t in traces], indent=2, default=str)
