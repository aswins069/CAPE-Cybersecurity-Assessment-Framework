"""CLI plan command - generate assessment plan."""
from __future__ import annotations

from typing import Optional

import typer

from cape.cli.console import get_console
from cape.db.session import init_db

app = typer.Typer(help="Generate an assessment plan from identified opportunities.")


@app.command()
def plan(
    target: str = typer.Argument(..., help="Target to plan for"),
    opportunity_ids: Optional[str] = typer.Option(None, "--opportunity-ids", help="Comma-separated opportunity IDs"),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, graph, json"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
) -> None:
    """Generate a structured assessment plan from opportunities.

    Examples:

      cape plan 192.168.1.1

      cape plan example.com --format graph

      cape plan 192.168.1.1 --json
    """
    console = get_console()
    init_db()

    from cape.show.engine import ShowEngine
    from cape.plan.engine import PlanEngine

    show_engine = ShowEngine()
    plan_engine = PlanEngine()

    findings = show_engine.load_findings_from_db(target)
    if not findings:
        console.print(f"[yellow]No findings for {target}. Run 'cape scan' first.[/yellow]")
        raise typer.Exit(0)

    opportunities = show_engine.analyze(target=target, findings=findings)
    if not opportunities:
        console.print("[yellow]No opportunities found to plan from.[/yellow]")
        raise typer.Exit(0)

    opp_id_filter = None
    if opportunity_ids:
        opp_id_filter = [x.strip() for x in opportunity_ids.split(",")]

    attack_plan = plan_engine.build_plan(
        target=target,
        opportunities=opportunities,
        opportunity_ids=opp_id_filter,
    )

    if json_output or fmt == "json":
        import json
        print(json.dumps({
            "plan_id": str(attack_plan.id),
            "target": attack_plan.target,
            "step_count": attack_plan.step_count,
            "steps": [
                {
                    "step_number": s.step_number,
                    "name": s.name,
                    "tool": s.tool,
                    "domain": s.domain.value,
                    "operator_required": s.operator_action_required,
                    "duration_seconds": s.estimated_duration_seconds,
                }
                for s in attack_plan.steps
            ],
        }, indent=2))
        return

    if fmt == "graph":
        from cape.plan.graph import AttackGraphGenerator
        gen = AttackGraphGenerator()
        console.print(gen.to_ascii(attack_plan.steps))
        return

    # Default: table
    from rich.table import Table
    console.print(f"\n[bold]Assessment Plan: {target}[/bold] ({attack_plan.step_count} steps)\n")

    table = Table(show_header=True, header_style="bold blue")
    table.add_column("#", width=4)
    table.add_column("Step Name", ratio=2)
    table.add_column("Domain", width=10)
    table.add_column("Tool", width=14)
    table.add_column("Duration", width=10)
    table.add_column("Manual?", width=8)

    for step in attack_plan.steps:
        manual_str = "[yellow]YES[/yellow]" if step.operator_action_required else "No"
        duration_str = f"{step.estimated_duration_seconds // 60}m"
        table.add_row(
            str(step.step_number),
            step.name,
            step.domain.value,
            step.tool or "—",
            duration_str,
            manual_str,
        )

    console.print(table)
    console.print(f"\nPlan ID: [dim]{attack_plan.id}[/dim]")
    console.print(f"[dim]Run 'cape attack {target}' to execute this plan interactively[/dim]")
