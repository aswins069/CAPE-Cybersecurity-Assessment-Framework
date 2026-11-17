"""CLI attack command - interactive attack session."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional
from uuid import UUID

import typer

from cape.cli.console import get_console
from cape.db.session import init_db

app = typer.Typer(help="Start or resume an interactive attack session.")


@app.command()
def attack(
    target: str = typer.Argument(..., help="Target to attack"),
    list_modules: bool = typer.Option(False, "--list", "-l", help="List available modules without starting session"),
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Jump to specific module"),
    interactive: bool = typer.Option(True, "--interactive/--no-interactive", help="Step-through mode"),
    session_id: Optional[str] = typer.Option(None, "--session-id", help="Resume a previous session UUID"),
) -> None:
    """Start an interactive attack session against a target.

    Examples:

      cape attack 192.168.1.1

      cape attack example.com --module SQLiModule

      cape attack 192.168.1.1 --list

      cape attack 192.168.1.1 --session-id <uuid> (resume)
    """
    console = get_console()
    init_db()

    # Resume session
    if session_id:
        from cape.attack.engine import AttackEngine
        engine = AttackEngine()
        session = engine.resume_session(UUID(session_id))
        if not session:
            console.print(f"[red]Could not resume session {session_id}[/red]")
            raise typer.Exit(1)
        console.print(f"[green]Session resumed:[/green] {session_id}")
        return

    from cape.core.session import new_session
    from cape.core.target_validator import TargetValidator

    validator = TargetValidator()
    try:
        target = validator.validate(target)
    except Exception as e:
        console.print(f"[red]Invalid target:[/red] {e}")
        raise typer.Exit(1)

    operator, scope_token = new_session(target)

    # Load opportunities
    from cape.show.engine import ShowEngine
    from cape.plan.engine import PlanEngine
    from cape.plan.models import AttackPlan

    show_engine = ShowEngine()
    plan_engine = PlanEngine()

    findings = show_engine.load_findings_from_db(target)
    if not findings:
        console.print(f"[yellow]No findings for {target}. Run 'cape scan {target}' first.[/yellow]")
        raise typer.Exit(0)

    opportunities = show_engine.analyze(target=target, findings=findings)

    if list_modules:
        from cape.attack.engine import AttackEngine
        engine = AttackEngine()
        available = engine.list_modules(opportunities)
        console.print(f"\n[bold]Available modules for {target}:[/bold]")
        for mod_name in available:
            console.print(f"  • {mod_name}")
        return

    attack_plan = plan_engine.build_plan(target=target, opportunities=opportunities)

    # Start attack session
    from cape.attack.engine import AttackEngine
    engine = AttackEngine()

    console.print(f"\n[bold]Starting attack session:[/bold] {target}")
    console.print(f"Operator: {operator} | Opportunities: {len(opportunities)} | Plan steps: {attack_plan.step_count}")

    session = engine.start_session(
        target=target,
        plan=attack_plan,
        opportunities=opportunities,
        operator=operator,
        scope_token=scope_token,
        module_filter=module,
        step_through=interactive,
        findings=findings,
    )

    console.print(f"\n[bold]Session complete:[/bold] {session.state.value}")
    console.print(f"Steps completed: {len(session.steps_completed)}")
    console.print(f"[dim]Run 'cape report {target} --session-id {session.id}' to generate report[/dim]")
