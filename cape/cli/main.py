"""CAPE CLI - main entrypoint.

Usage: co <command> [options]
"""
from __future__ import annotations

import typer
from rich.console import Console

from cape.cli.commands.scan import scan as scan_cmd
from cape.cli.commands.show import show as show_cmd
from cape.cli.commands.plan import plan as plan_cmd
from cape.cli.commands.attack import attack as attack_cmd
from cape.cli.commands.doctor import doctor as doctor_cmd
from cape.cli.commands.report import report as report_cmd
from cape.cli.commands.explain import explain as explain_cmd
from cape.cli.commands.diff import diff as diff_cmd
from cape.cli.commands.audit import audit as audit_cmd
from cape.cli.commands.clients import app as clients_app
from cape.cli.commands.demo import demo as demo_cmd

# Main typer application
app = typer.Typer(
    name="cape",
    help="""
╔═══════════════════════════════════════════════════════════════╗
║   CAPE - Continuous Assurance Penetration Testing Engine      ║
╚═══════════════════════════════════════════════════════════════╝

Pipeline: SCAN → SHOW → EXPLAIN → PLAN → ATTACK → REPORT

Run 'cape' with no arguments to launch the guided interactive menu.
    """,
    add_completion=True,
    no_args_is_help=False,
    invoke_without_command=True,
)

# Register sub-commands. Each of these wraps exactly one action, so it's
# registered directly on the root app ('cape doctor', not 'cape doctor
# doctor'). 'clients' is the one module with several sub-actions
# (use/list/add/...), so it stays a nested sub-app.
app.command(name="scan", help="Run security scans against authorized targets")(scan_cmd)
app.command(name="show", help="Show identified attack opportunities")(show_cmd)
app.command(name="plan", help="Generate assessment plans from opportunities")(plan_cmd)
app.command(name="attack", help="Start interactive attack sessions")(attack_cmd)
app.command(name="doctor", help="Check system health and dependencies")(doctor_cmd)
app.command(name="report", help="Generate assessment reports")(report_cmd)
app.command(name="explain", help="Explain why a finding got its score")(explain_cmd)
app.command(name="diff", help="Compare scans and detect drift")(diff_cmd)
app.command(name="audit", help="Inspect and verify the audit chain")(audit_cmd)
app.command(name="demo", help="Run the full pipeline on bundled sample data (no tools required)")(demo_cmd)
app.add_typer(clients_app, name="clients", help="Manage multi-tenant client isolation")


@app.callback()
def main_callback(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging", is_eager=True),
    version: bool = typer.Option(False, "--version", help="Show version and exit", is_eager=True),
) -> None:
    """CAPE - modular cybersecurity assessment framework."""
    if version:
        from cape.shared.constants import APP_VERSION
        typer.echo(f"CAPE v{APP_VERSION}")
        raise typer.Exit()

    if verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    # Ensure config dirs exist
    try:
        from cape.core.config import get_config
        from cape.core.logging import setup_logging
        cfg = get_config()
        setup_logging(cfg.log_level, cfg.log_file)
        from cape.db.session import init_db
        init_db()
    except Exception:
        pass  # Don't fail on startup - let individual commands handle it

    # CAPE: running bare 'cape' with no sub-command launches the guided
    # interactive menu instead of just printing help. Every individual
    # 'cape scan ...', 'cape show ...', etc. command keeps working exactly
    # as before - this only changes what happens with zero arguments.
    if ctx.invoked_subcommand is None:
        from cape.cli.menu import run_main_menu
        run_main_menu()
        raise typer.Exit()


@app.command()
def menu() -> None:
    """Launch the guided interactive menu explicitly (same as running 'cape' with no arguments)."""
    from cape.cli.menu import run_main_menu
    run_main_menu()


def entry_point() -> None:
    """Package entry point for 'cape' command."""
    app()


if __name__ == "__main__":
    app()
