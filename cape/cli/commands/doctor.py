"""CLI doctor command - health check for dependencies."""
from __future__ import annotations

import typer
from rich.table import Table

from cape.cli.console import get_console
from cape.core.dependency_checker import DependencyChecker
from cape.shared.enums import CheckStatus

app = typer.Typer(help="Check system health and dependencies.")


@app.command()
def doctor(
    fix: bool = typer.Option(False, "--fix", help="Attempt auto-remediation where possible"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check all required tools, permissions, and configuration.

    Examples:

      cape doctor

      cape doctor --fix

      cape doctor --json
    """
    console = get_console()
    checker = DependencyChecker()

    console.print("[bold]Running health checks...[/bold]\n")
    results = checker.run_all_checks()

    if json_output:
        import json
        data = [
            {
                "name": r.name,
                "status": r.status.value,
                "version": r.version,
                "path": r.path,
                "message": r.message,
                "remediation": r.remediation,
            }
            for r in results
        ]
        print(json.dumps(data, indent=2))
        return

    status_icon = {
        CheckStatus.OK: "[green]✓[/green]",
        CheckStatus.WARN: "[yellow]⚠[/yellow]",
        CheckStatus.FAIL: "[red]✗[/red]",
        CheckStatus.SKIP: "[dim]−[/dim]",
    }

    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("Tool/Check", ratio=1)
    table.add_column("Status", width=8)
    table.add_column("Version", width=14)
    table.add_column("Path", ratio=1)
    table.add_column("Notes", ratio=1)

    fail_count = 0
    warn_count = 0

    for result in results:
        icon = status_icon.get(result.status, "?")
        if result.status == CheckStatus.FAIL:
            fail_count += 1
        elif result.status == CheckStatus.WARN:
            warn_count += 1

        table.add_row(
            result.name,
            f"{icon} {result.status.value}",
            result.version or "—",
            result.path or "—",
            result.message,
        )

    console.print(table)

    # Show remediations for failures
    failures = [r for r in results if r.status == CheckStatus.FAIL and r.remediation]
    if failures:
        console.print("\n[bold red]Remediation steps:[/bold red]")
        for r in failures:
            console.print(f"  [red]✗ {r.name}:[/red] {r.remediation}")

            if fix and r.remediation and r.remediation.startswith("sudo apt"):
                console.print(f"    [dim]Running: {r.remediation}[/dim]")
                import subprocess
                try:
                    subprocess.run(r.remediation.split(), check=False, timeout=60)
                except Exception as e:
                    console.print(f"    [red]Auto-fix failed: {e}[/red]")

    # Summary
    ok_count = len(results) - fail_count - warn_count
    console.print(
        f"\n[bold]Summary:[/bold] "
        f"[green]{ok_count} OK[/green]  "
        f"[yellow]{warn_count} warnings[/yellow]  "
        f"[red]{fail_count} failures[/red]"
    )

    if fail_count > 0:
        raise typer.Exit(1)
