"""CLI demo command - run the full CAPE pipeline on bundled sample data.

No external security tools are required. See cape/demo/runner.py.
"""
from __future__ import annotations

import typer
from rich.panel import Panel
from rich.table import Table

from cape.cli.console import get_console

app = typer.Typer(help="Run the full CAPE pipeline on bundled demo data (no tools required).")

_SEVERITY_COLOR = {
    "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}


@app.command()
def demo(
    label: str = typer.Option("lab-target.demo", "--label", help="Display name for the demo target"),
) -> None:
    """Run SCAN -> SHOW -> EXPLAIN -> COMPLIANCE -> AUDIT using sample scanner output.

    Every record produced is explicitly tagged as demo data and stored
    under a target name prefixed 'demo-' so it can never be confused
    with a real assessment.

    Examples:

      cape demo
    """
    console = get_console()
    console.print(Panel.fit(
        "[bold cyan]CAPE DEMONSTRATION MODE[/bold cyan]\n"
        "Using bundled sample nmap/nikto/whatweb/wpscan output.\n"
        "[dim]No external tools executed. All data is labeled DEMO.[/dim]",
        border_style="cyan",
    ))

    from cape.demo.runner import run_demo
    result = run_demo(target_label=label)

    counts = result.severity_counts
    table = Table(title=f"Demo Assessment — {result.target}", show_header=True, header_style="bold blue")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        color = _SEVERITY_COLOR[sev]
        table.add_row(f"[{color}]{sev}[/{color}]", str(counts[sev]))
    console.print(table)

    console.print(
        f"\n[bold]Findings:[/bold] {len(result.findings)}   "
        f"[bold]Opportunities:[/bold] {len(result.opportunities)}"
    )
    console.print(f"[bold]Scan ID:[/bold] {result.scan_id}")
    console.print(f"[bold]Workspace:[/bold] {result.workspace_root}")
    console.print(
        f"\nRun [cyan]cape show \"{result.target}\"[/cyan] to see opportunities, "
        f"[cyan]cape explain \"{result.target}\"[/cyan] for the explainability trace, "
        f"or [cyan]cape report \"{result.target}\"[/cyan] to generate a report."
    )
