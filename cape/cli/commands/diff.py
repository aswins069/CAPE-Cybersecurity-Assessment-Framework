"""CLI diff command — CAPE Pillar C: compare scans and detect drift."""
from __future__ import annotations

import json
import logging
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cape.cli.console import get_console
from cape.db.session import init_db
from cape.show.drift import DriftReport, FindingStatus, ScanDiffer

logger = logging.getLogger(__name__)

app = typer.Typer(help="Compare scans of a target to detect drift over time.")

_SEVERITY_COLORS = {
    "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}


@app.command()
def diff(
    target: str = typer.Argument(..., help="Target to compare scans for"),
    scan_from: Optional[str] = typer.Option(None, "--from", help="Earlier scan UUID (baseline)"),
    scan_to: Optional[str] = typer.Option(None, "--to", help="Later scan UUID (comparison point)"),
    last: Optional[int] = typer.Option(None, "--last", help="Compare the last N scans pairwise"),
    output_format: str = typer.Option("table", "--format", help="Output format: table, summary, or json"),
    json_output: bool = typer.Option(False, "--json", help="Shortcut for --format json"),
) -> None:
    """Compare scans and show what changed: new, fixed, regressed, persistent findings.

    Examples:

      cape diff 192.168.1.100

      cape diff 192.168.1.100 --from <scan_id> --to <scan_id>

      cape diff 192.168.1.100 --last 3

      cape diff 192.168.1.100 --json
    """
    console = get_console()
    init_db()

    fmt = "json" if json_output else output_format
    if fmt not in ("table", "summary", "json"):
        console.print(f"[red]Invalid --format '{fmt}'. Use table, summary, or json.[/red]")
        raise typer.Exit(1)

    differ = ScanDiffer()

    try:
        if last:
            reports = differ.compare_last_n(target, last)
        elif scan_from and scan_to:
            reports = [differ.compare(target, scan_from, scan_to)]
        else:
            reports = _compare_most_recent_pair(target, differ)
    except Exception as e:
        logger.error(f"Drift comparison failed: {e}")
        console.print(f"[red]Failed to compute drift: {e}[/red]")
        raise typer.Exit(1)

    if not reports:
        console.print(
            f"[yellow]Not enough scan history for {target} to compute drift.[/yellow]"
        )
        console.print("[dim]Need at least two scans of the same target.[/dim]")
        raise typer.Exit(0)

    if fmt == "json":
        print(json.dumps([r.model_dump(mode="json") for r in reports], indent=2, default=str))
        return

    for report in reports:
        _render_report(report, console, summary_only=(fmt == "summary"))
        console.print()


def _compare_most_recent_pair(target: str, differ: ScanDiffer) -> list[DriftReport]:
    """Fall back to comparing the two most recent scans when no flags given."""
    reports = differ.compare_last_n(target, 2)
    return reports


def _render_report(report: DriftReport, console, summary_only: bool) -> None:
    """Render one DriftReport to the console."""
    trend_arrow = "↑" if report.trend_score > 0 else ("↓" if report.trend_score < 0 else "→")
    trend_label = "improving" if report.trend_score > 0 else (
        "regressing" if report.trend_score < 0 else "unchanged"
    )
    trend_style = "green" if report.trend_score > 0 else (
        "red" if report.trend_score < 0 else "dim"
    )

    header = Text()
    header.append(f"Target: {report.target}\n", style="bold")
    header.append(f"From scan: {report.scan_from}\n", style="dim")
    header.append(f"To scan:   {report.scan_to}\n", style="dim")
    header.append(f"Trend: {trend_arrow} ", style=trend_style)
    header.append(f"{trend_label}", style=trend_style)

    console.print(Panel(header, title="Drift Report", border_style="blue"))

    console.print(
        f"[bold]NEW:[/bold] {report.new_count}  |  "
        f"[bold]FIXED:[/bold] {report.fixed_count}  |  "
        f"[bold]REGRESSED:[/bold] {report.regressed_count}  |  "
        f"[bold]PERSISTENT:[/bold] {report.persistent_count}  |  "
        f"[bold]IMPROVED:[/bold] {report.improved_count}"
    )

    if summary_only:
        console.print(f"\n[{trend_style}]Trend score: {report.trend_score:+.2f} ({trend_label})[/{trend_style}]")
        return

    if not report.entries:
        console.print("[dim]No drift entries.[/dim]")
        return

    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("Status", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Title", ratio=2)
    table.add_column("Host", ratio=1)
    table.add_column("Port", width=6)
    table.add_column("Tool", width=10)
    table.add_column("Days Open", width=10)

    for entry in report.entries:
        sev = entry.severity_after or entry.severity_before or "INFO"
        color = _SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            f"[{color}]{entry.status.value}[/{color}]",
            sev,
            entry.finding_title,
            entry.host,
            str(entry.port) if entry.port else "—",
            entry.source_tool,
            str(entry.days_open) if entry.days_open is not None else "—",
        )

    console.print(table)
    console.print(
        f"\n[{trend_style}]Trend score: {report.trend_score:+.2f} ({trend_label})[/{trend_style}]"
    )
