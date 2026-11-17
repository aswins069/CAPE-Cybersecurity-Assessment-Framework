"""CLI audit command — CAPE Pillar D: inspect and verify the tamper-evident audit chain."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Optional

import typer
from rich.table import Table

from cape.cli.console import get_console
from cape.core.audit_chain import get_audit_logger

logger = logging.getLogger(__name__)

app = typer.Typer(help="Inspect and verify the tamper-evident audit chain.")


@app.command()
def audit(
    verify: bool = typer.Option(False, "--verify", help="Verify chain integrity"),
    repair: bool = typer.Option(False, "--repair", help="Archive a broken audit log and start a fresh chain"),
    tail: Optional[int] = typer.Option(None, "--tail", help="Show the last N entries"),
    target: Optional[str] = typer.Option(None, "--target", help="Filter by target"),
    since: Optional[str] = typer.Option(None, "--since", help="Filter by date (YYYY-MM-DD or ISO 8601)"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
) -> None:
    """Inspect or verify the hash-chained audit log.

    Examples:

      cape audit --verify

      cape audit --tail 20

      cape audit --target 192.168.1.1 --since 2026-06-01

      cape audit --verify --json
    """
    console = get_console()
    audit_logger = get_audit_logger()

    if repair:
        archive = audit_logger.repair()
        if archive is None:
            console.print("[yellow]Nothing to repair - audit log is empty or missing.[/yellow]")
        else:
            console.print(f"[green]Old log archived to {archive}; new audit chain started.[/green]")
        return

    if verify:
        result = audit_logger.verify_chain()
        if json_output:
            print(result.model_dump_json(indent=2))
            return

        if result.valid:
            console.print(f"[bold green]{result.message}[/bold green]")
        else:
            console.print(f"[bold red]✗ {result.message}[/bold red]")
            if result.corrupt_lines:
                raise typer.Exit(1)
            if result.first_broken_sequence is not None:
                console.print(
                    f"[red]This entry's prev_hash does not match entry "
                    f"#{result.first_broken_sequence - 1}.[/red]"
                )
                console.print(
                    f"[red]All entries after #{result.first_broken_sequence} "
                    f"cannot be trusted.[/red]"
                )
            raise typer.Exit(1)
        return

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            console.print(f"[red]Invalid --since date: {since}. Use YYYY-MM-DD or ISO 8601.[/red]")
            raise typer.Exit(1)

    entries = audit_logger.filter_entries(target=target, since=since_dt)

    if tail:
        entries = entries[-tail:]

    if not entries:
        console.print("[yellow]No matching audit entries.[/yellow]")
        raise typer.Exit(0)

    if json_output:
        print(json.dumps([e.model_dump() for e in entries], indent=2))
        return

    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("#", width=6)
    table.add_column("Timestamp", ratio=1)
    table.add_column("Event", width=18)
    table.add_column("Target", ratio=1)
    table.add_column("Operator", ratio=1)
    table.add_column("Detail", ratio=2)

    for entry in entries:
        table.add_row(
            str(entry.sequence), entry.timestamp, entry.event_type,
            entry.target, entry.operator, entry.detail,
        )

    console.print(table)
    console.print(f"\n[dim]{len(entries)} entries shown. Run 'cape audit --verify' to check chain integrity.[/dim]")
