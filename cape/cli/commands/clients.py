"""CLI clients command — CAPE multi-tenant client isolation."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import typer
from rich.table import Table

from cape.cli.console import get_console
from cape.core.workspace import validate_client_id
from cape.db.session import init_db

logger = logging.getLogger(__name__)

app = typer.Typer(help="Manage multi-tenant client isolation.")


@app.command("list")
def list_clients() -> None:
    """List all registered clients with their data counts.

    Example:

      cape clients list
    """
    console = get_console()
    init_db()

    from cape.db.session import db_session
    from cape.db.models import Client, FindingModel, OpportunityModel, Scan, Target

    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("Client ID", ratio=1)
    table.add_column("Targets", width=10)
    table.add_column("Scans", width=10)
    table.add_column("Findings", width=10)
    table.add_column("Last Active", ratio=1)

    with db_session() as session:
        clients = session.query(Client).order_by(Client.created_at.desc()).all()

        if not clients:
            console.print("[yellow]No clients registered yet.[/yellow]")
            console.print("[dim]Run 'cape clients create <client_id>' to register one.[/dim]")
            return

        for client in clients:
            target_count = session.query(Target).filter(Target.client_id == client.id).count()
            scan_count = session.query(Scan).filter(Scan.client_id == client.id).count()
            finding_count = session.query(FindingModel).filter(FindingModel.client_id == client.id).count()

            last_target = (
                session.query(Target)
                .filter(Target.client_id == client.id)
                .order_by(Target.last_scanned_at.desc())
                .first()
            )
            last_active = (
                last_target.last_scanned_at.isoformat()
                if last_target and last_target.last_scanned_at else "—"
            )

            table.add_row(client.id, str(target_count), str(scan_count), str(finding_count), last_active)

    console.print(table)


@app.command("create")
def create_client(
    client_id: str = typer.Argument(..., help="Unique client slug (alphanumeric + hyphens)"),
    name: str = typer.Option("", "--name", help="Client display name, e.g. 'Acme Corp'"),
    contact: str = typer.Option("", "--contact", help="Primary contact, e.g. an email address"),
) -> None:
    """Register a new client for multi-tenant isolation.

    Example:

      cape clients create acme-corp --name "Acme Corp" --contact "jane@acme.com"
    """
    console = get_console()
    init_db()

    try:
        validate_client_id(client_id)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    from cape.db.session import db_session
    from cape.db.models import Client

    with db_session() as session:
        existing = session.get(Client, client_id)
        if existing:
            console.print(f"[yellow]Client '{client_id}' already exists.[/yellow]")
            raise typer.Exit(1)

        session.add(Client(
            id=client_id, name=name, contact=contact, created_at=datetime.utcnow(), notes="",
        ))

    console.print(f"[green]✓ Client '{client_id}' created.[/green]")


@app.command("use")
def use_client(
    client_id: str = typer.Argument(..., help="Client ID to operate as for this session"),
) -> None:
    """Set CAPE_CLIENT_ID for the current shell session.

    Since a subprocess cannot export environment variables into its
    parent shell, this prints the export command for the operator to
    eval, and confirms the client exists.

    Example:

      eval "$(cape clients use acme-corp)"
    """
    console = get_console()
    init_db()

    try:
        validate_client_id(client_id)
    except ValueError as e:
        console.print(f"[red]{e}[/red]", style="red")
        raise typer.Exit(1)

    from cape.db.session import db_session
    from cape.db.models import Client

    with db_session() as session:
        client = session.get(Client, client_id)
        if not client:
            console.print(f"[red]No such client: '{client_id}'. Run 'cape clients create {client_id}' first.[/red]")
            raise typer.Exit(1)

    # Print the export statement to stdout (eval-able); status goes to stderr via console.
    console.print(
        f"[dim]# Run: eval \"$(cape clients use {client_id})\"[/dim]", style="dim",
    )
    typer.echo(f"export CAPE_CLIENT_ID={client_id}")


@app.command("report")
def client_report(
    client_id: str = typer.Argument(..., help="Client ID to generate an aggregated report for"),
    audience: str = typer.Option("full", "--audience", help="ciso, auditor, engineer, or full"),
    output_format: str = typer.Option("html", "--format", help="json, html, or pdf"),
) -> None:
    """Generate an aggregated report across all of a client's targets.

    Example:

      cape clients report acme-corp --audience ciso --format pdf
    """
    console = get_console()
    init_db()

    try:
        validate_client_id(client_id)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    from cape.db.session import db_session
    from cape.db.models import Client, Target

    with db_session() as session:
        client = session.get(Client, client_id)
        if not client:
            console.print(f"[red]No such client: '{client_id}'.[/red]")
            raise typer.Exit(1)

        targets = [
            t.hostname_or_ip for t in
            session.query(Target).filter(Target.client_id == client_id).all()
        ]

    if not targets:
        console.print(f"[yellow]Client '{client_id}' has no targets yet.[/yellow]")
        raise typer.Exit(0)

    console.print(f"[bold]Aggregated report for client '{client_id}'[/bold] ({len(targets)} target(s))")

    from cape.reports.assembler import ReportAssembler
    from cape.reports.generators.json_gen import JSONReportGenerator
    from cape.reports.generators.html_gen import HTMLReportGenerator
    from cape.reports.generators.pdf_gen import PDFReportGenerator
    from cape.core.workspace import WorkspaceManager

    assembler = ReportAssembler()
    generators = {
        "json": JSONReportGenerator(), "html": HTMLReportGenerator(), "pdf": PDFReportGenerator(),
    }
    generator = generators.get(output_format)
    if not generator:
        console.print(f"[red]Unknown format: {output_format}. Use json, html, or pdf.[/red]")
        raise typer.Exit(1)

    ext_map = {"json": ".json", "html": ".html", "pdf": ".pdf"}
    workspace_manager = WorkspaceManager(client_id=client_id)

    for target in targets:
        console.print(f"  • {target}")
        try:
            report_data = assembler.assemble(
                target=target, audience=audience, client_id=client_id,
            )
            workspace = workspace_manager.get_workspace(target)
            out_path = workspace.reports / f"report_{target.replace('/', '_')}_{audience}{ext_map[output_format]}"
            result_path = generator.generate(report_data, out_path)
            console.print(f"    [green]→ {result_path}[/green]")
        except Exception as e:
            logger.error(f"Failed to generate report for {target}: {e}")
            console.print(f"    [red]✗ failed: {e}[/red]")


@app.command("audit")
def client_audit(
    client_id: str = typer.Argument(..., help="Client ID to filter the audit log by"),
    since: Optional[str] = typer.Option(None, "--since", help="Filter by date (YYYY-MM-DD or ISO 8601)"),
) -> None:
    """Show the audit log filtered to a single client's activity.

    Example:

      cape clients audit acme-corp --since 2026-06-01
    """
    console = get_console()
    init_db()

    try:
        validate_client_id(client_id)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            console.print(f"[red]Invalid --since date: {since}[/red]")
            raise typer.Exit(1)

    from cape.db.session import db_session
    from cape.db.models import AuditChainEntry

    with db_session() as session:
        query = session.query(AuditChainEntry).filter(AuditChainEntry.client_id == client_id)
        if since_dt:
            query = query.filter(AuditChainEntry.timestamp >= since_dt.isoformat())
        entries = query.order_by(AuditChainEntry.sequence.asc()).all()

    if not entries:
        console.print(f"[yellow]No audit entries found for client '{client_id}'.[/yellow]")
        raise typer.Exit(0)

    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("#", width=6)
    table.add_column("Timestamp", ratio=1)
    table.add_column("Event", width=18)
    table.add_column("Target", ratio=1)
    table.add_column("Detail", ratio=2)

    for entry in entries:
        table.add_row(str(entry.sequence), entry.timestamp, entry.event_type, entry.target, entry.detail)

    console.print(table)
