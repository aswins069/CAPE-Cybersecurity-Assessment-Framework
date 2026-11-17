"""CLI report command - generate security assessment reports."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

from cape.cli.console import get_console
from cape.db.session import init_db

app = typer.Typer(help="Generate assessment reports.")


@app.command()
def report(
    target: str = typer.Argument(..., help="Target to report on"),
    fmt: str = typer.Option("json", "--format", "-f", help="Report format: json, html, pdf"),
    audience: str = typer.Option("full", "--audience", help="Report audience: ciso, auditor, engineer, full"),
    scan_id: Optional[str] = typer.Option(None, "--scan-id", help="Specific scan UUID"),
    session_id: Optional[str] = typer.Option(None, "--session-id", help="Specific session UUID"),
    client: Optional[str] = typer.Option(None, "--client", help="Scope report data to this CAPE client_id"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    open_after: bool = typer.Option(False, "--open", help="Open report after generation"),
    operator: str = typer.Option("", "--operator", help="Operator name for report metadata"),
) -> None:
    """Generate a security assessment report for a target.

    Examples:

      cape report 192.168.1.1

      cape report example.com --format html --open

      cape report 192.168.1.1 --format pdf --audience ciso

      cape report 192.168.1.1 --audience auditor --format html

      cape report 192.168.1.1 --scan-id <uuid> --format json
    """
    console = get_console()
    init_db()

    audience = audience.lower()
    if audience not in ("ciso", "auditor", "engineer", "full"):
        console.print(f"[red]Invalid --audience '{audience}'. Use ciso, auditor, engineer, or full.[/red]")
        raise typer.Exit(1)

    from cape.reports.assembler import ReportAssembler
    from cape.reports.generators.json_gen import JSONReportGenerator
    from cape.reports.generators.html_gen import HTMLReportGenerator
    from cape.reports.generators.pdf_gen import PDFReportGenerator
    from cape.core.config import get_config
    from cape.core.workspace import WorkspaceManager
    from cape.core.audit_logger import get_audit_logger

    cfg = get_config()
    audit = get_audit_logger()
    workspace_manager = WorkspaceManager(client_id=client)
    workspace = workspace_manager.get_workspace(target)

    # Determine output path
    ext_map = {"json": ".json", "html": ".html", "pdf": ".pdf"}
    ext = ext_map.get(fmt, ".json")

    if output is None:
        output = workspace.reports / f"report_{target.replace('/', '_')}_{audience}{ext}"
    output.parent.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]Assembling {audience} report data for:[/bold] {target}")

    # Assemble data from DB
    assembler = ReportAssembler()
    report_data = assembler.assemble(
        target=target,
        scan_id=scan_id,
        session_id=session_id,
        operator=operator,
        audience=audience,
        client_id=client,
    )

    if not report_data.findings:
        console.print("[yellow]No findings found. Run 'cape scan' first.[/yellow]")
        raise typer.Exit(0)

    console.print(
        f"  Findings: {report_data.scan_summary.total_findings} | "
        f"Opportunities: {len(report_data.opportunities)} | "
        f"Evidence: {len(report_data.evidence)}"
    )

    # Generate report
    generators = {
        "json": JSONReportGenerator(),
        "html": HTMLReportGenerator(),
        "pdf": PDFReportGenerator(),
    }

    generator = generators.get(fmt)
    if not generator:
        console.print(f"[red]Unknown format:[/red] {fmt}. Use: json, html, pdf")
        raise typer.Exit(1)

    console.print(f"Generating [bold]{fmt.upper()}[/bold] report...")

    try:
        result_path = generator.generate(report_data, output)
        console.print(f"[green]✓ Report generated:[/green] {result_path}")
    except Exception as e:
        console.print(f"[red]Report generation failed:[/red] {e}")
        raise typer.Exit(1)

    # Persist to DB
    try:
        from cape.db.session import db_session
        from cape.db.models import Report, Target
        from datetime import datetime

        with db_session() as s:
            target_obj = s.query(Target).filter_by(hostname_or_ip=target).first()
            if target_obj:
                rpt = Report(
                    target_id=target_obj.id,
                    session_id=session_id,
                    format=fmt,
                    created_at=datetime.utcnow(),
                    file_path=str(result_path),
                    audience=audience,
                    client_id=client,
                )
                s.add(rpt)
    except Exception as e:
        console.print(f"[dim]Note: Could not persist report record: {e}[/dim]")

    audit.log_report_generated(target, operator or "unknown", fmt, str(result_path))

    # Open report if requested
    if open_after:
        try:
            if sys.platform == "linux":
                subprocess.Popen(["xdg-open", str(result_path)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(result_path)])
            elif sys.platform == "win32":
                subprocess.Popen(["start", str(result_path)], shell=True)
        except Exception:
            console.print("[dim]Could not auto-open report[/dim]")
