"""CLI scan command for CAPE."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from cape.cli.console import get_console
from cape.core.config import get_config
from cape.core.session import new_session
from cape.core.target_validator import TargetValidator
from cape.core.workspace import WorkspaceManager
from cape.db.session import init_db
from cape.scan.engine import ScanEngine
from cape.shared.enums import Severity

app = typer.Typer(help="Run security scans against authorized targets.")


@app.command()
def scan(
    profile: str = typer.Argument("quick", help="Scan profile: quick, recon, web, cms, network, smb, api, vuln, full"),
    target: str = typer.Argument(..., help="Target hostname, IP, CIDR, or URL"),
    resume: bool = typer.Option(False, "--resume", help="Resume from last checkpoint"),
    timeout: Optional[int] = typer.Option(None, "--timeout", "-t", help="Override scan timeout (seconds)"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", help="Override workspace directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would run without executing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show tool output live"),
) -> None:
    """Run a security scan against a target.

    Examples:

      cape scan quick 192.168.1.1

      cape scan web https://example.com --verbose

      cape scan full 10.0.0.0/24 --timeout 7200

      cape scan recon 192.168.1.1 --resume
    """
    console = get_console()
    cfg = get_config()
    init_db()

    # Validate target format
    validator = TargetValidator()
    try:
        target = validator.validate(target)
    except Exception as e:
        console.print(f"[red]Invalid target:[/red] {e}")
        raise typer.Exit(1)

    operator, scope_token = new_session(target)

    console.print(f"[bold]Starting {profile} scan against:[/bold] {target}")

    # Setup workspace
    workspace_root = output_dir or cfg.workspace_root
    workspace_manager = WorkspaceManager(workspace_root)

    if resume:
        checkpoint = workspace_manager.load_checkpoint(target)
        if checkpoint:
            console.print(f"[cyan]Resuming from checkpoint[/cyan]: completed {len(checkpoint.get('completed_plugins', []))} plugins")
        else:
            console.print("[yellow]No checkpoint found, starting fresh[/yellow]")

    # Run scan
    engine = ScanEngine(workspace_manager=workspace_manager)

    available_profiles = engine.list_profiles()
    if profile not in available_profiles:
        console.print(f"[red]Unknown profile:[/red] {profile}")
        console.print(f"Available: {', '.join(available_profiles)}")
        raise typer.Exit(1)

    def progress_callback(plugin_name: str, status: str) -> None:
        if verbose:
            console.print(f"  [dim]{plugin_name}[/dim]: {status}")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=not verbose,
    ) as progress:
        task = progress.add_task(f"Scanning {target} [{profile}]...", total=None)

        result = engine.run_scan(
            target=target,
            profile_name=profile,
            scope_token=scope_token,
            operator=operator,
            resume=resume,
            dry_run=dry_run,
            timeout_override=timeout,
            verbose=verbose,
            progress_callback=progress_callback,
        )

        progress.update(task, description=f"[green]Scan complete[/green]")

    if dry_run:
        console.print("[yellow]DRY RUN - no tools were executed[/yellow]")
        return

    # Display results
    if json_output:
        import json
        output = {
            "target": result.target,
            "profile": result.profile,
            "status": result.status.value,
            "finding_count": len(result.findings),
            "duration_seconds": result.duration_seconds,
            "findings": [f.to_dict() for f in result.findings],
        }
        print(json.dumps(output, indent=2, default=str))
        return

    # Rich table output
    from rich.table import Table

    console.print(f"\n[bold]Scan Results: {result.target}[/bold]")
    console.print(f"Status: {result.status.value} | Duration: {result.duration_seconds:.1f}s | Findings: {len(result.findings)}")

    if result.findings:
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Severity", width=10)
        table.add_column("Title", ratio=3)
        table.add_column("Tool", width=12)
        table.add_column("Host", width=16)
        table.add_column("Port", width=6)

        severity_color = {
            "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
            "LOW": "cyan", "INFO": "dim",
        }

        for f in sorted(result.findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity.value)):
            color = severity_color.get(f.severity.value, "white")
            table.add_row(
                f"[{color}]{f.severity.value}[/{color}]",
                f.title[:80],
                f.source_tool,
                f.host,
                str(f.port or "—"),
            )

        console.print(table)

    console.print(f"\n[dim]Run 'cape show {target}' to see attack opportunities[/dim]")
