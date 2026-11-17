"""CLI show command - display attack opportunities."""
from __future__ import annotations

from typing import Optional
from uuid import UUID

import typer
from rich.table import Table

from cape.cli.console import get_console
from cape.db.session import init_db

app = typer.Typer(help="Show identified attack opportunities for a target.")


@app.command()
def show(
    target: str = typer.Argument(..., help="Target to analyze"),
    scan_id: Optional[str] = typer.Option(None, "--scan-id", help="Specific scan UUID"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by domain: WEB, SMB, NETWORK, etc."),
    min_score: float = typer.Option(0.0, "--min-score", help="Minimum opportunity score (0-10)"),
    compliance: bool = typer.Option(False, "--compliance", help="Show compliance control annotations per finding"),
    remediation: bool = typer.Option(False, "--remediation", help="Show a priority + top-countermeasure overview per opportunity"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Analyze scan findings and show attack opportunities.

    Examples:

      cape show 192.168.1.1

      cape show example.com --domain WEB --min-score 5.0

      cape show 192.168.1.1 --compliance

      cape show 192.168.1.1 --remediation

      cape show 192.168.1.1 --json
    """
    console = get_console()
    init_db()

    from cape.show.engine import ShowEngine
    engine = ShowEngine()

    findings = engine.load_findings_from_db(target, scan_id)
    if not findings:
        console.print(f"[yellow]No findings found for target: {target}[/yellow]")
        console.print("[dim]Run 'cape scan' first to populate findings.[/dim]")
        raise typer.Exit(0)

    opportunities = engine.analyze(
        target=target,
        findings=findings,
        min_score=min_score,
        domain_filter=domain,
    )

    if compliance:
        _show_compliance_table(findings, console, json_output)
        if json_output:
            return
        console.print()  # spacing before opportunities section

    remediation_plans = {}
    if remediation and opportunities:
        from cape.show.remediation.mapper import RemediationMapper
        from cape.show.knowledge.loader import KnowledgeBaseLoader

        rmapper = RemediationMapper()
        patterns_by_id = {p.id: p for p in KnowledgeBaseLoader().load_attack_patterns()}
        for opp in opportunities:
            supporting = [f for f in findings if f.id in set(opp.supporting_findings)]
            remediation_plans[opp.id] = rmapper.build_plan(
                opportunity=opp,
                attack_pattern=patterns_by_id.get(opp.attack_pattern_id),
                findings=supporting,
            )

    if json_output:
        import json
        payload = []
        for o in opportunities:
            d = o.to_dict()
            if o.id in remediation_plans:
                d["remediation"] = remediation_plans[o.id].to_dict()
            payload.append(d)
        print(json.dumps(payload, indent=2, default=str))
        return

    if not opportunities:
        console.print("[yellow]No opportunities identified above the score threshold.[/yellow]")
        return

    console.print(f"\n[bold]Attack Opportunities: {target}[/bold] ({len(opportunities)} found)\n")

    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("#", width=4)
    table.add_column("Name", ratio=2)
    table.add_column("Domain", width=10)
    table.add_column("Score", width=7)
    table.add_column("Severity", width=10)
    table.add_column("MITRE", width=12)
    table.add_column("Modules", ratio=1)

    severity_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}

    for idx, opp in enumerate(opportunities, 1):
        color = severity_color.get(opp.severity.value, "white")
        table.add_row(
            str(idx),
            f"[{color}]{opp.name}[/{color}]",
            opp.domain.value,
            f"[{color}]{opp.score:.1f}[/{color}]",
            f"[{color}]{opp.severity.value}[/{color}]",
            opp.mitre_technique or "—",
            ", ".join(opp.recommended_modules[:2]),
        )

    console.print(table)

    if remediation:
        console.print()
        _show_remediation_overview(opportunities, remediation_plans, console)

    console.print(f"\n[dim]Run 'cape plan {target}' to generate an assessment plan[/dim]")


def _show_remediation_overview(opportunities, remediation_plans: dict, console) -> None:
    """Render a compact priority + top-countermeasure table per opportunity.

    This is an overview only - run 'cape explain <target> --all' for the
    full countermeasure breakdown, verification steps, and MITRE mappings.
    """
    console.print(f"[bold]Remediation Overview[/bold] ({len(opportunities)} opportunities)\n")

    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("Opportunity", ratio=2)
    table.add_column("Priority", width=16)
    table.add_column("Top countermeasure (do this first)", ratio=3)

    priority_color = {
        "Fix immediately": "bold red", "Fix this sprint": "red",
        "Schedule": "yellow", "Track": "dim",
    }

    for opp in opportunities:
        plan = remediation_plans.get(opp.id)
        if plan is None:
            continue
        color = priority_color.get(plan.priority, "white")
        top = plan.countermeasures[0].title if plan.countermeasures else (plan.residual_risk_note or "—")
        table.add_row(opp.name, f"[{color}]{plan.priority}[/{color}]", top)

    console.print(table)
    console.print("[dim]Run 'cape explain <target> --all' for full countermeasures, verification steps, and MITRE mappings.[/dim]")


def _show_compliance_table(findings, console, json_output: bool) -> None:
    """Render (or JSON-print) per-finding compliance control annotations."""
    from cape.show.compliance.mapper import ComplianceMapper

    mapper = ComplianceMapper()
    annotations = mapper.annotate_all(findings)

    if json_output:
        import json
        payload = [
            {
                "finding_id": str(f.id), "title": f.title, "severity": f.severity.value,
                **annotations[f.id].model_dump(),
            }
            for f in findings
        ]
        print(json.dumps(payload, indent=2))
        return

    console.print(f"[bold]Compliance Control Mapping[/bold] ({len(findings)} findings)\n")

    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("Severity", width=10)
    table.add_column("Finding", ratio=2)
    table.add_column("PCI-DSS", ratio=1)
    table.add_column("SOC2", ratio=1)
    table.add_column("ISO27001", ratio=1)
    table.add_column("NIST CSF", ratio=1)
    table.add_column("CIS", ratio=1)

    severity_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}

    for f in findings:
        annotation = annotations[f.id]
        color = severity_color.get(f.severity.value, "white")
        table.add_row(
            f"[{color}]{f.severity.value}[/{color}]",
            f.title,
            ", ".join(annotation.pci_dss) or "—",
            ", ".join(annotation.soc2) or "—",
            ", ".join(annotation.iso27001) or "—",
            ", ".join(annotation.nist_csf) or "—",
            ", ".join(annotation.cis_controls) or "—",
        )

    console.print(table)
