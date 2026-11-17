"""CLI explain command — CAPE Pillar A: why did this opportunity get its score?"""
from __future__ import annotations

import json
import logging
from typing import Optional
from uuid import UUID

import typer

from cape.cli.console import get_console
from cape.db.session import init_db

logger = logging.getLogger(__name__)

app = typer.Typer(help="Explain exactly why an opportunity received its score.")


@app.command()
def explain(
    target: str = typer.Argument(..., help="Target whose opportunities should be explained"),
    opportunity_id: Optional[str] = typer.Option(
        None, "--opportunity-id", help="Explain a single opportunity by UUID"
    ),
    all_opportunities: bool = typer.Option(
        False, "--all", help="Explain every opportunity recorded for the target"
    ),
    min_score: float = typer.Option(
        0.0, "--min-score", help="Only explain opportunities at or above this score"
    ),
    output_format: str = typer.Option(
        "rich", "--format", help="Output format: rich or json"
    ),
    deep: bool = typer.Option(
        False, "--deep", help="Include raw tool output snippet / file path"
    ),
    ai: bool = typer.Option(
        False, "--ai", help="Add an AI-narrated plain-language summary (explain/remediation only)"
    ),
    redact_target: bool = typer.Option(
        False, "--redact-target", help="With --ai, replace the target identifier before it's sent to the model"
    ),
) -> None:
    """Explain exactly why an opportunity scored the way it did.

    Reconstructs which rule conditions matched, on which evidence, and
    every factor in the scoring formula with its provenance. Always
    recomputes the score as an independent sanity check against what was
    actually shown to the operator - if they disagree, says so.

    Examples:

      cape explain 192.168.1.1 --all

      cape explain 192.168.1.1 --opportunity-id 3fa85f64-... --deep

      cape explain 192.168.1.1 --all --format json

      cape explain 192.168.1.1 --all --ai --redact-target
    """
    console = get_console()
    init_db()

    if output_format not in ("rich", "json"):
        console.print(f"[red]Invalid --format '{output_format}'. Use 'rich' or 'json'.[/red]")
        raise typer.Exit(1)

    if ai and output_format == "json":
        console.print("[yellow]--ai is ignored with --format json; use --format rich to see AI narration.[/yellow]")

    if not opportunity_id and not all_opportunities:
        console.print("[yellow]Specify --opportunity-id <uuid> or --all.[/yellow]")
        raise typer.Exit(1)

    opportunities = _load_opportunities(target, opportunity_id, min_score)
    if not opportunities:
        console.print(f"[yellow]No opportunities found for target: {target}[/yellow]")
        console.print("[dim]Run 'cape show <target>' first to generate opportunities.[/dim]")
        raise typer.Exit(0)

    findings = _load_findings(target)
    if not findings:
        console.print(f"[yellow]No findings found for target: {target}[/yellow]")
        raise typer.Exit(0)

    from cape.show.explain.tracing_evaluator import TracingEvaluator
    from cape.show.explain.renderer import render_trace, render_traces_json
    from cape.show.knowledge.loader import KnowledgeBaseLoader

    kb_loader = KnowledgeBaseLoader()
    rules_by_id = {r.id: r for r in kb_loader.load_opportunity_rules()}
    patterns_by_id = {p.id: p for p in kb_loader.load_attack_patterns()}
    tracer = TracingEvaluator()

    traces = []
    for opp in opportunities:
        rule = rules_by_id.get(opp.rule_id)
        if rule is None:
            console.print(
                f"[yellow]Warning:[/yellow] could not find originating rule "
                f"'{opp.rule_id}' for opportunity '{opp.name}' — skipping. "
                f"This opportunity may predate CAPE's rule_id fix; re-run "
                f"'cape show {target}' to regenerate it."
            )
            continue

        pattern = patterns_by_id.get(opp.attack_pattern_id)
        relevant_findings = [f for f in findings if f.id in set(opp.supporting_findings)] or findings

        trace = tracer.trace_rule(
            opportunity=opp, rule=rule, findings=relevant_findings,
            attack_pattern=pattern, deep=deep,
        )
        traces.append(trace)

    if not traces:
        console.print("[yellow]No opportunities could be traced.[/yellow]")
        raise typer.Exit(0)

    if output_format == "json":
        print(render_traces_json(traces))
        return

    for trace in traces:
        render_trace(trace, console, deep=deep)
        if ai:
            _render_ai_narrative(trace, console, redact_target=redact_target)
        console.print()  # spacing between multiple traces


def _render_ai_narrative(trace, console, redact_target: bool) -> None:
    """Print an AI-narrated summary panel under the deterministic trace.

    Scoped to explain/remediation narration only — see
    cape.show.explain.ai_narrator for why attack content is out of scope.
    Streams the response for a live-typing effect; falls back to a single
    static print if streaming isn't available.
    """
    from rich.live import Live
    from rich.panel import Panel

    from cape.show.explain.ai_narrator import ai_narration_available, narrate_stream

    if not ai_narration_available():
        console.print(
            "\n[dim]AI narration skipped: no API key configured "
            "(set GOOGLE_AI_API_KEY or GEMINI_API_KEY).[/dim]"
        )
        return

    console.print()
    text = ""
    with Live(Panel("", title="AI Explanation", border_style="magenta"), console=console, refresh_per_second=8) as live:
        for chunk in narrate_stream(trace, redact_target=redact_target):
            text += chunk
            live.update(Panel(text, title="AI Explanation", border_style="magenta"))


def _load_opportunities(target: str, opportunity_id: Optional[str], min_score: float) -> list:
    """Load persisted Opportunity domain objects from the DB for a target."""
    from cape.db.session import db_session
    from cape.db.models import OpportunityModel
    from cape.show.models import Opportunity
    from cape.shared.enums import AttackDomain, Severity

    results = []
    try:
        with db_session() as session:
            query = session.query(OpportunityModel).filter(OpportunityModel.target == target)
            if opportunity_id:
                query = query.filter(OpportunityModel.id == opportunity_id)
            query = query.filter(OpportunityModel.score >= min_score)

            for om in query.all():
                results.append(Opportunity(
                    id=UUID(om.id),
                    target=om.target,
                    domain=AttackDomain(om.domain),
                    attack_pattern_id=om.attack_pattern_id,
                    rule_id=om.rule_id or "",
                    name=om.name,
                    description=om.description,
                    score=om.score,
                    confidence=om.confidence,
                    severity=Severity(om.severity),
                    supporting_findings=[UUID(f) for f in (om.supporting_findings or [])],
                    recommended_modules=om.recommended_modules or [],
                    mitre_technique=om.mitre_technique,
                    explanation=om.explanation,
                ))
    except Exception as e:
        logger.error(f"Failed to load opportunities from DB: {e}")

    return sorted(results, key=lambda o: o.score, reverse=True)


def _load_findings(target: str) -> list:
    """Load Finding domain objects for a target via ShowEngine's loader."""
    from cape.show.engine import ShowEngine
    engine = ShowEngine()
    return engine.load_findings_from_db(target)
