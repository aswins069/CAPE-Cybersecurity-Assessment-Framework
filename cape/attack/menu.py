"""Interactive attack menu for CAPE.

Built with Rich for display and prompt_toolkit for input.
Menu is dynamically constructed from active opportunities.
"""
from __future__ import annotations

import logging
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cape.attack.models import AttackSession
from cape.show.models import Opportunity
from cape.shared.enums import Severity

logger = logging.getLogger(__name__)

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


class MenuBuilder:
    """Builds and renders the interactive attack menu.

    Dynamically constructs menu entries from available opportunities,
    filtering to only show modules that have matching opportunities.
    """

    def render(
        self,
        target: str,
        opportunities: list[Opportunity],
        session: AttackSession,
    ) -> None:
        """Render the attack menu to the console.

        Args:
            target: Target being assessed.
            opportunities: Scored opportunities from show engine.
            session: Active attack session.
        """
        console.print()

        # Header panel
        header_text = Text()
        header_text.append(f"ATTACK SESSION: {target}\n", style="bold white")
        header_text.append(
            f"Opportunities: {len(opportunities)} found  │  "
            f"Steps Completed: {len(session.steps_completed)}  │  "
            f"State: {session.state.value}",
            style="dim",
        )
        console.print(Panel(header_text, border_style="blue", expand=True))

        if not opportunities:
            console.print("[yellow]No opportunities identified. Run 'scan' first.[/yellow]")
            return

        # Opportunities table
        table = Table(
            show_header=True,
            header_style="bold blue",
            border_style="dim",
            expand=True,
        )
        table.add_column("#", style="bold", width=4)
        table.add_column("Module / Opportunity", ratio=3)
        table.add_column("Domain", width=10)
        table.add_column("Score", width=8)
        table.add_column("Severity", width=10)
        table.add_column("MITRE", width=12)

        for idx, opp in enumerate(opportunities, 1):
            color = SEVERITY_COLORS.get(opp.severity, "white")
            score_text = f"{opp.score:.1f}"

            table.add_row(
                f"[bold]{idx}[/bold]",
                f"[{color}]{opp.name}[/{color}]",
                opp.domain.value,
                f"[{color}]{score_text}[/{color}]",
                f"[{color}]{opp.severity.value}[/{color}]",
                opp.mitre_technique or "—",
            )

        console.print(table)

        # Action bar
        actions_text = (
            "  [bold][a][/bold] Run all  "
            "[bold][s][/bold] Step-through  "
            "[bold][i][/bold] Inspect opportunity  "
            "[bold][r][/bold] Generate report  "
            "[bold][q][/bold] Quit"
        )
        console.print(Panel(actions_text, border_style="dim", expand=True))

    def prompt_selection(self, opportunities: list[Opportunity]) -> str:
        """Prompt operator for menu selection via an arrow-key menu.

        Builds one arrow-key list combining every opportunity (by index)
        with the action-bar commands (run all / step-through / inspect /
        report / quit), so the operator never has to type a number or
        letter - just move the cursor and press Enter. Returns the same
        string vocabulary the rest of AttackEngine already expects
        ("1".."N", "a", "s", "i", "r", "q"), so no caller changes.
        """
        from cape.cli.tui import BACK, QUIT, MenuItem, arrow_menu

        items = [
            MenuItem(f"{idx}. {opp.name}", str(idx))
            for idx, opp in enumerate(opportunities, 1)
        ]
        items.append(MenuItem("Run all", "a"))
        items.append(MenuItem("Step-through", "s"))
        if opportunities:
            items.append(MenuItem("Inspect an opportunity", "i"))
        items.append(MenuItem("Generate report", "r"))

        try:
            choice = arrow_menu("Attack action", items, breadcrumb="Attack session", allow_back=False)
            if choice is QUIT or choice is BACK or choice is None:
                return "q"
            return str(choice)
        except Exception:
            # Fall back to the plain typed prompt if a real TTY/prompt_toolkit
            # app isn't available (e.g. piped input, some CI environments).
            try:
                from prompt_toolkit import prompt as pt_prompt
                return pt_prompt("Select [1-N/a/s/i/r/q]: ").strip().lower()
            except (ImportError, KeyboardInterrupt):
                return input("Select [1-N/a/s/i/r/q]: ").strip().lower()

    def confirm_execution(self, module_name: str) -> bool:
        """Ask operator to confirm module execution.

        Args:
            module_name: Name of module to execute.

        Returns:
            True if confirmed.
        """
        console.print(
            f"\n[yellow]About to execute module:[/yellow] [bold]{module_name}[/bold]"
        )
        try:
            response = input("Confirm? [y/N]: ").strip().lower()
            return response == "y"
        except (EOFError, KeyboardInterrupt):
            return False

    def show_opportunity_detail(self, opp: Opportunity) -> None:
        """Display detailed information about an opportunity.

        Args:
            opp: Opportunity to inspect.
        """
        color = SEVERITY_COLORS.get(opp.severity, "white")
        detail_text = Text()
        detail_text.append(f"{opp.name}\n", style=f"bold {color}")
        detail_text.append(f"Score: {opp.score:.1f} | Severity: {opp.severity.value} | Confidence: {opp.confidence:.0%}\n\n")
        detail_text.append(f"Domain: {opp.domain.value}\n")
        if opp.mitre_technique:
            detail_text.append(f"MITRE: {opp.mitre_technique}\n")
        detail_text.append(f"\nDescription:\n{opp.description}\n\n")
        detail_text.append(f"Explanation:\n{opp.explanation}\n\n")
        if opp.recommended_modules:
            detail_text.append(f"Modules: {', '.join(opp.recommended_modules)}\n")

        console.print(Panel(detail_text, title="Opportunity Detail", border_style="blue"))
        console.print(
            "[dim]This is a quick summary. For the full scoring trace - every rule "
            "condition checked, every scoring factor, and a consistency check against "
            "this score - press [e] for the full explanation, or Enter to continue.[/dim]"
        )

    def offer_full_explanation(self, opp: Opportunity, target: str) -> None:
        """Offer and, if accepted, render the full co-explain trace for an opportunity.

        This is the real explainability engine (TracingEvaluator), not the
        static one-line `explanation` string shown in show_opportunity_detail.
        It reconstructs every matched rule condition and every scoring factor,
        and independently recomputes the score as a consistency check against
        what was actually shown to the operator.

        Args:
            opp: The opportunity to explain in full.
            target: The target the opportunity belongs to.
        """
        choice = input("  Press [e] for full explanation, or Enter to continue: ").strip().lower()
        if choice != "e":
            return

        try:
            from cape.show.engine import ShowEngine
            from cape.show.explain.tracing_evaluator import TracingEvaluator
            from cape.show.explain.renderer import render_trace
            from cape.show.knowledge.loader import KnowledgeBaseLoader

            if not opp.rule_id:
                console.print(
                    "[yellow]This opportunity has no rule_id on record (it may predate "
                    "the explainability engine). Re-run 'cape show' to regenerate it before "
                    "it can be explained.[/yellow]"
                )
                return

            kb_loader = KnowledgeBaseLoader()
            rules_by_id = {r.id: r for r in kb_loader.load_opportunity_rules()}
            patterns_by_id = {p.id: p for p in kb_loader.load_attack_patterns()}

            rule = rules_by_id.get(opp.rule_id)
            if rule is None:
                console.print(
                    f"[yellow]Could not find the originating rule '{opp.rule_id}' in the "
                    f"knowledge base - it may have been removed or renamed.[/yellow]"
                )
                return

            engine = ShowEngine()
            findings = engine.load_findings_from_db(target)
            relevant_findings = [f for f in findings if f.id in set(opp.supporting_findings)] or findings

            pattern = patterns_by_id.get(opp.attack_pattern_id)
            trace = TracingEvaluator().trace_rule(
                opportunity=opp, rule=rule, findings=relevant_findings, attack_pattern=pattern,
            )
            render_trace(trace, console)
        except Exception as e:
            logger.error(f"Failed to build full explanation: {e}")
            console.print(f"[red]Could not generate the full explanation: {e}[/red]")

    def prompt_operator_input(self, step_name: str, required_inputs: list[str]) -> dict[str, str]:
        """Prompt operator for step-specific inputs.

        Args:
            step_name: Name of step requiring input.
            required_inputs: List of required input field names.

        Returns:
            Dict of field_name → value.
        """
        console.print(f"\n[yellow]Operator input required for:[/yellow] [bold]{step_name}[/bold]")
        result: dict[str, str] = {}
        for field in required_inputs:
            try:
                value = input(f"  {field}: ").strip()
                result[field] = value
            except (EOFError, KeyboardInterrupt):
                result[field] = ""
        return result

    def show_step_result(self, step_name: str, success: bool, output: str) -> None:
        """Display the result of a step execution.

        Args:
            step_name: Name of completed step.
            success: Whether step succeeded.
            output: Tool output to display.
        """
        status = "[green]✓ PASSED[/green]" if success else "[red]✗ FAILED[/red]"
        console.print(f"\n{status} {step_name}")
        if output:
            console.print(
                Panel(
                    output[:2000] + ("..." if len(output) > 2000 else ""),
                    title="Output",
                    border_style="dim",
                )
            )
