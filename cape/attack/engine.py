"""Attack engine - orchestrates interactive assessment sessions."""
from __future__ import annotations

import logging
import uuid
from typing import Optional
from uuid import UUID

from cape.attack.menu import MenuBuilder
from cape.attack.models import AttackSession, Evidence
from cape.attack.session import SessionManager
from cape.plan.models import AttackPlan
from cape.show.models import Opportunity
from cape.shared.enums import SessionState
from cape.shared.finding import Finding

logger = logging.getLogger(__name__)


class AttackEngine:
    """Orchestrates interactive attack sessions.

    Manages session lifecycle, module loading, menu interaction,
    and evidence collection.
    """

    def __init__(self) -> None:
        """Initialize attack engine."""
        self.session_manager = SessionManager()
        self.menu_builder = MenuBuilder()
        self._module_cache: dict[str, object] = {}

    def start_session(
        self,
        target: str,
        plan: AttackPlan,
        opportunities: list[Opportunity],
        operator: str,
        scope_token: str,
        module_filter: Optional[str] = None,
        step_through: bool = True,
        findings: Optional[list[Finding]] = None,
    ) -> AttackSession:
        """Start an interactive attack session.

        Args:
            target: Target being assessed.
            plan: Attack plan from plan engine.
            opportunities: Identified opportunities.
            operator: Operator name.
            scope_token: Scope authorization token.
            module_filter: Optional specific module to run.
            step_through: If True, prompt before each step.

        Returns:
            Completed or aborted AttackSession.
        """
        from cape.core.audit_logger import get_audit_logger
        audit = get_audit_logger()

        session = self.session_manager.create_session(
            target=target,
            plan_id=plan.id,
            operator=operator,
            scope_token=scope_token,
        )

        self.session_manager.transition(session, SessionState.LOADED)

        # Filter modules by available opportunities
        available_modules = self._get_available_modules(opportunities)

        if module_filter:
            available_modules = {
                k: v for k, v in available_modules.items()
                if k.lower() == module_filter.lower()
            }

        if not available_modules:
            from cape.cli.console import get_console
            get_console().print("[yellow]No modules available for identified opportunities.[/yellow]")
            return session

        self.session_manager.transition(session, SessionState.ACTIVE)
        audit.log_attack_start(target, operator, str(list(available_modules.keys())))

        try:
            if step_through:
                session = self._run_interactive(
                    session, target, plan, opportunities, available_modules, findings or []
                )
            else:
                session = self._run_all_modules(
                    session, target, available_modules, opportunities, findings or []
                )
        except KeyboardInterrupt:
            logger.info("Attack session interrupted by operator")
            if session.state == SessionState.ACTIVE:
                self.session_manager.transition(session, SessionState.ABORTED)
        except Exception as e:
            logger.error(f"Attack session error: {e}", exc_info=True)
            if session.state == SessionState.ACTIVE:
                self.session_manager.transition(session, SessionState.ABORTED)

        if session.state == SessionState.ACTIVE:
            self.session_manager.transition(session, SessionState.COMPLETED)

        audit.log_attack_complete(target, operator, str(session.id))
        return session

    def resume_session(self, session_id: UUID) -> Optional[AttackSession]:
        """Resume a paused session.

        Args:
            session_id: UUID of session to resume.

        Returns:
            Resumed session, or None if not found.
        """
        session = self.session_manager.load_session(session_id)
        if not session:
            logger.error(f"Session {session_id} not found")
            return None

        if session.state != SessionState.PAUSED:
            logger.error(f"Session {session_id} is not in PAUSED state: {session.state.value}")
            return None

        from cape.core.audit_logger import get_audit_logger
        from cape.shared.enums import EventType
        audit = get_audit_logger()
        audit.log(
            EventType.SESSION_RESUME,
            target=session.target,
            operator=session.operator,
            detail=f"Session resumed: {session_id}",
        )

        self.session_manager.transition(session, SessionState.ACTIVE)
        return session

    def list_modules(self, opportunities: list[Opportunity]) -> list[str]:
        """List available modules for the given opportunities.

        Args:
            opportunities: Identified opportunities.

        Returns:
            List of module names.
        """
        return list(self._get_available_modules(opportunities).keys())

    def _get_available_modules(
        self, opportunities: list[Opportunity]
    ) -> dict[str, object]:
        """Get modules that have matching opportunities.

        Args:
            opportunities: Scored opportunities.

        Returns:
            Dict of module_name → module_instance.
        """
        try:
            from cape.attack.modules import AVAILABLE_MODULES
        except ImportError:
            return {}

        opportunity_pattern_ids = {o.attack_pattern_id for o in opportunities}
        opportunity_module_names = set()
        for opp in opportunities:
            opportunity_module_names.update(opp.recommended_modules)

        available: dict[str, object] = {}
        for name, cls in AVAILABLE_MODULES.items():
            module = cls()
            # Include if module name is in recommended_modules OR no filter
            if name in opportunity_module_names or not opportunity_module_names:
                available[name] = module

        return available

    def _run_interactive(
        self,
        session: AttackSession,
        target: str,
        plan: AttackPlan,
        opportunities: list[Opportunity],
        modules: dict[str, object],
        findings: list[Finding],
    ) -> AttackSession:
        """Run interactive menu-driven session.

        Args:
            session: Active session.
            target: Target being assessed.
            plan: Attack plan.
            opportunities: Available opportunities.
            modules: Available modules.

        Returns:
            Updated session.
        """
        from cape.cli.console import get_console
        console = get_console()

        while session.state == SessionState.ACTIVE:
            self.menu_builder.render(target, opportunities, session)
            choice = self.menu_builder.prompt_selection(opportunities)

            if choice == "q":
                self.session_manager.transition(session, SessionState.ABORTED)
                break

            elif choice == "a":
                session = self._run_all_modules(session, target, modules, opportunities, findings)
                break

            elif choice == "s":
                session = self._run_step_through(session, target, modules, opportunities, findings)
                break

            elif choice == "r":
                console.print("[dim]Report generation - use 'cape report' command[/dim]")

            elif choice == "i":
                idx_str = input("  Opportunity number: ").strip()
                try:
                    idx = int(idx_str) - 1
                    if 0 <= idx < len(opportunities):
                        opp = opportunities[idx]
                        self.menu_builder.show_opportunity_detail(opp)
                        self.menu_builder.offer_full_explanation(opp, target)
                except ValueError:
                    pass

            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(opportunities):
                    opp = opportunities[idx]
                    module_names = opp.recommended_modules
                    for mod_name in module_names:
                        if mod_name in modules:
                            self._execute_module(
                                modules[mod_name], session, target, opportunities, findings
                            )
                else:
                    console.print("[red]Invalid selection[/red]")

            else:
                console.print("[red]Unknown command[/red]")

        return session

    def _run_all_modules(
        self,
        session: AttackSession,
        target: str,
        modules: dict[str, object],
        opportunities: list[Opportunity],
        findings: list[Finding],
    ) -> AttackSession:
        """Run all available modules sequentially."""
        for name, module in modules.items():
            if session.state != SessionState.ACTIVE:
                break
            self._execute_module(module, session, target, opportunities, findings)
        return session

    def _run_step_through(
        self,
        session: AttackSession,
        target: str,
        modules: dict[str, object],
        opportunities: list[Opportunity],
        findings: list[Finding],
    ) -> AttackSession:
        """Run modules one at a time with operator confirmation."""
        for name, module in modules.items():
            if session.state != SessionState.ACTIVE:
                break
            confirmed = self.menu_builder.confirm_execution(name)
            if confirmed:
                self._execute_module(module, session, target, opportunities, findings)
        return session

    def _execute_module(
        self,
        module: object,
        session: AttackSession,
        target: str,
        opportunities: list[Opportunity],
        findings: list[Finding],
    ) -> None:
        """Execute a single attack module.

        Args:
            module: Module instance.
            session: Active session.
            target: Target string.
            opportunities: Available opportunities.
        """
        from cape.cli.console import get_console
        console = get_console()

        ctx = module.load_context(target, session, findings)  # type: ignore[attr-defined]
        validation = module.validate_preconditions(ctx)  # type: ignore[attr-defined]

        if not validation.valid:
            console.print(
                f"[yellow]Skipping {module.name}: "
                f"{', '.join(validation.missing_requirements)}[/yellow]"
            )
            return

        preparation = module.prepare_tools(ctx)  # type: ignore[attr-defined]
        if not preparation.ready:
            console.print(
                f"[yellow]Skipping {module.name}: required tool(s) unavailable: "
                f"{', '.join(preparation.missing_tools)}[/yellow]"
            )
            return

        steps = module.get_steps(ctx)  # type: ignore[attr-defined]
        step_results = []

        for step in steps:
            operator_inputs = {}
            if getattr(module, "requires_explicit_run", False):
                console.print(f"\\n[yellow]⚠ Controlled lab test:[/yellow] {step.name}")
                console.print(f"  {step.description}")
                if step.notes:
                    console.print(f"  [dim]Notes: {step.notes}[/dim]")
                collector = getattr(module, "collect_operator_inputs", None)
                if callable(collector):
                    operator_inputs = collector(ctx, step)
                confirmation = input("  Type RUN to execute this test (anything else cancels): ").strip()
                if confirmation != "RUN":
                    from cape.scan.plugins.base import StepResult
                    result = StepResult(
                        step_id=str(step.id), success=False,
                        output="BLOCKED_BY_OPERATOR: execution was not confirmed",
                    )
                    step_results.append(result)
                    self.menu_builder.show_step_result(step.name, False, result.output)
                    continue
            elif step.operator_action_required:
                console.print(f"\\n[yellow]⚠ Operator action required:[/yellow] {step.name}")
                console.print(f"  {step.description}")
                if step.notes:
                    console.print(f"  [dim]Notes: {step.notes}[/dim]")
                if step.tool_args_template:
                    console.print(f"  [dim]Command template: {step.tool_args_template}[/dim]")
                input("  Press ENTER when complete (or Ctrl+C to abort)...")

            result = module.execute_step(step, ctx, operator_inputs)  # type: ignore[attr-defined]
            step_results.append(result)
            self.menu_builder.show_step_result(step.name, result.success, result.output or result.error)

            # Preserve raw step output as session evidence for audit/report review.
            try:
                from pathlib import Path
                import json
                from datetime import datetime, timezone
                from cape.attack.models import Evidence
                evidence_dir = Path.home() / ".cape" / "workspaces" / (
                    "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in target)[:90]
                ) / "sessions" / str(session.id) / "attack_evidence"
                evidence_dir.mkdir(parents=True, exist_ok=True)
                evidence_file = evidence_dir / f"{step.id}_result.json"
                evidence_file.write_text(json.dumps({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "module": getattr(module, "name", type(module).__name__),
                    "step": step.name,
                    "success": bool(result.success),
                    "output": result.output,
                    "error": result.error,
                }, indent=2), encoding="utf-8")
                evidence = Evidence(
                    session_id=session.id, step_id=step.id,
                    tool=step.tool or "cape-python-check",
                    command_run=step.tool or "bounded verification test",
                    raw_output_file=evidence_file,
                    summary=(result.output or result.error)[:500],
                )
                self.session_manager.add_evidence(session, evidence)
            except Exception as evidence_error:
                logger.warning("Could not persist attack evidence: %s", evidence_error)

            # Audit every attempted module step, including blocked/failed results.
            try:
                from cape.core.audit_logger import get_audit_logger
                from cape.shared.enums import EventType
                get_audit_logger().log(
                    EventType.TOOL_EXECUTE, target=target, operator=session.operator,
                    detail=f"module={getattr(module, 'name', type(module).__name__)}; "
                           f"step={step.name}; success={bool(result.success)}; "
                           f"evidence={(result.output or result.error)[:300]}",
                )
            except Exception as audit_error:
                logger.warning("Could not append attack-step audit event: %s", audit_error)

            self.session_manager.mark_step_complete(session, step.id)

        findings = module.collect_results(step_results)  # type: ignore[attr-defined]
        module.persist_results(findings, session)  # type: ignore[attr-defined]
