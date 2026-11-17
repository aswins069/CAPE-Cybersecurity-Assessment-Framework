"""CAPE interactive menu — a guided front-end over the existing CLI commands.

Design principle: this module never reimplements engine logic, scope
gating, or audit logging. Every menu action calls the exact same Typer
command function (e.g. cli.commands.show.show) that 'cape show ...' calls
on the command line, just with answers supplied as plain arguments
instead of parsed flags. The menu is purely additive - every existing
`co <command> ...` invocation keeps working exactly as before, unchanged.

Pipeline stages (in order, matching CAPE's stated pipeline):
    Scan -> Show -> Explain -> Plan -> Attack
Supporting capabilities:
    Diff -> Audit -> Report -> Clients -> Doctor
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from cape.cli.tui import BACK, QUIT, MenuItem, arrow_menu, confirm_menu, text_menu

logger = logging.getLogger(__name__)

console = Console()

_SEVERITY_COLOR = {
    "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}


# ============================================================================
# Small shared helpers
# ============================================================================

def _confirm(text: str, default_yes: bool = True) -> bool:
    """A y/n confirmation, now an arrow-key Yes/No menu instead of typed y/n."""
    return confirm_menu(text, default_yes=default_yes)


def _resolve_default(param) -> object:
    """Resolve a Typer OptionInfo/ArgumentInfo default to its real Python value.

    When a Typer command function is called directly (bypassing Typer's
    own app() runner, as every menu action does), parameters the caller
    didn't supply keep their raw typer.models.OptionInfo/ArgumentInfo
    object as their default instead of the actual default value Typer
    would normally resolve (None, 0.0, "rich", False, ...). Passing that
    raw object straight into engine code breaks it in confusing ways
    (e.g. a SQL query bound to an OptionInfo object). This pulls out the
    real default so direct calls behave the same as CLI invocations.
    """
    import inspect
    if param.default is inspect.Parameter.empty:
        return None
    default = param.default
    # typer.models.OptionInfo / ArgumentInfo both expose the underlying
    # default value as `.default`.
    if hasattr(default, "default") and type(default).__module__.startswith("typer"):
        return default.default
    return default


def _call_command(fn, **kwargs) -> bool:
    """Call a Typer command function directly, with unset parameters
    resolved to their real defaults, and swallowing its typer.Exit.

    Typer command functions raise typer.Exit(code) instead of returning a
    value when they want to stop early (e.g. "no findings, run scan
    first"). When called directly (bypassing Typer's own app() runner),
    that exception would otherwise propagate and crash the whole menu
    process. We catch it here and just return to the menu loop.

    Returns:
        True if the command ran to completion without typer.Exit(code>0).
        False if it exited early with a non-zero code (treated as a
        recoverable "nothing to do" outcome, not a crash).
    """
    import inspect

    try:
        sig = inspect.signature(fn)
        full_kwargs = dict(kwargs)
        for name, param in sig.parameters.items():
            if name not in full_kwargs:
                full_kwargs[name] = _resolve_default(param)
        fn(**full_kwargs)
        return True
    except typer.Exit as e:
        code = getattr(e, "exit_code", getattr(e, "code", 0)) or 0
        return code == 0
    except Exception as e:
        logger.error(f"Menu action failed calling {getattr(fn, '__name__', fn)}: {e}")
        console.print(f"[red]Error: {e}[/red]")
        return False


def _recent_targets(limit: int = 8) -> list[str]:
    """Best-effort list of recently-scanned targets, newest first.

    Reads straight from the Target table - read-only, no engine logic
    duplicated. CAPE multi-tenant scoping (CAPE_CLIENT_ID) is respected if
    set, exactly like every other read path in the project.
    """
    try:
        from cape.db.session import db_session, init_db
        from cape.db.models import Target
        from cape.core.config import get_config

        init_db()
        cfg = get_config()

        with db_session() as session:
            query = session.query(Target)
            if cfg.current_client:
                query = query.filter(Target.client_id == cfg.current_client)
            rows = query.order_by(Target.last_scanned_at.desc().nullslast()).limit(limit).all()
            return [t.hostname_or_ip for t in rows]
    except Exception as e:
        logger.error(f"Could not load recent targets: {e}")
        return []


_NEW_TARGET = object()


def _pick_target(prompt_label: str = "Target", breadcrumb: str = "") -> Optional[str]:
    """Offer recent targets on an arrow-key menu, or a row to type a new one."""
    recent = _recent_targets()

    if recent:
        items = [MenuItem(t, t) for t in recent]
        items.append(MenuItem("+ Enter a new target", _NEW_TARGET))
        choice = arrow_menu(prompt_label, items, breadcrumb=breadcrumb)
        if choice is QUIT:
            raise typer.Exit()
        if choice is BACK or choice is None:
            return None
        if choice is not _NEW_TARGET:
            return choice

    target = text_menu(
        f"Enter {prompt_label.lower()} (hostname, IP, or URL)", breadcrumb=breadcrumb
    )
    return target or None


def _current_client_banner() -> str:
    """Small banner line showing the active CAPE client, if any."""
    try:
        from cape.core.config import get_config
        client = get_config().current_client
        return client or "(none)"
    except Exception:
        return "(none)"


# ============================================================================
# Main menu
# ============================================================================

_MAIN_MENU_ITEMS = [
    MenuItem("Scan", "scan", "Find vulnerabilities"),
    MenuItem("Show", "show", "View attack opportunities"),
    MenuItem("Explain", "explain", "Why did it score this way?"),
    MenuItem("Plan", "plan", "Order the assessment"),
    MenuItem("Attack", "attack", "Pick a path and intrude"),
    MenuItem("Diff", "diff", "What changed since the last scan?"),
    MenuItem("Audit", "audit", "Verify the tamper-evident log"),
    MenuItem("Report", "report", "CISO / auditor / engineer / full"),
    MenuItem("Clients", "clients", "Multi-tenant isolation"),
    MenuItem("Demo Mode", "demo", "Run the full pipeline on sample data — no tools needed"),
    MenuItem("Configuration", "config", "Set up scan tools, degree, and paths"),
    MenuItem("Doctor", "doctor", "System health check"),
]

_MAIN_MENU_DISPATCH = {
    "scan": lambda: menu_scan(),
    "show": lambda: menu_show(),
    "explain": lambda: menu_explain(),
    "plan": lambda: menu_plan(),
    "attack": lambda: menu_attack(),
    "diff": lambda: menu_diff(),
    "audit": lambda: menu_audit(),
    "report": lambda: menu_report(),
    "clients": lambda: menu_clients(),
    "demo": lambda: menu_demo(),
    "config": lambda: menu_config(),
    "doctor": lambda: menu_doctor(),
}


def run_main_menu() -> None:
    """Entry point: render the arrow-key main menu loop until the operator quits."""
    from cape.db.session import init_db
    init_db()

    while True:
        title = "CAPE - Continuous Assurance Pentest Engine"
        breadcrumb = f"Client: {_current_client_banner()}"
        choice = arrow_menu(title, _MAIN_MENU_ITEMS, breadcrumb=breadcrumb, allow_back=False)

        if choice is QUIT or choice is None:
            console.print("[dim]Goodbye.[/dim]")
            break

        action = _MAIN_MENU_DISPATCH.get(choice)
        if action:
            action()


# ============================================================================
# 1. Scan
# ============================================================================

_SCAN_PROFILES = [
    ("quick", "Fast top-1000 port scan plus web fingerprinting"),
    ("recon", "Full port scan plus service enumeration"),
    ("web", "Web vulnerability scanning (nikto, gobuster)"),
    ("cms", "CMS detection plus WordPress scanning"),
    ("network", "Full network assessment plus SNMP"),
    ("smb", "SMB enumeration plus signing checks"),
    ("api", "API endpoint discovery plus ZAP scanning"),
    ("vuln", "NSE vulnerability scripts plus nikto"),
    ("full", "All of the above, intelligently sequenced"),
]


def menu_scan() -> None:
    """Guided scan: pick target, pick profile, confirm scope, run."""
    from cape.cli.commands.scan import scan as scan_fn

    target = _pick_target("Target to scan", breadcrumb="CAPE > Scan")
    if not target:
        return

    items = [MenuItem(f"{name:<10} {desc}", name, ) for name, desc in _SCAN_PROFILES]
    profile = arrow_menu("Scan profile", items, breadcrumb=f"CAPE > Scan > {target}")
    if profile is BACK or profile is QUIT or profile is None:
        return

    console.print(f"\n[bold]Running:[/bold] cape scan {profile} {target}")
    ok = _call_command(scan_fn, profile=profile, target=target)

    if ok and _confirm("Scan step finished. View attack opportunities now?"):
        _show_for_target(target)


# ============================================================================
# 2. Show
# ============================================================================

def menu_show() -> None:
    """Guided show: pick target, optional filters, render opportunities,
    then offer an inline explain for any interesting result."""
    target = _pick_target("Target to show opportunities for")
    if not target:
        return
    _show_for_target(target)


def _show_for_target(target: str) -> None:
    """Shared show logic, reused after Scan completes and from the Show menu."""
    show_compliance = _confirm("Show compliance control mapping (PCI-DSS/SOC2/ISO27001) too?", default_yes=False)

    from cape.cli.commands.show import show as show_fn
    _call_command(show_fn, target=target, compliance=show_compliance)

    # Real opportunities (re-derived, same as the CLI command itself) so we
    # can offer an inline "explain this one" follow-up by index.
    opportunities = _load_opportunities_quietly(target)
    if not opportunities:
        return

    if _confirm("\nExplain any of these opportunities in full right now?", default_yes=False):
        _explain_pick_from_list(target, opportunities)


def _load_opportunities_quietly(target: str) -> list:
    """Re-derive opportunities for a target without printing anything,
    so the menu can offer follow-up actions against them."""
    try:
        from cape.show.engine import ShowEngine
        engine = ShowEngine()
        findings = engine.load_findings_from_db(target)
        if not findings:
            return []
        return engine.analyze(target=target, findings=findings)
    except Exception as e:
        logger.error(f"Could not load opportunities for {target}: {e}")
        return []


# ============================================================================
# 3. Explain
# ============================================================================

def menu_explain() -> None:
    """Standalone explain: pick target, pick all/one, toggle deep, render."""
    target = _pick_target("Target to explain opportunities for")
    if not target:
        return

    opportunities = _load_opportunities_quietly(target)
    if not opportunities:
        console.print(f"[yellow]No opportunities found for {target}. Run Scan and Show first.[/yellow]")
        return

    _explain_pick_from_list(target, opportunities)


def _explain_pick_from_list(target: str, opportunities: list) -> None:
    """Shared 'pick one or all, then explain' flow used by both the Show
    follow-up and the standalone Explain menu."""
    items = [
        MenuItem(
            f"{opp.severity.value:<8} {opp.name}  (score {opp.score:.1f})",
            str(opp.id),
        )
        for opp in opportunities
    ]
    items.append(MenuItem("Explain all", "__all__"))
    choice = arrow_menu("Which opportunity?", items, breadcrumb=f"CAPE > Explain > {target}")
    if choice is BACK or choice is QUIT or choice is None:
        return

    deep = _confirm("Include raw tool output (--deep)?", default_yes=False)

    from cape.cli.commands.explain import explain as explain_fn

    if choice == "__all__":
        _call_command(explain_fn, target=target, all_opportunities=True, deep=deep)
    else:
        _call_command(explain_fn, target=target, opportunity_id=choice, deep=deep)


# ============================================================================
# 4. Plan
# ============================================================================

def menu_plan() -> None:
    """Guided plan: pick target, build plan, offer per-step explain."""
    target = _pick_target("Target to plan for")
    if not target:
        return

    from cape.cli.commands.plan import plan as plan_fn
    _call_command(plan_fn, target=target, fmt="table")

    if _confirm("\nExplain the opportunity behind any of these steps?", default_yes=False):
        opportunities = _load_opportunities_quietly(target)
        if opportunities:
            _explain_pick_from_list(target, opportunities)
        else:
            console.print("[yellow]No opportunities available to explain.[/yellow]")


# ============================================================================
# 5. Attack — hands off into the existing, unmodified AttackEngine/menu
# ============================================================================

def menu_attack() -> None:
    """Guided attack: pick target, confirm scope, hand off into the real
    AttackEngine session (attack/engine.py + attack/menu.py), unchanged.

    This menu does not reimplement scope gating, module dispatch, or the
    inspect/explain flow inside the attack session - it calls the exact
    same 'cape attack' command function that already enforces all of that.
    """
    target = _pick_target("Target to attack", breadcrumb="CAPE > Attack")
    if not target:
        return

    list_only = _confirm("Just list available modules without starting a session?", default_yes=False)
    interactive = True
    if not list_only:
        interactive = _confirm("Step-through mode (confirm before each module)?", default_yes=True)

    console.print(f"\n[bold]Starting attack flow for:[/bold] {target}")

    from cape.cli.commands.attack import attack as attack_fn
    _call_command(
        attack_fn, target=target, list_modules=list_only, interactive=interactive,
    )


# ============================================================================
# 6. Diff
# ============================================================================

def menu_diff() -> None:
    """Guided diff: pick target, pick comparison mode, render."""
    target = _pick_target("Target to compare scans for")
    if not target:
        return

    items = [
        MenuItem("Compare the last 2 scans", "last2"),
        MenuItem("Compare the last N scans", "lastn"),
        MenuItem("Compare two specific scan IDs", "ids"),
    ]
    choice = arrow_menu("Diff mode", items, breadcrumb=f"CAPE > Diff > {target}")
    if choice is BACK or choice is QUIT or choice is None:
        return

    from cape.cli.commands.diff import diff as diff_fn

    if choice == "lastn":
        n_str = text_menu("How many recent scans?", default="3")
        n = int(n_str) if n_str.isdigit() else 3
        _call_command(diff_fn, target=target, last=n)
    elif choice == "ids":
        scan_from = text_menu("Earlier scan ID")
        scan_to = text_menu("Later scan ID")
        _call_command(diff_fn, target=target, scan_from=scan_from, scan_to=scan_to)
    else:
        _call_command(diff_fn, target=target, last=2)


# ============================================================================
# 7. Audit
# ============================================================================

def menu_audit() -> None:
    """Guided audit: verify chain, or browse recent entries."""
    items = [
        MenuItem("Verify chain integrity", "verify"),
        MenuItem("Show recent entries", "tail"),
        MenuItem("Filter by target", "filter"),
    ]
    choice = arrow_menu("Audit mode", items, breadcrumb="CAPE > Audit")
    if choice is BACK or choice is QUIT or choice is None:
        return

    from cape.cli.commands.audit import audit as audit_fn

    if choice == "tail":
        n_str = text_menu("How many recent entries?", default="20")
        n = int(n_str) if n_str.isdigit() else 20
        _call_command(audit_fn, tail=n)
    elif choice == "filter":
        target = _pick_target("Target to filter by", breadcrumb="CAPE > Audit > Filter")
        if target:
            _call_command(audit_fn, target=target)
    else:
        _call_command(audit_fn, verify=True)


# ============================================================================
# 8. Report
# ============================================================================

_AUDIENCES = [
    ("ciso", "Executive summary - no technical detail or port numbers"),
    ("auditor", "Scope, audit chain, compliance evidence - no exploit detail"),
    ("engineer", "Full technical detail, evidence, reproduction steps"),
    ("full", "Everything from all three audiences combined"),
]
_FORMATS = ["html", "json", "pdf"]


def _pick_audience(breadcrumb: str) -> Optional[str]:
    items = [MenuItem(f"{name:<10} {desc}", name) for name, desc in _AUDIENCES]
    choice = arrow_menu("Audience", items, breadcrumb=breadcrumb)
    return None if choice in (BACK, QUIT, None) else choice


def _pick_format(breadcrumb: str) -> Optional[str]:
    items = [MenuItem(fmt, fmt) for fmt in _FORMATS]
    choice = arrow_menu("Format", items, breadcrumb=breadcrumb)
    return None if choice in (BACK, QUIT, None) else choice


def menu_report() -> None:
    """Guided report: pick target, audience, format, generate, offer to open."""
    target = _pick_target("Target to report on", breadcrumb="CAPE > Report")
    if not target:
        return

    if _confirm("Explain any opportunities before generating the report?", default_yes=False):
        opportunities = _load_opportunities_quietly(target)
        if opportunities:
            _explain_pick_from_list(target, opportunities)

    audience = _pick_audience(f"CAPE > Report > {target}")
    if not audience:
        return
    fmt = _pick_format(f"CAPE > Report > {target} > {audience}")
    if not fmt:
        return

    from cape.cli.commands.report import report as report_fn
    _call_command(report_fn, target=target, fmt=fmt, audience=audience)


# ============================================================================
# 9. Clients
# ============================================================================

def menu_clients() -> None:
    """Guided multi-tenant client management."""
    items = [
        MenuItem("List clients", "list"),
        MenuItem("Create a client", "create"),
        MenuItem("Switch active client", "switch"),
        MenuItem("Generate an aggregated client report", "report"),
    ]
    choice = arrow_menu("Clients", items, breadcrumb="CAPE > Clients")
    if choice is BACK or choice is QUIT or choice is None:
        return

    from cape.cli.commands.clients import (
        list_clients as list_fn, create_client as create_fn,
        use_client as use_fn, client_report as report_fn,
    )

    if choice == "create":
        client_id = text_menu("New client ID (alphanumeric + hyphens)")
        if not client_id:
            return
        name = text_menu("Display name", default="")
        contact = text_menu("Contact email", default="")
        _call_command(create_fn, client_id=client_id, name=name, contact=contact)
    elif choice == "switch":
        client_id = text_menu("Client ID to switch to")
        if not client_id:
            return
        _call_command(use_fn, client_id=client_id)
        console.print(
            "[dim]Note: this only takes effect for new shells that eval the printed "
            "export line; the running menu process keeps its current client context.[/dim]"
        )
    elif choice == "report":
        client_id = text_menu("Client ID to report on")
        if not client_id:
            return
        audience = _pick_audience(f"CAPE > Clients > Report > {client_id}") or "full"
        fmt = _pick_format(f"CAPE > Clients > Report > {client_id} > {audience}") or "html"
        _call_command(report_fn, client_id=client_id, audience=audience, output_format=fmt)
    else:
        _call_command(list_fn)


# ============================================================================
# 0. Doctor
# ============================================================================

def menu_doctor() -> None:
    """Run the system health check."""
    from cape.cli.commands.doctor import doctor as doctor_fn
    _call_command(doctor_fn)


# ============================================================================
# 00. Demo Mode
# ============================================================================

def menu_demo() -> None:
    """Run the full pipeline against bundled sample data - no tools required."""
    from cape.cli.commands.demo import demo as demo_fn
    _call_command(demo_fn)


# ============================================================================
# Configuration Manager
# ============================================================================

_INTENSITY_LEVELS = [
    ("light", "Slower and quieter (nmap -T2, fewer scripts)"),
    ("normal", "Default balance of speed and thoroughness (nmap -T4)"),
    ("aggressive", "Fastest and most thorough (nmap -T5, -A)"),
]

_CONFIGURABLE_TOOLS = [
    "nmap", "masscan", "nikto", "whatweb", "gobuster",
    "wpscan", "enum4linux", "snmp-check", "zap", "dirb",
]


def menu_config() -> None:
    """Configuration manager: pick scan degree/intensity, enable or
    disable individual tools, and point a tool name at a custom binary
    path. Settings persist to ~/.cape/config.yaml and are read by the
    scan engine and plugins on every subsequent run."""
    while True:
        from cape.core.config import get_config
        cfg = get_config()

        items = [
            MenuItem(f"Scan degree / intensity   (current: {cfg.scan_intensity})", "intensity"),
            MenuItem("Enable / disable tools", "tools"),
            MenuItem("Set a custom tool path", "path"),
            MenuItem("View current configuration", "view"),
        ]
        choice = arrow_menu("Configuration Manager", items, breadcrumb="CAPE > Configuration")
        if choice is BACK or choice is QUIT or choice is None:
            return

        if choice == "intensity":
            _config_set_intensity()
        elif choice == "tools":
            _config_toggle_tools()
        elif choice == "path":
            _config_set_tool_path()
        elif choice == "view":
            _config_view()


def _config_set_intensity() -> None:
    from cape.core.config import update_settings

    items = [MenuItem(f"{name:<10} {desc}", name) for name, desc in _INTENSITY_LEVELS]
    choice = arrow_menu(
        "Scan degree / intensity", items, breadcrumb="CAPE > Configuration > Intensity"
    )
    if choice in (BACK, QUIT, None):
        return
    update_settings(scan_intensity=choice)
    console.print(f"[green]Scan degree set to:[/green] {choice}")


def _config_toggle_tools() -> None:
    from cape.core.config import get_config, update_settings

    while True:
        cfg = get_config()
        items = []
        for tool in _CONFIGURABLE_TOOLS:
            enabled = cfg.enabled_tools.get(tool, True)
            state = "[green]ON [/green] " if enabled else "[red]OFF[/red] "
            items.append(MenuItem(f"{state}{tool}", tool))
        items.append(MenuItem("Done", "__done__"))

        choice = arrow_menu(
            "Enable / disable tools (Enter toggles a tool)",
            items,
            breadcrumb="CAPE > Configuration > Tools",
        )
        if choice in (BACK, QUIT, None, "__done__"):
            return

        enabled_tools = dict(cfg.enabled_tools)
        enabled_tools[choice] = not enabled_tools.get(choice, True)
        update_settings(enabled_tools=enabled_tools)


def _config_set_tool_path() -> None:
    from cape.core.config import get_config, update_settings

    cfg = get_config()
    items = [
        MenuItem(f"{t:<10} {cfg.tool_paths.get(t, '(default: PATH lookup)')}", t)
        for t in _CONFIGURABLE_TOOLS
    ]
    choice = arrow_menu(
        "Pick a tool to set a custom binary path for",
        items,
        breadcrumb="CAPE > Configuration > Tool Paths",
    )
    if choice in (BACK, QUIT, None):
        return

    path_str = text_menu(
        f"Path to the '{choice}' binary (leave blank to reset to default PATH lookup)",
        default=cfg.tool_paths.get(choice, ""),
    )
    tool_paths = dict(cfg.tool_paths)
    if path_str:
        tool_paths[choice] = path_str
    else:
        tool_paths.pop(choice, None)
    update_settings(tool_paths=tool_paths)
    console.print(f"[green]Updated tool path for {choice}[/green]")


def _config_view() -> None:
    from cape.core.config import get_config

    cfg = get_config()
    lines = [f"Scan degree / intensity: {cfg.scan_intensity}", "", "Tools:"]
    for tool in _CONFIGURABLE_TOOLS:
        enabled = cfg.enabled_tools.get(tool, True)
        path = cfg.tool_paths.get(tool, "PATH lookup")
        lines.append(f"  {tool:<10} {'enabled ' if enabled else 'disabled'}  ({path})")

    console.print(Panel("\n".join(lines), title="Current Configuration", border_style="cyan"))
    text_menu("Press Enter to continue")
