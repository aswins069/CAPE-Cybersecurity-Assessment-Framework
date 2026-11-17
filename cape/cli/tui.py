"""Reusable arrow-key menu navigation for CAPE.

Design principle (same one menu.py already follows): this module is
UI-only. It never contains business logic, engine calls, or scope
gating. It renders a list, lets the operator move a cursor with the
arrow keys (or j/k), and returns whatever value was attached to the
highlighted item. Every screen in cli/menu.py and attack/menu.py keeps
calling the exact same command functions as before - only the input
method changed, from "type a number + Enter" to "arrow keys + Enter".

Navigation convention used everywhere this is called:
    Up/Down or j/k  - move the cursor
    Enter           - select the highlighted item
    Esc or b        - go back one level (caller decides what that means)
    q or Ctrl-C     - quit out of the whole menu
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style

# Sentinels returned by arrow_menu() instead of an item's value.
BACK = object()
QUIT = object()

_STYLE = Style.from_dict({
    "title": "bold cyan",
    "breadcrumb": "italic #888888",
    "cursor": "bold ansigreen",
    "selected": "bold ansigreen",
    "item": "",
    "desc": "#888888",
    "footer": "italic #888888",
    "disabled": "#666666",
})


@dataclass
class MenuItem:
    """One selectable row in an arrow_menu()."""
    label: str
    value: Any = None
    description: str = ""
    disabled: bool = False


def arrow_menu(
    title: str,
    items: list[MenuItem],
    breadcrumb: str = "",
    allow_back: bool = True,
    input=None,
    output=None,
) -> Any:
    """Render a scrollable arrow-key menu and block until a choice is made.

    Returns:
        The .value of the selected MenuItem, or the BACK / QUIT sentinel.
    """
    selectable = [i for i, item in enumerate(items) if not item.disabled]
    if not selectable:
        return BACK if allow_back else QUIT
    state = {"i": selectable[0]}

    def _move(delta: int) -> None:
        pos = selectable.index(state["i"]) if state["i"] in selectable else 0
        state["i"] = selectable[(pos + delta) % len(selectable)]

    def get_text():
        lines: list[tuple[str, str]] = []
        if breadcrumb:
            lines.append(("class:breadcrumb", breadcrumb + "\n\n"))
        lines.append(("class:title", title + "\n\n"))
        for i, item in enumerate(items):
            if item.disabled:
                lines.append(("class:disabled", f"    {item.label}"))
            elif i == state["i"]:
                lines.append(("class:cursor", "  \u276f "))
                lines.append(("class:selected", item.label))
            else:
                lines.append(("class:item", f"    {item.label}"))
            if item.description:
                lines.append(("class:desc", f"  \u2014 {item.description}"))
            lines.append(("", "\n"))
        footer = "\n\u2191/\u2193 or j/k move   Enter select"
        if allow_back:
            footer += "   Esc/b back"
        footer += "   q quit"
        lines.append(("class:footer", footer))
        return lines

    kb = KeyBindings()

    @kb.add("up")
    @kb.add("k")
    def _up(event):
        _move(-1)

    @kb.add("down")
    @kb.add("j")
    def _down(event):
        _move(1)

    @kb.add("enter")
    def _select(event):
        event.app.exit(result=items[state["i"]].value)

    @kb.add("q")
    @kb.add("c-c")
    def _quit(event):
        event.app.exit(result=QUIT)

    if allow_back:
        @kb.add("escape")
        @kb.add("b")
        def _back(event):
            event.app.exit(result=BACK)

    control = FormattedTextControl(get_text, focusable=True)
    window = Window(content=control, always_hide_cursor=True)
    app: Application = Application(
        layout=Layout(HSplit([window])),
        key_bindings=kb,
        style=_STYLE,
        full_screen=False,
        mouse_support=False,
        input=input,
        output=output,
    )
    return app.run()


def confirm_menu(question: str, breadcrumb: str = "", default_yes: bool = True) -> bool:
    """Arrow-key Yes/No prompt. Returns True for Yes, False for No/quit/back."""
    items = (
        [MenuItem("Yes", True), MenuItem("No", False)]
        if default_yes
        else [MenuItem("No", False), MenuItem("Yes", True)]
    )
    result = arrow_menu(question, items, breadcrumb=breadcrumb, allow_back=False)
    return result is True


def text_menu(
    title: str,
    default: str = "",
    breadcrumb: str = "",
) -> str:
    """Free-text entry (hostnames, paths, IDs aren't a fixed list, so this
    stays a plain prompt rather than an arrow menu - there's nothing to
    move a cursor between)."""
    from rich.console import Console
    console = Console()
    if breadcrumb:
        console.print(f"[italic #888888]{breadcrumb}[/italic #888888]")
    suffix = f" [{default}]" if default else ""
    raw = console.input(f"[bold cyan]{title}{suffix}:[/bold cyan] ").strip()
    return raw or default
