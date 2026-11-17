"""Rich console singleton for CAPE CLI."""
from __future__ import annotations

from rich.console import Console

_console: Console | None = None


def get_console() -> Console:
    """Get or create the global Rich console."""
    global _console
    if _console is None:
        _console = Console()
    return _console
