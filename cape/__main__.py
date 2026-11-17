"""Allows launching CAPE as `python -m cape`.

Running with no arguments drops straight into the arrow-key TUI
dashboard (cli.main handles this via its Typer callback). Running
`python -m cape <command> ...` behaves exactly like the installed
`cape` console script, e.g. `python -m cape doctor`.
"""
from __future__ import annotations

from cape.cli.main import app

if __name__ == "__main__":
    app()
