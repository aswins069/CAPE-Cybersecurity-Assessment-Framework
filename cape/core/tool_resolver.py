"""Resolves external tool binaries and enabled/disabled state for CAPE.

Backs the "Configuration Manager" TUI screen: an operator can point a
tool name (nmap, nikto, ...) at a custom binary path, or disable a
tool entirely, from the Configuration menu. Every plugin's dependency
check and subprocess execution goes through here instead of calling
shutil.which() directly, so those settings actually take effect.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional


def resolve_tool_path(tool: str) -> Optional[str]:
    """Return the path to use for `tool`: a configured override if set
    and it exists, otherwise the normal PATH lookup."""
    from cape.core.config import get_config

    custom = get_config().tool_paths.get(tool)
    if custom and Path(custom).exists():
        return custom
    return shutil.which(tool)


def is_tool_enabled(tool: str) -> bool:
    """Whether `tool` is enabled in the Configuration Manager (default: yes)."""
    from cape.core.config import get_config

    return get_config().enabled_tools.get(tool, True)
