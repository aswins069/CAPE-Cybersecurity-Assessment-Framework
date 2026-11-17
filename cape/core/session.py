"""Lightweight session identity for CAPE.

CAPE used to require a manually-authored scope file, a typed
authorization acknowledgment, and an expiry date before any scan or
attack could run. That authorization structure has been removed for
this simplified build - CAPE now just tags every scan/attack session
with the local operating-system username and a generated session
token (used for audit-log correlation and attack-session identity),
with no prompts, files, or dates involved.
"""
from __future__ import annotations

import getpass

from cape.shared.utils import generate_session_token


def get_operator() -> str:
    """Return the local OS username to tag scans/attacks/audit entries with."""
    try:
        return getpass.getuser()
    except Exception:
        return "operator"


def new_session(target: str) -> tuple[str, str]:
    """Return (operator, session_token) for a new scan or attack run.

    No scope file, no acknowledgment prompt, no expiry check - just an
    operator name and a generated token so downstream audit logging and
    attack-session tracking keep working exactly as before.
    """
    operator = get_operator()
    token = generate_session_token(target, operator)
    return operator, token
