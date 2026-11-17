"""Shared utility functions for CAPE."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import time
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from cape.shared.constants import SEVERITY_WEIGHTS


def validate_ip(target: str) -> bool:
    """Return True if target is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def validate_cidr(target: str) -> bool:
    """Return True if target is a valid CIDR network."""
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def validate_hostname(target: str) -> bool:
    """Return True if target is a valid hostname."""
    if len(target) > 255:
        return False
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"\.)*[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(target))


def validate_url(target: str) -> bool:
    """Return True if target is a valid HTTP/HTTPS URL."""
    pattern = re.compile(
        r"^https?://"
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
        r"localhost|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"(?::\d+)?"
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )
    return bool(pattern.match(target))


def sanitize_target(target: str) -> str:
    """Strip shell metacharacters from a target string.

    Raises ValueError if target contains dangerous characters.
    """
    shell_metachars = set(';|&$`(){}[]<>\\"\' \t\n\r')
    bad = [c for c in target if c in shell_metachars]
    if bad:
        raise ValueError(
            f"Target '{target}' contains forbidden characters: {set(bad)}"
        )
    return target.strip()


def severity_weight(severity: str) -> float:
    """Return numeric weight for a severity string."""
    return SEVERITY_WEIGHTS.get(severity, 0.1)


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def generate_session_token(target: str, operator: str) -> str:
    """Generate a deterministic session token for a target+operator combo."""
    raw = f"{target}:{operator}:{time.time()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def uuid_str(u: Optional[UUID]) -> Optional[str]:
    """Convert UUID to string or return None."""
    return str(u) if u else None


def ensure_dir(path: Path) -> Path:
    """Create directory if it doesn't exist, return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_read(path: Path, default: str = "") -> str:
    """Read file content safely, return default on error."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, IOError):
        return default


def truncate(text: str, max_len: int = 200) -> str:
    """Truncate text to max_len, adding ellipsis."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def resolve_target_host(target: str) -> str:
    """Extract just the hostname/IP from a target (strip scheme/path)."""
    # Remove scheme
    target = re.sub(r"^https?://", "", target)
    # Remove port and path
    target = target.split(":")[0].split("/")[0]
    return target.strip()


def clamp(value: float, minimum: float = 0.0, maximum: float = 10.0) -> float:
    """Clamp value between minimum and maximum."""
    return max(minimum, min(maximum, value))


def flatten_list(nested: list[Any]) -> list[Any]:
    """Flatten one level of a nested list."""
    result: list[Any] = []
    for item in nested:
        if isinstance(item, list):
            result.extend(item)
        else:
            result.append(item)
    return result
