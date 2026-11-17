"""Target input validation for CAPE.

All target inputs are validated before any operation. Shell metacharacters
are rejected, and format is checked before a scan or attack session starts.
"""
from __future__ import annotations

import ipaddress
import re

from cape.core.exceptions import TargetValidationError
from cape.shared.utils import (
    sanitize_target,
    validate_cidr,
    validate_hostname,
    validate_ip,
    validate_url,
)


class TargetValidator:
    """Validates target inputs before any operation.

    Checks format (hostname, IP, CIDR, URL) and rejects inputs
    containing shell metacharacters.
    """

    SHELL_METACHARS = re.compile(r"[;|&$`(){}\\'\"\t\n\r<>]")

    def validate(self, target: str) -> str:
        """Validate target and return sanitized form.

        Raises TargetValidationError if target is invalid.
        """
        if not target or not target.strip():
            raise TargetValidationError(target)

        # Reject shell metacharacters
        if self.SHELL_METACHARS.search(target):
            raise TargetValidationError(target)

        stripped = target.strip()

        if self.is_valid(stripped):
            return stripped

        raise TargetValidationError(target)

    def is_valid(self, target: str) -> bool:
        """Return True if target passes any valid format check."""
        return (
            validate_ip(target)
            or validate_cidr(target)
            or validate_hostname(target)
            or validate_url(target)
        )

    def target_type(self, target: str) -> str:
        """Return the type of target: 'ip', 'cidr', 'hostname', 'url', or 'unknown'."""
        if validate_ip(target):
            return "ip"
        if validate_cidr(target):
            return "cidr"
        if validate_url(target):
            return "url"
        if validate_hostname(target):
            return "hostname"
        return "unknown"

    def normalize(self, target: str) -> str:
        """Normalize target to a consistent string form."""
        target = target.strip()
        # Strip trailing slash from URLs
        target = target.rstrip("/")
        return target

    def extract_host(self, target: str) -> str:
        """Extract just the host portion from a URL or return target as-is."""
        if validate_url(target):
            # Remove scheme and path
            host = re.sub(r"^https?://", "", target)
            host = host.split("/")[0].split(":")[0]
            return host
        return target

    def validate_many(self, targets: list[str]) -> list[str]:
        """Validate a list of targets, returning sanitized list or raising on first error."""
        return [self.validate(t) for t in targets]
