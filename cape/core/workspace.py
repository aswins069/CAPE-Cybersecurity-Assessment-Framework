"""Workspace manager for CAPE.

Each target gets an isolated workspace directory tree under
~/.cape/workspaces/<target>/
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from cape.core.config import get_config
from cape.core.exceptions import WorkspaceError

_CLIENT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9-]+$")


def validate_client_id(client_id: str) -> str:
    """Validate a CAPE client_id is alphanumeric + hyphens only.

    This guards every place client_id is interpolated into a filesystem
    path or used as a raw SQL filter value, preventing path traversal
    and injection via a malicious --client / CAPE_CLIENT_ID value.

    Args:
        client_id: The candidate client ID.

    Returns:
        The same client_id, unchanged, if valid.

    Raises:
        ValueError: if client_id is empty or contains characters other
            than ASCII letters, digits, and hyphens.
    """
    if not client_id or not _CLIENT_ID_PATTERN.match(client_id):
        raise ValueError(
            f"Invalid client_id '{client_id}': must be non-empty and contain only "
            f"alphanumeric characters and hyphens."
        )
    return client_id


@dataclass
class WorkspacePaths:
    """Paths within a target workspace."""

    root: Path
    raw: Path
    parsed: Path
    plans: Path
    sessions: Path
    reports: Path
    checkpoint_file: Path

    @classmethod
    def from_root(cls, root: Path) -> "WorkspacePaths":
        """Build WorkspacePaths from a workspace root directory."""
        return cls(
            root=root,
            raw=root / "raw",
            parsed=root / "parsed",
            plans=root / "plans",
            sessions=root / "sessions",
            reports=root / "reports",
            checkpoint_file=root / ".checkpoint",
        )

    def ensure_exists(self) -> None:
        """Create all subdirectories."""
        for path in [self.raw, self.parsed, self.plans, self.sessions, self.reports]:
            path.mkdir(parents=True, exist_ok=True)


@dataclass
class WorkspaceSummary:
    """Summary of a target workspace."""

    target: str
    root: Path
    created_at: Optional[datetime]
    last_modified: Optional[datetime]
    has_checkpoint: bool
    raw_file_count: int
    parsed_file_count: int


class WorkspaceManager:
    """Manages per-target workspace directories.

    Creates, retrieves, and maintains workspace directory trees.
    Supports checkpoint save/load for scan resumption.
    """

    def __init__(
        self,
        workspace_root: Optional[Path] = None,
        client_id: Optional[str] = None,
    ) -> None:
        """Initialize with workspace root directory.

        Args:
            workspace_root: Explicit workspace root. If None, derived from
                config, optionally namespaced under the given client_id.
            client_id: CAPE multi-tenant client ID. When set (and
                workspace_root is not explicitly given), workspaces live
                under ~/.cape/clients/<client_id>/workspaces/
                instead of the shared default location.
        """
        self.client_id = client_id

        if workspace_root is None:
            base_config_root = get_config().workspace_root
            if client_id:
                validate_client_id(client_id)
                # base_config_root is normally
                # ~/.cape/workspaces - swap it for the
                # per-client namespace: ~/.cape/clients/<id>/workspaces
                co_root = base_config_root.parent
                workspace_root = co_root / "clients" / client_id / "workspaces"
            else:
                workspace_root = base_config_root

        self.workspace_root = workspace_root
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def _target_dir_name(self, target: str) -> str:
        """Convert target to a safe directory name."""
        # Replace characters invalid in directory names
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
        return safe[:100]  # Limit length

    def create_workspace(self, target: str) -> WorkspacePaths:
        """Create a workspace for the target, return paths.

        If workspace already exists, returns existing paths.
        """
        dir_name = self._target_dir_name(target)
        root = self.workspace_root / dir_name
        paths = WorkspacePaths.from_root(root)
        paths.ensure_exists()
        return paths

    def get_workspace(self, target: str) -> WorkspacePaths:
        """Get workspace paths for target.

        Creates workspace if it doesn't exist.
        """
        return self.create_workspace(target)

    def save_checkpoint(self, target: str, state: dict[str, Any]) -> None:
        """Save scan state to checkpoint file.

        Args:
            target: Target being scanned.
            state: Dict containing completed plugins, current stage, etc.
        """
        paths = self.get_workspace(target)
        state["_saved_at"] = datetime.utcnow().isoformat()
        try:
            with paths.checkpoint_file.open("w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, default=str)
        except OSError as e:
            raise WorkspaceError(f"Failed to save checkpoint for {target}: {e}") from e

    def load_checkpoint(self, target: str) -> Optional[dict[str, Any]]:
        """Load checkpoint state for target.

        Returns:
            Dict with saved state, or None if no checkpoint exists.
        """
        paths = self.get_workspace(target)
        if not paths.checkpoint_file.exists():
            return None
        try:
            with paths.checkpoint_file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def clear_checkpoint(self, target: str) -> None:
        """Delete checkpoint file for target."""
        paths = self.get_workspace(target)
        if paths.checkpoint_file.exists():
            paths.checkpoint_file.unlink()

    def list_workspaces(self) -> list[WorkspaceSummary]:
        """List all existing workspaces with summary information."""
        summaries: list[WorkspaceSummary] = []

        if not self.workspace_root.exists():
            return summaries

        for entry in self.workspace_root.iterdir():
            if not entry.is_dir():
                continue

            paths = WorkspacePaths.from_root(entry)

            # Get timestamps
            try:
                stat = entry.stat()
                created_at = datetime.fromtimestamp(stat.st_ctime)
                last_modified = datetime.fromtimestamp(stat.st_mtime)
            except OSError:
                created_at = None
                last_modified = None

            raw_count = len(list(paths.raw.glob("*"))) if paths.raw.exists() else 0
            parsed_count = len(list(paths.parsed.glob("*"))) if paths.parsed.exists() else 0

            summaries.append(
                WorkspaceSummary(
                    target=entry.name,
                    root=entry,
                    created_at=created_at,
                    last_modified=last_modified,
                    has_checkpoint=paths.checkpoint_file.exists(),
                    raw_file_count=raw_count,
                    parsed_file_count=parsed_count,
                )
            )

        return sorted(summaries, key=lambda s: s.last_modified or datetime.min, reverse=True)
