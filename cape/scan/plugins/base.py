"""Base plugin class for all scan plugins.

All scan plugins inherit from BasePlugin and implement its abstract methods.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from cape.shared.enums import PermissionType
from cape.shared.finding import Finding, RawParsedItem

logger = logging.getLogger(__name__)


@dataclass
class DependencyResult:
    """Result of a plugin dependency check."""

    installed: bool
    version: Optional[str] = None
    path: Optional[str] = None
    missing: Optional[str] = None


@dataclass
class PermissionResult:
    """Result of a plugin permission check."""

    sufficient: bool
    required: list[PermissionType] = None  # type: ignore
    message: str = ""

    def __post_init__(self) -> None:
        if self.required is None:
            self.required = []


@dataclass
class ExecutionResult:
    """Result of executing a plugin tool."""

    stdout: str
    stderr: str
    returncode: int
    raw_file_path: Optional[Path]
    duration: float
    timed_out: bool = False
    partial: bool = False


@dataclass
class PluginOptions:
    """Options passed to a plugin during execution."""

    extra_args: list[str] = None  # type: ignore
    wordlist: Optional[str] = None
    ports: Optional[str] = None
    rate: Optional[int] = None
    custom: dict[str, Any] = None  # type: ignore

    def __post_init__(self) -> None:
        if self.extra_args is None:
            self.extra_args = []
        if self.custom is None:
            self.custom = {}


@dataclass
class StepResult:
    """Result of executing a single workflow step."""

    step_id: str
    success: bool
    output: str
    error: str = ""
    findings: list[Finding] = None  # type: ignore
    duration: float = 0.0

    def __post_init__(self) -> None:
        if self.findings is None:
            self.findings = []


class BasePlugin(ABC):
    """Abstract base class for all scan plugins.

    Each plugin wraps a single external security tool.
    """

    name: str = ""
    version: str = "1.0.0"
    required_tool: str = ""
    required_permissions: list[PermissionType] = []
    supported_profiles: list[str] = []

    @abstractmethod
    def check_dependency(self) -> DependencyResult:
        """Check if the required tool is installed.

        Returns:
            DependencyResult with installed status, version, and path.
        """

    @abstractmethod
    def check_permissions(self) -> PermissionResult:
        """Check if required permissions are available.

        Returns:
            PermissionResult indicating if permissions are sufficient.
        """

    @abstractmethod
    def build_command(self, target: str, options: PluginOptions) -> list[str]:
        """Build the argv list for tool execution.

        Args:
            target: Validated target string.
            options: Plugin-specific options.

        Returns:
            List of argv strings. NEVER a shell string.
        """

    @abstractmethod
    def execute(
        self,
        target: str,
        workspace: Any,
        options: PluginOptions,
        timeout: int,
    ) -> ExecutionResult:
        """Execute the tool and save raw output.

        Args:
            target: Validated target string.
            workspace: WorkspacePaths for this target.
            options: Plugin options.
            timeout: Execution timeout in seconds.

        Returns:
            ExecutionResult with stdout, stderr, returncode, raw_file_path.
        """

    @abstractmethod
    def parse_output(self, raw_file: Path) -> list[RawParsedItem]:
        """Parse raw tool output into intermediate items.

        Args:
            raw_file: Path to raw output file.

        Returns:
            List of RawParsedItem instances.
        """

    @abstractmethod
    def normalize_findings(
        self,
        items: list[RawParsedItem],
        target: str,
        scan_id: UUID,
    ) -> list[Finding]:
        """Normalize parsed items into Finding instances.

        Args:
            items: List of RawParsedItem from parse_output.
            target: Target string.
            scan_id: ID of the current scan.

        Returns:
            List of normalized Finding instances.
        """

    def run(
        self,
        target: str,
        workspace: Any,
        options: Optional[PluginOptions] = None,
        timeout: int = 300,
        scan_id: Optional[UUID] = None,
    ) -> list[Finding]:
        """Orchestrate: execute → parse → normalize → return.

        Catches and logs all exceptions without propagating (plugin isolation).

        Args:
            target: Validated target string.
            workspace: WorkspacePaths instance.
            options: Plugin options, defaults to empty PluginOptions.
            timeout: Execution timeout in seconds.
            scan_id: Optional scan UUID for finding metadata.

        Returns:
            List of Finding instances, may be empty on error.
        """
        if options is None:
            options = PluginOptions()

        if scan_id is None:
            import uuid
            scan_id = uuid.uuid4()

        start = time.time()
        logger.info(f"[{self.name}] Starting against {target}")

        try:
            dep = self.check_dependency()
            if not dep.installed:
                logger.warning(f"[{self.name}] Tool not installed: {dep.missing}")
                return []

            perm = self.check_permissions()
            if not perm.sufficient:
                logger.warning(f"[{self.name}] Insufficient permissions: {perm.message}")
                if getattr(self, "skip_on_insufficient_permissions", False):
                    logger.warning(
                        f"[{self.name}] Skipped. Re-run with root, e.g. "
                        f"'sudo -E env \"PATH=$PATH\" cape ...'"
                    )
                    return []

            result = self.execute(target, workspace, options, timeout)

            if result.timed_out:
                logger.warning(f"[{self.name}] Timed out after {timeout}s, using partial output")

            if not result.raw_file_path or not result.raw_file_path.exists():
                logger.warning(f"[{self.name}] No output file produced")
                return []

            items = self.parse_output(result.raw_file_path)
            findings = self.normalize_findings(items, target, scan_id)

            duration = time.time() - start
            logger.info(f"[{self.name}] Completed in {duration:.1f}s, {len(findings)} findings")

            return findings

        except Exception as e:
            logger.error(f"[{self.name}] Unhandled error: {e}", exc_info=True)
            return []

    def _run_subprocess(
        self,
        argv: list[str],
        cwd: Path,
        timeout: int,
        env: Optional[dict] = None,
    ) -> ExecutionResult:
        """Run a subprocess safely without shell=True.

        Args:
            argv: Command and arguments list.
            cwd: Working directory.
            timeout: Timeout in seconds.
            env: Optional environment variables.

        Returns:
            ExecutionResult with stdout, stderr, returncode, and duration.
        """
        from cape.core.audit_logger import get_audit_logger
        from cape.core.tool_resolver import resolve_tool_path
        audit = get_audit_logger()

        # Configuration Manager tool-path override: if the operator has
        # pointed this tool at a custom binary, use it for the actual
        # execution too (build_command() still just names the tool).
        if argv:
            resolved = resolve_tool_path(argv[0])
            if resolved:
                argv = [resolved, *argv[1:]]

        audit.log_tool_execute(str(cwd), "system", argv)

        logger.debug(f"Executing: {' '.join(argv)}")
        start = time.time()

        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(cwd),
                env=env,
                shell=False,  # NEVER True
            )

            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                duration = time.time() - start
                return ExecutionResult(
                    stdout=stdout.decode("utf-8", errors="replace"),
                    stderr=stderr.decode("utf-8", errors="replace"),
                    returncode=proc.returncode,
                    raw_file_path=None,
                    duration=duration,
                )
            except subprocess.TimeoutExpired:
                # Graceful shutdown: SIGTERM, wait 5s, then SIGKILL
                proc.send_signal(signal.SIGTERM)
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()

                duration = time.time() - start
                return ExecutionResult(
                    stdout=stdout.decode("utf-8", errors="replace") if stdout else "",
                    stderr=stderr.decode("utf-8", errors="replace") if stderr else "",
                    returncode=proc.returncode or -1,
                    raw_file_path=None,
                    duration=duration,
                    timed_out=True,
                    partial=True,
                )

        except FileNotFoundError as e:
            return ExecutionResult(
                stdout="",
                stderr=str(e),
                returncode=-1,
                raw_file_path=None,
                duration=time.time() - start,
            )
