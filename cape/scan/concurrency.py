"""Concurrency planning and execution for scan engine.

Implements SEQUENTIAL, THREAD_POOL, PROCESS_POOL, and ASYNC concurrency modes.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from cape.shared.enums import ConcurrencyMode
from cape.shared.finding import Finding

logger = logging.getLogger(__name__)


@dataclass
class PluginGroup:
    """A group of plugins sharing a concurrency mode."""

    name: str
    plugins: list[str]
    concurrency: ConcurrencyMode
    max_workers: int = 4
    timeout: Optional[int] = None


@dataclass
class ExecutionPlan:
    """Ordered list of plugin groups with their concurrency modes."""

    groups: list[PluginGroup] = field(default_factory=list)
    total_timeout: int = 3600

    def add_group(self, group: PluginGroup) -> None:
        """Add a plugin group to the plan."""
        self.groups.append(group)


class ConcurrencyPlanner:
    """Reads scan profile and builds an ExecutionPlan.

    Determines threading strategy per plugin group based on profile
    declarations.
    """

    def build_plan(self, profile_config: dict[str, Any], total_timeout: int = 3600) -> ExecutionPlan:
        """Build an ExecutionPlan from a profile YAML config dict.

        Args:
            profile_config: Parsed profile YAML dict.
            total_timeout: Overall scan timeout in seconds.

        Returns:
            ExecutionPlan with ordered groups.
        """
        plan = ExecutionPlan(total_timeout=total_timeout)

        plugin_groups = profile_config.get("plugin_groups", [])
        for group_config in plugin_groups:
            mode_str = group_config.get("concurrency", "sequential")
            try:
                mode = ConcurrencyMode(mode_str)
            except ValueError:
                logger.warning(f"Unknown concurrency mode '{mode_str}', using SEQUENTIAL")
                mode = ConcurrencyMode.SEQUENTIAL

            group = PluginGroup(
                name=group_config.get("name", "unnamed"),
                plugins=group_config.get("plugins", []),
                concurrency=mode,
                max_workers=group_config.get("max_workers", 4),
                timeout=group_config.get("timeout"),
            )
            plan.add_group(group)

        # If no plugin_groups defined, put all plugins in sequential group
        if not plan.groups:
            all_plugins = profile_config.get("plugins", [])
            if all_plugins:
                plan.add_group(PluginGroup(
                    name="default",
                    plugins=all_plugins,
                    concurrency=ConcurrencyMode.SEQUENTIAL,
                ))

        return plan


class ExecutionPipeline:
    """Executes plugins according to an ExecutionPlan.

    Dispatches plugin runs using the appropriate concurrency mode.
    """

    def __init__(self, max_workers: int = 4) -> None:
        """Initialize pipeline with max worker count."""
        self.max_workers = max_workers

    def run_group(
        self,
        group: PluginGroup,
        plugin_runners: list[Callable[[], list[Finding]]],
    ) -> list[Finding]:
        """Run a group of plugin runners using the group's concurrency mode.

        Args:
            group: Plugin group configuration.
            plugin_runners: List of callables that each return list[Finding].

        Returns:
            Flattened list of all findings from all plugins in the group.
        """
        if not plugin_runners:
            return []

        if group.concurrency == ConcurrencyMode.SEQUENTIAL:
            return self._run_sequential(plugin_runners)
        elif group.concurrency == ConcurrencyMode.THREAD_POOL:
            return self._run_thread_pool(plugin_runners, group.max_workers)
        elif group.concurrency == ConcurrencyMode.PROCESS_POOL:
            return self._run_process_pool(plugin_runners, group.max_workers)
        elif group.concurrency == ConcurrencyMode.ASYNC:
            return self._run_async(plugin_runners)
        else:
            return self._run_sequential(plugin_runners)

    def _run_sequential(
        self, runners: list[Callable[[], list[Finding]]]
    ) -> list[Finding]:
        """Run plugins one at a time."""
        results: list[Finding] = []
        for runner in runners:
            try:
                findings = runner()
                results.extend(findings)
            except Exception as e:
                logger.error(f"Plugin runner error (sequential): {e}", exc_info=True)
        return results

    def _run_thread_pool(
        self, runners: list[Callable[[], list[Finding]]], max_workers: int
    ) -> list[Finding]:
        """Run plugins using a thread pool (I/O-bound: nmap, nikto)."""
        results: list[Finding] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(runner): runner for runner in runners}
            for future in concurrent.futures.as_completed(futures):
                try:
                    findings = future.result()
                    results.extend(findings)
                except Exception as e:
                    logger.error(f"Plugin runner error (thread_pool): {e}", exc_info=True)
        return results

    def _run_process_pool(
        self, runners: list[Callable[[], list[Finding]]], max_workers: int
    ) -> list[Finding]:
        """Run plugins using a process pool (CPU-bound: parsers).

        Falls back to thread pool if process pool is unavailable.
        """
        # Note: process pool requires picklable callables
        # We fall back to thread pool since lambdas aren't picklable
        logger.debug("Process pool requested, using thread pool (callables not picklable)")
        return self._run_thread_pool(runners, max_workers)

    def _run_async(
        self, runners: list[Callable[[], list[Finding]]]
    ) -> list[Finding]:
        """Run lightweight checks using asyncio (banner grabs, nc checks)."""
        results: list[Finding] = []

        async def _gather() -> None:
            loop = asyncio.get_event_loop()
            tasks = [loop.run_in_executor(None, runner) for runner in runners]
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for item in completed:
                if isinstance(item, Exception):
                    logger.error(f"Async runner error: {item}")
                elif isinstance(item, list):
                    results.extend(item)

        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(_gather())
            loop.close()
        except Exception as e:
            logger.error(f"Async execution error: {e}")
            # Fallback to sequential
            return self._run_sequential(runners)

        return results
