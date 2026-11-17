"""Scan engine - main orchestration for target scanning.

Coordinates profile loading, plugin execution, finding persistence.
"""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

import yaml

from cape.core.audit_logger import get_audit_logger
from cape.core.config import get_config
from cape.core.tool_resolver import is_tool_enabled
from cape.core.workspace import WorkspaceManager, WorkspacePaths
from cape.scan.concurrency import ConcurrencyPlanner, ExecutionPipeline
from cape.scan.models import ScanResult
from cape.scan.plugins.base import PluginOptions
from cape.shared.finding import Finding
from cape.shared.enums import ScanStatus

logger = logging.getLogger(__name__)

PROFILES_DIR = Path(__file__).parent / "profiles"


class ScanEngine:
    """Main scan engine that orchestrates plugin execution.

    Loads scan profiles, resolves plugins, manages concurrency,
    and persists findings to the workspace and database.
    """

    def __init__(
        self,
        workspace_manager: Optional[WorkspaceManager] = None,
        profiles_dir: Optional[Path] = None,
    ) -> None:
        """Initialize scan engine."""
        self.workspace_manager = workspace_manager or WorkspaceManager()
        self.profiles_dir = profiles_dir or PROFILES_DIR
        self.planner = ConcurrencyPlanner()
        self.pipeline = ExecutionPipeline()
        self._plugin_cache: dict[str, Any] = {}

    def load_profile(self, profile_name: str) -> dict[str, Any]:
        """Load a scan profile YAML file.

        Args:
            profile_name: Profile name (e.g., 'quick', 'web').

        Returns:
            Parsed profile dict.

        Raises:
            FileNotFoundError: If profile does not exist.
        """
        profile_file = self.profiles_dir / f"{profile_name}.yaml"
        if not profile_file.exists():
            raise FileNotFoundError(
                f"Profile '{profile_name}' not found at {profile_file}. "
                f"Available: {self.list_profiles()}"
            )
        with profile_file.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def list_profiles(self) -> list[str]:
        """Return list of available scan profile names."""
        if not self.profiles_dir.exists():
            return []
        return [f.stem for f in self.profiles_dir.glob("*.yaml")]

    def _get_plugin(self, plugin_name: str) -> Optional[Any]:
        """Get an instantiated plugin by name from the registry or built-ins."""
        if plugin_name in self._plugin_cache:
            return self._plugin_cache[plugin_name]

        plugin_map = {
            "nmap": lambda: self._import_plugin("cape.scan.plugins.nmap", "NmapPlugin"),
            "masscan": lambda: self._import_plugin("cape.scan.plugins.masscan", "MasscanPlugin"),
            "nikto": lambda: self._import_plugin("cape.scan.plugins.nikto", "NiktoPlugin"),
            "whatweb": lambda: self._import_plugin("cape.scan.plugins.whatweb", "WhatWebPlugin"),
            "gobuster": lambda: self._import_plugin("cape.scan.plugins.gobuster", "GobusterPlugin"),
            "dirb": lambda: self._import_plugin("cape.scan.plugins.wpscan", "DirbPlugin"),
            "wpscan": lambda: self._import_plugin("cape.scan.plugins.wpscan", "WpscanPlugin"),
            "enum4linux": lambda: self._import_plugin("cape.scan.plugins.wpscan", "Enum4linuxPlugin"),
            "snmp-check": lambda: self._import_plugin("cape.scan.plugins.wpscan", "SnmpCheckPlugin"),
            "zap": lambda: self._import_plugin("cape.scan.plugins.zap", "ZapPlugin"),
        }

        factory = plugin_map.get(plugin_name)
        if factory:
            try:
                plugin = factory()()
                self._plugin_cache[plugin_name] = plugin
                return plugin
            except Exception as e:
                logger.error(f"Failed to load plugin '{plugin_name}': {e}")
                return None

        return None

    def _import_plugin(self, module_path: str, class_name: str) -> type:
        """Dynamically import a plugin class."""
        import importlib
        module = importlib.import_module(module_path)
        return getattr(module, class_name)

    def run_scan(
        self,
        target: str,
        profile_name: str,
        scope_token: str,
        operator: str,
        scan_id: Optional[UUID] = None,
        resume: bool = False,
        dry_run: bool = False,
        timeout_override: Optional[int] = None,
        verbose: bool = False,
        progress_callback: Optional[Any] = None,
    ) -> ScanResult:
        """Run a full scan against a target using the specified profile.

        Args:
            target: Validated target string.
            profile_name: Profile name to use.
            scope_token: Session token used to correlate this run's audit-log entries.
            operator: Operator name for audit logging.
            scan_id: Optional UUID for this scan.
            resume: If True, skip completed plugins from checkpoint.
            dry_run: If True, show plan without executing.
            timeout_override: Override profile's scan timeout.
            verbose: If True, log tool output live.
            progress_callback: Optional callable(plugin_name, status).

        Returns:
            ScanResult with all findings.
        """
        if scan_id is None:
            scan_id = uuid.uuid4()

        audit = get_audit_logger()
        workspace = self.workspace_manager.get_workspace(target)
        started_at = datetime.utcnow()

        audit.log_scan_start(target, operator, profile_name)
        logger.info(f"Starting scan: target={target}, profile={profile_name}, scan_id={scan_id}")

        try:
            profile_config = self.load_profile(profile_name)
        except FileNotFoundError as e:
            audit.log_scan_fail(target, operator, str(e))
            return ScanResult(
                scan_id=scan_id,
                target=target,
                profile=profile_name,
                status=ScanStatus.FAILED,
                findings=[],
                started_at=started_at,
                error=str(e),
            )

        cfg = get_config()
        scan_timeout = timeout_override or profile_config.get(
            "scan_timeout", cfg.default_scan_timeout
        )
        plugin_timeout = profile_config.get("plugin_timeout", cfg.default_plugin_timeout)

        # Load checkpoint if resuming
        completed_plugins: set[str] = set()
        if resume:
            checkpoint = self.workspace_manager.load_checkpoint(target)
            if checkpoint:
                completed_plugins = set(checkpoint.get("completed_plugins", []))
                logger.info(f"Resuming scan, skipping: {completed_plugins}")

        # Build execution plan
        plan = self.planner.build_plan(profile_config, total_timeout=scan_timeout)

        if dry_run:
            logger.info("DRY RUN - would execute:")
            for group in plan.groups:
                for plugin_name in group.plugins:
                    logger.info(f"  [{group.concurrency.value}] {plugin_name}")
            return ScanResult(
                scan_id=scan_id,
                target=target,
                profile=profile_name,
                status=ScanStatus.COMPLETED,
                findings=[],
                started_at=started_at,
                completed_at=datetime.utcnow(),
                dry_run=True,
            )

        # Check for inter-stage dependencies
        # (e.g., only run smb plugins if smb ports found in recon)
        found_services: set[str] = set()
        all_findings: list[Finding] = []

        scan_start = time.time()

        for group in plan.groups:
            # Check overall timeout
            if time.time() - scan_start > scan_timeout:
                logger.warning(f"Scan timeout reached ({scan_timeout}s)")
                break

            group_plugins = [
                p for p in group.plugins
                if p not in completed_plugins
                and self._should_run_plugin(p, found_services, profile_config)
            ]

            if not group_plugins:
                continue

            logger.info(f"Running group '{group.name}': {group_plugins} [{group.concurrency.value}]")

            # Build runners for this group
            runners = []
            for plugin_name in group_plugins:
                plugin = self._get_plugin(plugin_name)
                if plugin is None:
                    logger.warning(f"Plugin '{plugin_name}' not available, skipping")
                    continue

                options = self._build_plugin_options(plugin_name, profile_config, target)
                p_timeout = profile_config.get("plugins", {}).get(
                    plugin_name, {}
                ).get("timeout", plugin_timeout)

                def make_runner(p=plugin, t=target, w=workspace, o=options, to=p_timeout, sid=scan_id):
                    def runner() -> list[Finding]:
                        if progress_callback:
                            progress_callback(p.name, "running")
                        findings = p.run(t, w, o, to, sid)
                        if progress_callback:
                            progress_callback(p.name, "done")
                        return findings
                    return runner

                runners.append(make_runner())

            group_findings = self.pipeline.run_group(group, runners)
            all_findings.extend(group_findings)

            # Update found services for conditional execution
            for f in group_findings:
                if f.service:
                    found_services.add(f.service.lower())

            # Update completed plugins in checkpoint
            for plugin_name in group_plugins:
                completed_plugins.add(plugin_name)

            # Save checkpoint
            self.workspace_manager.save_checkpoint(target, {
                "completed_plugins": list(completed_plugins),
                "scan_id": str(scan_id),
                "profile": profile_name,
            })

        # Persist findings to database
        self._persist_findings(all_findings, target, str(scan_id), profile_name)

        completed_at = datetime.utcnow()
        self.workspace_manager.clear_checkpoint(target)

        audit.log_scan_complete(target, operator, len(all_findings))

        return ScanResult(
            scan_id=scan_id,
            target=target,
            profile=profile_name,
            status=ScanStatus.COMPLETED,
            findings=all_findings,
            started_at=started_at,
            completed_at=completed_at,
        )

    def _should_run_plugin(
        self,
        plugin_name: str,
        found_services: set[str],
        profile_config: dict[str, Any],
    ) -> bool:
        """Check conditional execution requirements.

        Args:
            plugin_name: Plugin to check.
            found_services: Services discovered so far.
            profile_config: Profile configuration dict.

        Returns:
            True if plugin should run.
        """
        if not is_tool_enabled(plugin_name):
            logger.info(f"Skipping {plugin_name}: disabled in Configuration Manager")
            return False

        requires = profile_config.get("conditionals", {}).get(plugin_name, {}).get(
            "requires_service", None
        )
        if requires and requires not in found_services:
            logger.info(f"Skipping {plugin_name}: requires service '{requires}' not found yet")
            return False
        return True

    def _build_plugin_options(
        self,
        plugin_name: str,
        profile_config: dict[str, Any],
        target: str,
    ) -> PluginOptions:
        """Build plugin-specific options from profile config."""
        plugin_cfg = profile_config.get("plugins", {}).get(plugin_name, {})
        return PluginOptions(
            extra_args=plugin_cfg.get("extra_args", []),
            wordlist=plugin_cfg.get("wordlist"),
            ports=plugin_cfg.get("ports"),
            rate=plugin_cfg.get("rate"),
            custom={
                "profile": profile_config.get("name", "unknown"),
                "scan_intensity": get_config().scan_intensity,
                **plugin_cfg.get("custom", {}),
            },
        )

    def _persist_findings(
        self,
        findings: list[Finding],
        target: str,
        scan_id: str,
        profile_name: str = "unknown",
    ) -> None:
        """Persist findings to the database."""
        try:
            from cape.db.session import db_session
            from cape.db.models import FindingModel, Scan, Target
            from datetime import datetime as dt

            with db_session() as session:
                # Ensure target exists
                target_obj = session.query(Target).filter_by(
                    hostname_or_ip=target
                ).first()
                if not target_obj:
                    target_obj = Target(
                        hostname_or_ip=target,
                        created_at=dt.utcnow(),
                    )
                    session.add(target_obj)
                    session.flush()

                target_obj.last_scanned_at = dt.utcnow()

                # Ensure a Scan row exists for this scan_id before findings
                # reference it - findings.scan_id has a FOREIGN KEY to
                # scans.id, so inserting findings without this row first
                # fails the constraint and silently drops every finding.
                scan_row = session.get(Scan, scan_id)
                if not scan_row:
                    session.add(Scan(
                        id=scan_id,
                        target_id=target_obj.id,
                        profile=profile_name,
                        status="COMPLETED",
                        started_at=dt.utcnow(),
                        completed_at=dt.utcnow(),
                    ))
                    session.flush()

                for finding in findings:
                    fm = FindingModel(
                        id=str(finding.id),
                        target=finding.target,
                        target_id=target_obj.id,
                        scan_id=scan_id,
                        source_tool=finding.source_tool,
                        scan_profile=finding.scan_profile,
                        timestamp=finding.timestamp,
                        category=finding.category.value,
                        severity=finding.severity.value,
                        confidence=finding.confidence,
                        title=finding.title,
                        description=finding.description,
                        evidence=finding.evidence,
                        host=finding.host,
                        port=finding.port,
                        protocol=finding.protocol,
                        service=finding.service,
                        cve_ids=finding.cve_ids,
                        cvss_score=finding.cvss_score,
                        cvss_vector=finding.cvss_vector,
                        remediation=finding.remediation,
                        references=finding.references,
                        raw_output_file=str(finding.raw_output_file) if finding.raw_output_file else None,
                        tags=finding.tags,
                        extra=finding.extra,
                    )
                    session.merge(fm)

                    # CAPE Pillar C: record this finding's drift fingerprint
                    # so cape diff can match it across future scans by
                    # semantic identity rather than UUID.
                    try:
                        from cape.show.drift import ScanDiffer
                        from cape.db.models import ScanFingerprint

                        fingerprint = ScanDiffer()._fingerprint(finding)
                        session.add(ScanFingerprint(
                            scan_id=scan_id,
                            finding_id=str(finding.id),
                            fingerprint=fingerprint,
                            created_at=dt.utcnow(),
                        ))
                    except Exception as fp_err:
                        logger.error(f"Failed to record scan fingerprint: {fp_err}")

        except Exception as e:
            logger.error(f"Failed to persist findings: {e}", exc_info=True)
