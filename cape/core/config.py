"""Configuration system for CAPE.

Uses pydantic-settings. Environment variables with CO_ prefix override file values.
Config file: ~/.cape/config.yaml
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_workspace_root() -> Path:
    return Path.home() / ".cape" / "workspaces"


def _default_log_file() -> Path:
    return Path.home() / ".cape" / "logs" / "cape.log"


def _default_audit_log() -> Path:
    return Path.home() / ".cape" / "logs" / "audit.log"


def _default_db_url() -> str:
    db_path = Path.home() / ".cape" / "db" / "cape.db"
    return f"sqlite:///{db_path}"


def _default_kb_dir() -> Path:
    return Path(__file__).parent.parent / "show" / "knowledge"


def _default_templates_dir() -> Path:
    return Path(__file__).parent.parent / "reports" / "templates"


class Config(BaseSettings):
    """Global configuration for CAPE.

    Values are read from ~/.cape/config.yaml and can be
    overridden by environment variables prefixed with CO_.
    """

    # Note: ~/.cape/config.yaml is plain YAML, not a dotenv file, so it is
    # loaded explicitly (see get_config() below) rather than via pydantic-
    # settings' env_file mechanism, which expects KEY=VALUE lines.
    model_config = SettingsConfigDict(
        env_prefix="CAPE_",
        extra="ignore",
    )

    framework_name: str = "CAPE"
    db_url: str = _default_db_url()
    workspace_root: Path = Path.home() / ".cape" / "workspaces"
    log_level: str = "INFO"
    log_file: Path = Path.home() / ".cape" / "logs" / "cape.log"
    audit_log_file: Path = Path.home() / ".cape" / "logs" / "audit.log"
    default_scan_timeout: int = 3600
    default_plugin_timeout: int = 300
    max_parallel_plugins: int = 4
    enable_openvas: bool = False
    report_templates_dir: Path = (
        Path(__file__).parent.parent / "reports" / "templates"
    )
    kb_dir: Path = Path(__file__).parent.parent / "show" / "knowledge"
    # CAPE multi-tenant client isolation: set per-session via 'cape clients use'
    # or directly via the CAPE_CLIENT_ID environment variable.
    current_client: Optional[str] = Field(default=None, validation_alias="CAPE_CLIENT_ID")

    # --- Configuration Manager settings (set via the TUI "Configuration"
    # menu, persisted to ~/.cape/config.yaml) ---
    # Degree/intensity of scanning: light | normal | aggressive. Read by
    # scan plugins (e.g. nmap) to pick timing templates and flags.
    scan_intensity: str = "normal"
    # tool name -> explicit path to its binary, overriding PATH lookup.
    tool_paths: dict[str, str] = Field(default_factory=dict)
    # tool name -> enabled/disabled. Missing entries default to enabled.
    enabled_tools: dict[str, bool] = Field(default_factory=dict)

    # --- AI-assisted explainability & remediation narration (Pillar A+) ---
    # Deliberately scoped to `explain`/remediation narration only — never
    # attack planning or execution, which stay fully deterministic. Read
    # from GOOGLE_AI_API_KEY / GEMINI_API_KEY first (matching Google's own
    # SDK convention), falling back to CAPE_GOOGLE_AI_API_KEY / this field
    # so it can also live in ~/.cape/config.yaml if the user prefers that.
    google_ai_api_key: Optional[str] = Field(default=None, validation_alias="CAPE_GOOGLE_AI_API_KEY")
    ai_model: str = "gemini-2.5-flash"
    ai_narration_enabled: bool = True

    @field_validator("workspace_root", "log_file", "audit_log_file", mode="before")
    @classmethod
    def expand_paths(cls, v: Any) -> Path:
        """Expand ~ in paths."""
        return Path(str(v)).expanduser()

    def ensure_dirs(self) -> None:
        """Create all required directories."""
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.audit_log_file.parent.mkdir(parents=True, exist_ok=True)
        db_path = Path(self.db_url.replace("sqlite:///", ""))
        db_path.parent.mkdir(parents=True, exist_ok=True)


_config_instance: Optional[Config] = None

_SETTINGS_FILE = Path.home() / ".cape" / "config.yaml"
_SETTINGS_KEYS = ("scan_intensity", "tool_paths", "enabled_tools")


def get_config() -> Config:
    """Get or create the global Config singleton.

    Settings saved by the Configuration Manager (scan_intensity,
    tool_paths, enabled_tools) are layered on top of the defaults from
    ~/.cape/config.yaml, since those are plain YAML and don't reliably
    round-trip through pydantic-settings' dotenv-style env_file loading.
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
        saved = load_yaml_config(_SETTINGS_FILE)
        for key in _SETTINGS_KEYS:
            if key in saved:
                setattr(_config_instance, key, saved[key])
        _config_instance.ensure_dirs()
    return _config_instance


def update_settings(**kwargs: Any) -> Config:
    """Update one or more Configuration Manager settings and persist them.

    Only accepts the keys in _SETTINGS_KEYS. Merges with whatever is
    already saved in ~/.cape/config.yaml rather than overwriting it.
    """
    cfg = get_config()
    saved = load_yaml_config(_SETTINGS_FILE)
    for key, value in kwargs.items():
        if key not in _SETTINGS_KEYS:
            raise ValueError(f"Unknown setting: {key}")
        setattr(cfg, key, value)
        saved[key] = value
    save_yaml_config(_SETTINGS_FILE, saved)
    return cfg


def load_yaml_config(path: Path) -> dict[str, Any]:
    """Load a YAML config file, returning empty dict if not found."""
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def save_yaml_config(path: Path, data: dict[str, Any]) -> None:
    """Save a dict as YAML config file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
