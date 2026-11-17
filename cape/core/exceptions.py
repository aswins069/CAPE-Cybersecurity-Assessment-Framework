"""Custom exceptions for CAPE."""


class CyberOrchestratorError(Exception):
    """Base exception for all framework errors."""


class DependencyMissingError(CyberOrchestratorError):
    """Raised when a required tool is not installed."""

    def __init__(self, tool: str, install_hint: str = "") -> None:
        self.tool = tool
        super().__init__(
            f"Required tool '{tool}' is not installed. {install_hint}"
        )


class PermissionError(CyberOrchestratorError):
    """Raised when required permissions are missing."""

    def __init__(self, permission: str, tool: str) -> None:
        self.permission = permission
        self.tool = tool
        super().__init__(
            f"Tool '{tool}' requires {permission} permissions. "
            "Try running with sudo or setting appropriate capabilities."
        )


class ParseError(CyberOrchestratorError):
    """Raised when a parser fails to parse tool output."""

    def __init__(self, tool: str, reason: str, raw_file: str = "") -> None:
        self.tool = tool
        self.reason = reason
        super().__init__(
            f"Failed to parse output from '{tool}': {reason}"
            + (f" (file: {raw_file})" if raw_file else "")
        )


class WorkspaceError(CyberOrchestratorError):
    """Raised when workspace operations fail."""


class ConfigError(CyberOrchestratorError):
    """Raised when configuration is invalid."""


class PluginError(CyberOrchestratorError):
    """Raised when a plugin encounters an error."""

    def __init__(self, plugin: str, reason: str) -> None:
        self.plugin = plugin
        super().__init__(f"Plugin '{plugin}' error: {reason}")


class ScanTimeoutError(CyberOrchestratorError):
    """Raised when a scan exceeds its timeout."""

    def __init__(self, tool: str, timeout: int) -> None:
        self.tool = tool
        self.timeout = timeout
        super().__init__(
            f"Tool '{tool}' timed out after {timeout}s. "
            "Partial results were saved."
        )


class TargetValidationError(CyberOrchestratorError):
    """Raised when a target fails format validation."""

    def __init__(self, target: str) -> None:
        self.target = target
        super().__init__(
            f"Invalid target format: '{target}'. "
            "Expected: hostname, IP, CIDR, or URL."
        )


class DatabaseError(CyberOrchestratorError):
    """Raised when a database operation fails."""


class ReportError(CyberOrchestratorError):
    """Raised when report generation fails."""


class AttackModuleError(CyberOrchestratorError):
    """Raised when an attack module fails."""


class SessionError(CyberOrchestratorError):
    """Raised when session state transitions fail."""
