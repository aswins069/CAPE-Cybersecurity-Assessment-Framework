"""Shared enumerations for CAPE."""
from enum import Enum


class FindingCategory(str, Enum):
    """Categories of security findings."""
    PORT = "PORT"
    SERVICE = "SERVICE"
    VULNERABILITY = "VULNERABILITY"
    HEADER = "HEADER"
    DIRECTORY = "DIRECTORY"
    CREDENTIAL_HINT = "CREDENTIAL_HINT"
    CMS = "CMS"
    API_ENDPOINT = "API_ENDPOINT"
    WIRELESS = "WIRELESS"
    SMB = "SMB"


class Severity(str, Enum):
    """Finding severity levels."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackDomain(str, Enum):
    """Domains of attack assessment."""
    WEB = "WEB"
    NETWORK = "NETWORK"
    SMB = "SMB"
    CMS = "CMS"
    API = "API"
    AUTH = "AUTH"
    WIRELESS = "WIRELESS"


class SessionState(str, Enum):
    """Attack session state machine states."""
    IDLE = "IDLE"
    LOADED = "LOADED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"


class PermissionType(str, Enum):
    """Required permission types for plugins."""
    ROOT = "ROOT"
    NETWORK = "NETWORK"
    NONE = "NONE"


class CheckStatus(str, Enum):
    """Doctor check result statuses."""
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


class ConditionOp(str, Enum):
    """Operators for rule conditions."""
    EQUALS = "EQUALS"
    CONTAINS = "CONTAINS"
    REGEX = "REGEX"
    IN = "IN"
    GT = "GT"
    LT = "LT"
    EXISTS = "EXISTS"


class ConcurrencyMode(str, Enum):
    """Concurrency modes for scan execution."""
    SEQUENTIAL = "sequential"
    THREAD_POOL = "thread_pool"
    PROCESS_POOL = "process_pool"
    ASYNC = "async"


class ScanStatus(str, Enum):
    """Scan execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PAUSED = "PAUSED"


class EventType(str, Enum):
    """Audit log event types."""
    SCAN_START = "SCAN_START"
    SCAN_COMPLETE = "SCAN_COMPLETE"
    SCAN_FAIL = "SCAN_FAIL"
    SCOPE_AUTHORIZED = "SCOPE_AUTHORIZED"
    SCOPE_REFUSED = "SCOPE_REFUSED"
    ATTACK_START = "ATTACK_START"
    ATTACK_COMPLETE = "ATTACK_COMPLETE"
    ATTACK_ABORT = "ATTACK_ABORT"
    REPORT_GENERATED = "REPORT_GENERATED"
    TOOL_EXECUTE = "TOOL_EXECUTE"
    SESSION_RESUME = "SESSION_RESUME"
