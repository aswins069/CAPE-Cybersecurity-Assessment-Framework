"""Shared constants for CAPE."""

APP_NAME = "CAPE"
APP_VERSION = "1.0.0"
CONFIG_DIR_NAME = ".cape"

# Severity weights for scoring
SEVERITY_WEIGHTS = {
    "INFO": 0.1,
    "LOW": 0.3,
    "MEDIUM": 0.5,
    "HIGH": 0.8,
    "CRITICAL": 1.0,
}

# Domain weights for opportunity scoring
DOMAIN_WEIGHTS = {
    "WEB": 1.0,
    "NETWORK": 0.9,
    "SMB": 1.0,
    "CMS": 0.85,
    "API": 0.95,
    "AUTH": 1.0,
    "WIRELESS": 0.8,
}

# Default timeouts (seconds)
DEFAULT_PLUGIN_TIMEOUT = 300
DEFAULT_SCAN_TIMEOUT = 3600
DEFAULT_GROUP_TIMEOUT_MULTIPLIER = 1.5

# Subprocess kill delays
SIGTERM_WAIT = 5

# Report formats
REPORT_FORMATS = ["json", "html", "pdf"]

# Known hardened SSH versions (not brute-force feasible)
HARDENED_SSH_VERSIONS = [
    "OpenSSH_8.9",
    "OpenSSH_9.0",
    "OpenSSH_9.1",
    "OpenSSH_9.2",
    "OpenSSH_9.3",
]

# Common default credentials services
DEFAULT_CRED_SERVICES = {
    21: ("ftp", "anonymous"),
    22: ("ssh", "root/root, admin/admin"),
    23: ("telnet", "admin/admin"),
    80: ("http", "admin/admin"),
    443: ("https", "admin/admin"),
    3306: ("mysql", "root/root"),
    5432: ("postgresql", "postgres/postgres"),
    6379: ("redis", "no auth"),
    27017: ("mongodb", "no auth"),
}

# MITRE ATT&CK base URL
MITRE_URL = "https://attack.mitre.org/techniques/"

# NVD CVE URL
NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail/"
