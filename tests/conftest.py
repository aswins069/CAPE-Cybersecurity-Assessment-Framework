"""Pytest configuration and shared fixtures for CAPE tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Return path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def nmap_fixture(fixtures_dir: Path) -> Path:
    """Return path to nmap sample XML fixture."""
    return fixtures_dir / "nmap" / "sample_scan.xml"


@pytest.fixture(scope="session")
def nikto_fixture(fixtures_dir: Path) -> Path:
    """Return path to nikto sample output fixture."""
    return fixtures_dir / "nikto" / "sample_output.txt"


@pytest.fixture(scope="session")
def whatweb_fixture(fixtures_dir: Path) -> Path:
    """Return path to whatweb sample JSON fixture."""
    return fixtures_dir / "whatweb" / "sample_output.json"


@pytest.fixture(scope="session")
def wpscan_fixture(fixtures_dir: Path) -> Path:
    """Return path to wpscan sample JSON fixture."""
    return fixtures_dir / "wpscan" / "sample_output.json"


@pytest.fixture
def memory_db():
    """Provide an in-memory SQLite database session."""
    from cape.db.session import get_memory_session
    session = get_memory_session()
    yield session
    session.close()


@pytest.fixture
def temp_workspace(tmp_path: Path):
    """Provide a temporary workspace manager."""
    from cape.core.workspace import WorkspaceManager
    return WorkspaceManager(workspace_root=tmp_path / "workspaces")


@pytest.fixture
def sample_finding():
    """Provide a sample Finding instance."""
    from cape.shared.finding import FindingFactory
    return FindingFactory.create()


@pytest.fixture
def sample_findings():
    """Provide a list of diverse sample findings."""
    from cape.shared.finding import FindingFactory
    from cape.shared.enums import FindingCategory, Severity
    return [
        FindingFactory.create(port=80, service="http", severity=Severity.INFO),
        FindingFactory.create(port=443, service="https", severity=Severity.INFO),
        FindingFactory.create(port=445, service="smb", category=FindingCategory.SMB, severity=Severity.HIGH,
                              tags=["smb", "signing"]),
        FindingFactory.create_vulnerability(cvss_score=9.8),
        FindingFactory.create(port=22, service="ssh", severity=Severity.LOW),
        FindingFactory.create(category=FindingCategory.CMS, severity=Severity.LOW,
                              tags=["wordpress", "cms"]),
    ]


# ===========================================================================
# CAPE test utilities — used by test_drift.py, test_audit_chain.py, test_clients.py
# ===========================================================================

@pytest.fixture
def cape_db():
    """Initialize a fresh in-memory SQLite DB for one test and tear it down after.

    Unlike the production `init_db()`, this never touches a real DB file
    on disk, and resets the global engine/session factory afterwards so
    tests don't leak state into each other.
    """
    import cape.db.session as db_session_module

    engine = db_session_module.init_db("sqlite:///:memory:")
    yield engine

    # Reset module globals so the next test (or get_engine()) re-initializes cleanly.
    db_session_module._engine = None
    db_session_module._SessionFactory = None


def make_scan_pair(target: str, session) -> tuple[str, str]:
    """Create two Scan rows (and their Target) for drift tests.

    Args:
        target: hostname/IP the scans belong to.
        session: an active SQLAlchemy Session.

    Returns:
        Tuple of (scan_id_from, scan_id_to), scan_id_from created earlier.
    """
    import uuid as uuid_module
    from datetime import datetime, timedelta
    from cape.db.models import Scan, Target

    target_obj = session.query(Target).filter_by(hostname_or_ip=target).first()
    if not target_obj:
        target_obj = Target(hostname_or_ip=target, created_at=datetime.utcnow())
        session.add(target_obj)
        session.flush()

    scan_from = Scan(
        id=str(uuid_module.uuid4()), target_id=target_obj.id, profile="quick",
        status="COMPLETED", started_at=datetime.utcnow() - timedelta(days=7),
        completed_at=datetime.utcnow() - timedelta(days=7),
    )
    scan_to = Scan(
        id=str(uuid_module.uuid4()), target_id=target_obj.id, profile="quick",
        status="COMPLETED", started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
    )
    session.add(scan_from)
    session.add(scan_to)
    session.flush()

    return scan_from.id, scan_to.id


def make_finding_pair(
    title: str = "Outdated SSH Server",
    sev_before: str = "LOW",
    sev_after: str = "HIGH",
    target: str = "10.0.0.1",
    host: str = "10.0.0.1",
    port: int = 22,
):
    """Create two Finding instances with identical content but different
    severities, for drift regression/improvement tests.

    Args:
        title: shared finding title (same logical finding both times).
        sev_before: severity in the "before" scan.
        sev_after: severity in the "after" scan.
        target/host/port: identity fields used in fingerprinting; kept
            identical across both findings so they fingerprint the same.

    Returns:
        Tuple of (finding_before, finding_after) Finding instances.
    """
    from cape.shared.finding import FindingFactory
    from cape.shared.enums import Severity

    finding_before = FindingFactory.create(
        target=target, host=host, port=port, title=title,
        severity=Severity(sev_before),
    )
    finding_after = FindingFactory.create(
        target=target, host=host, port=port, title=title,
        severity=Severity(sev_after),
    )
    return finding_before, finding_after
