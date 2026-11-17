"""Unit tests for CAPE multi-tenant client isolation."""
from __future__ import annotations

import pytest

from cape.core.workspace import WorkspaceManager, validate_client_id


class TestClientIsolation:
    def test_findings_isolated_by_client_id(self, cape_db, tmp_path) -> None:
        """Findings tagged with different client_ids must not leak across clients."""
        from cape.db.session import db_session
        from cape.db.models import FindingModel, Target
        from cape.shared.finding import FindingFactory
        from datetime import datetime

        target = "10.0.0.1"
        with db_session() as session:
            t = Target(hostname_or_ip=target, created_at=datetime.utcnow(), client_id="client-a")
            session.add(t)
            session.flush()

            f_a = FindingFactory.create(target=target, host=target, title="Client A Finding")
            f_b = FindingFactory.create(target=target, host=target, title="Client B Finding")

            session.add(FindingModel(
                id=str(f_a.id), target=target, target_id=t.id, source_tool="nmap",
                scan_profile="quick", timestamp=f_a.timestamp, category=f_a.category.value,
                severity=f_a.severity.value, confidence=0.9, title=f_a.title,
                description="", evidence="", host=target, client_id="client-a",
            ))
            session.add(FindingModel(
                id=str(f_b.id), target=target, target_id=t.id, source_tool="nmap",
                scan_profile="quick", timestamp=f_b.timestamp, category=f_b.category.value,
                severity=f_b.severity.value, confidence=0.9, title=f_b.title,
                description="", evidence="", host=target, client_id="client-b",
            ))

        with db_session() as session:
            client_a_findings = session.query(FindingModel).filter(
                FindingModel.target == target, FindingModel.client_id == "client-a",
            ).all()
            client_b_findings = session.query(FindingModel).filter(
                FindingModel.target == target, FindingModel.client_id == "client-b",
            ).all()

        assert len(client_a_findings) == 1
        assert client_a_findings[0].title == "Client A Finding"
        assert len(client_b_findings) == 1
        assert client_b_findings[0].title == "Client B Finding"

    def test_scan_only_returns_own_client_findings(self, cape_db) -> None:
        """A query scoped to client_id='client-a' must never return client-b's rows."""
        from cape.db.session import db_session
        from cape.db.models import FindingModel, Target
        from cape.shared.finding import FindingFactory
        from datetime import datetime

        target = "10.0.0.2"
        with db_session() as session:
            t = Target(hostname_or_ip=target, created_at=datetime.utcnow())
            session.add(t)
            session.flush()

            for i, cid in enumerate(["client-a", "client-a", "client-b"]):
                f = FindingFactory.create(target=target, host=target, title=f"Finding {i}")
                session.add(FindingModel(
                    id=str(f.id), target=target, target_id=t.id, source_tool="nmap",
                    scan_profile="quick", timestamp=f.timestamp, category=f.category.value,
                    severity=f.severity.value, confidence=0.9, title=f.title,
                    description="", evidence="", host=target, client_id=cid,
                ))

        with db_session() as session:
            results = session.query(FindingModel).filter(FindingModel.client_id == "client-a").all()

        assert len(results) == 2
        assert all(r.client_id == "client-a" for r in results)

    def test_workspace_path_includes_client_id(self, tmp_path) -> None:
        """WorkspaceManager must namespace paths under clients/<client_id>/workspaces/."""
        import cape.core.config as config_module
        config_module._config_instance = None

        import os
        os.environ["CO_WORKSPACE_ROOT"] = str(tmp_path / "workspaces")
        try:
            wm = WorkspaceManager(client_id="acme-corp")
            assert "clients" in str(wm.workspace_root)
            assert "acme-corp" in str(wm.workspace_root)
            assert "workspaces" in str(wm.workspace_root)
        finally:
            os.environ.pop("CO_WORKSPACE_ROOT", None)
            config_module._config_instance = None

    def test_client_list_shows_correct_counts(self, cape_db) -> None:
        """Counting targets/findings per client_id must give the right numbers."""
        from cape.db.session import db_session
        from cape.db.models import Client, FindingModel, Target
        from cape.shared.finding import FindingFactory
        from datetime import datetime

        with db_session() as session:
            session.add(Client(id="acme-corp", name="Acme Corp", contact="", created_at=datetime.utcnow()))
            t1 = Target(hostname_or_ip="10.1.1.1", created_at=datetime.utcnow(), client_id="acme-corp")
            t2 = Target(hostname_or_ip="10.1.1.2", created_at=datetime.utcnow(), client_id="acme-corp")
            session.add(t1)
            session.add(t2)
            session.flush()

            for t in (t1, t2):
                f = FindingFactory.create(target=t.hostname_or_ip, host=t.hostname_or_ip)
                session.add(FindingModel(
                    id=str(f.id), target=t.hostname_or_ip, target_id=t.id, source_tool="nmap",
                    scan_profile="quick", timestamp=f.timestamp, category=f.category.value,
                    severity=f.severity.value, confidence=0.9, title=f.title,
                    description="", evidence="", host=t.hostname_or_ip, client_id="acme-corp",
                ))

        with db_session() as session:
            target_count = session.query(Target).filter(Target.client_id == "acme-corp").count()
            finding_count = session.query(FindingModel).filter(FindingModel.client_id == "acme-corp").count()

        assert target_count == 2
        assert finding_count == 2

    def test_no_client_id_returns_all_legacy_data(self, cape_db) -> None:
        """An unscoped query (no client_id filter) must still see pre-CAPE legacy rows
        that have client_id=NULL, preserving backward compatibility."""
        from cape.db.session import db_session
        from cape.db.models import FindingModel, Target
        from cape.shared.finding import FindingFactory
        from datetime import datetime

        target = "10.0.0.3"
        with db_session() as session:
            t = Target(hostname_or_ip=target, created_at=datetime.utcnow())  # no client_id
            session.add(t)
            session.flush()

            f = FindingFactory.create(target=target, host=target, title="Legacy Finding")
            session.add(FindingModel(
                id=str(f.id), target=target, target_id=t.id, source_tool="nmap",
                scan_profile="quick", timestamp=f.timestamp, category=f.category.value,
                severity=f.severity.value, confidence=0.9, title=f.title,
                description="", evidence="", host=target, client_id=None,
            ))

        with db_session() as session:
            unscoped = session.query(FindingModel).filter(FindingModel.target == target).all()

        assert len(unscoped) == 1
        assert unscoped[0].client_id is None
        assert unscoped[0].title == "Legacy Finding"

    def test_validate_client_id_rejects_unsafe_input(self) -> None:
        """validate_client_id must reject anything that isn't alphanumeric+hyphens."""
        with pytest.raises(ValueError):
            validate_client_id("acme corp; rm -rf /")
        with pytest.raises(ValueError):
            validate_client_id("../../etc/passwd")
        with pytest.raises(ValueError):
            validate_client_id("")
        # valid cases should not raise
        assert validate_client_id("acme-corp") == "acme-corp"
        assert validate_client_id("client123") == "client123"
