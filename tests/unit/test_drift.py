"""Unit tests for CAPE Pillar C: ScanDiffer / drift detection."""
from __future__ import annotations

from datetime import datetime, timedelta

from cape.shared.finding import FindingFactory
from cape.show.drift import FindingStatus, ScanDiffer
from tests.conftest import make_finding_pair, make_scan_pair


def _persist(session, finding, scan_id, target_id):
    """Helper: write a Finding (pydantic) into the findings table as a FindingModel."""
    from cape.db.models import FindingModel

    fm = FindingModel(
        id=str(finding.id), target=finding.target, target_id=target_id, scan_id=scan_id,
        source_tool=finding.source_tool, scan_profile=finding.scan_profile,
        timestamp=finding.timestamp, category=finding.category.value,
        severity=finding.severity.value, confidence=finding.confidence,
        title=finding.title, description=finding.description, evidence=finding.evidence,
        host=finding.host, port=finding.port, protocol=finding.protocol,
        service=finding.service, cve_ids=finding.cve_ids, tags=finding.tags, extra=finding.extra,
    )
    session.add(fm)
    return fm


class TestScanDiffer:
    def setup_method(self) -> None:
        self.differ = ScanDiffer()

    def test_new_finding_detected(self, cape_db) -> None:
        """A finding present only in the later scan is NEW."""
        from cape.db.session import db_session
        target = "10.0.0.1"
        with db_session() as session:
            scan_from, scan_to = make_scan_pair(target, session)
            from cape.db.models import Target
            target_id = session.query(Target).filter_by(hostname_or_ip=target).first().id
            new_finding = FindingFactory.create(target=target, host=target, title="New Open Port")
            _persist(session, new_finding, scan_to, target_id)

        report = self.differ.compare(target, scan_from, scan_to)
        assert report.new_count == 1
        assert report.entries[0].status == FindingStatus.NEW
        assert report.entries[0].severity_before is None

    def test_fixed_finding_detected(self, cape_db) -> None:
        """A finding present only in the earlier scan is FIXED."""
        from cape.db.session import db_session
        target = "10.0.0.2"
        with db_session() as session:
            scan_from, scan_to = make_scan_pair(target, session)
            from cape.db.models import Target
            target_id = session.query(Target).filter_by(hostname_or_ip=target).first().id
            old_finding = FindingFactory.create(target=target, host=target, title="Old Vulnerable Service")
            _persist(session, old_finding, scan_from, target_id)

        report = self.differ.compare(target, scan_from, scan_to)
        assert report.fixed_count == 1
        assert report.entries[0].status == FindingStatus.FIXED
        assert report.entries[0].severity_after is None

    def test_regressed_finding(self, cape_db) -> None:
        """Same logical finding, severity LOW -> HIGH, is REGRESSED."""
        from cape.db.session import db_session
        target = "10.0.0.3"
        before, after = make_finding_pair(
            title="Weak TLS Config", sev_before="LOW", sev_after="HIGH", target=target, host=target,
        )
        with db_session() as session:
            scan_from, scan_to = make_scan_pair(target, session)
            from cape.db.models import Target
            target_id = session.query(Target).filter_by(hostname_or_ip=target).first().id
            _persist(session, before, scan_from, target_id)
            _persist(session, after, scan_to, target_id)

        report = self.differ.compare(target, scan_from, scan_to)
        assert report.regressed_count == 1
        assert report.entries[0].status == FindingStatus.REGRESSED
        assert report.entries[0].severity_before == "LOW"
        assert report.entries[0].severity_after == "HIGH"

    def test_persistent_finding(self, cape_db) -> None:
        """Same finding, same severity, both scans -> PERSISTENT."""
        from cape.db.session import db_session
        target = "10.0.0.4"
        before, after = make_finding_pair(
            title="Open SSH Port", sev_before="MEDIUM", sev_after="MEDIUM", target=target, host=target,
        )
        with db_session() as session:
            scan_from, scan_to = make_scan_pair(target, session)
            from cape.db.models import Target
            target_id = session.query(Target).filter_by(hostname_or_ip=target).first().id
            _persist(session, before, scan_from, target_id)
            _persist(session, after, scan_to, target_id)

        report = self.differ.compare(target, scan_from, scan_to)
        assert report.persistent_count == 1
        assert report.entries[0].status == FindingStatus.PERSISTENT
        assert report.entries[0].days_open is not None

    def test_improved_finding(self, cape_db) -> None:
        """Same finding, severity HIGH -> LOW, is IMPROVED."""
        from cape.db.session import db_session
        target = "10.0.0.5"
        before, after = make_finding_pair(
            title="Misconfigured Header", sev_before="HIGH", sev_after="LOW", target=target, host=target,
        )
        with db_session() as session:
            scan_from, scan_to = make_scan_pair(target, session)
            from cape.db.models import Target
            target_id = session.query(Target).filter_by(hostname_or_ip=target).first().id
            _persist(session, before, scan_from, target_id)
            _persist(session, after, scan_to, target_id)

        report = self.differ.compare(target, scan_from, scan_to)
        assert report.improved_count == 1
        assert report.entries[0].status == FindingStatus.IMPROVED

    def test_fingerprint_stable(self) -> None:
        """Two identical findings (in content) produce the same fingerprint."""
        f1 = FindingFactory.create(title="Same Finding", host="10.0.0.9", port=443)
        f2 = FindingFactory.create(title="Same Finding", host="10.0.0.9", port=443)
        assert self.differ._fingerprint(f1) == self.differ._fingerprint(f2)

    def test_fingerprint_ignores_uuid(self) -> None:
        """Two Finding instances with the same content but different UUIDs
        and timestamps still fingerprint identically (identity is semantic,
        not UUID-based)."""
        f1 = FindingFactory.create(title="Identical Issue", host="10.0.0.10", port=8080)
        f2 = FindingFactory.create(title="Identical Issue", host="10.0.0.10", port=8080)
        assert f1.id != f2.id  # sanity: factory generates distinct UUIDs
        assert self.differ._fingerprint(f1) == self.differ._fingerprint(f2)

    def test_trend_score_positive_when_mostly_fixed(self, cape_db) -> None:
        """A scan pair dominated by FIXED findings yields a positive trend score."""
        from cape.db.session import db_session
        target = "10.0.0.6"
        with db_session() as session:
            scan_from, scan_to = make_scan_pair(target, session)
            from cape.db.models import Target
            target_id = session.query(Target).filter_by(hostname_or_ip=target).first().id
            for i in range(3):
                f = FindingFactory.create(target=target, host=target, title=f"Fixed Issue {i}", port=1000 + i)
                _persist(session, f, scan_from, target_id)  # only in "from" => FIXED

        report = self.differ.compare(target, scan_from, scan_to)
        assert report.fixed_count == 3
        assert report.trend_score > 0

    def test_trend_score_negative_when_mostly_new(self, cape_db) -> None:
        """A scan pair dominated by NEW findings yields a negative trend score."""
        from cape.db.session import db_session
        target = "10.0.0.7"
        with db_session() as session:
            scan_from, scan_to = make_scan_pair(target, session)
            from cape.db.models import Target
            target_id = session.query(Target).filter_by(hostname_or_ip=target).first().id
            for i in range(3):
                f = FindingFactory.create(target=target, host=target, title=f"New Issue {i}", port=2000 + i)
                _persist(session, f, scan_to, target_id)  # only in "to" => NEW

        report = self.differ.compare(target, scan_from, scan_to)
        assert report.new_count == 3
        assert report.trend_score < 0
