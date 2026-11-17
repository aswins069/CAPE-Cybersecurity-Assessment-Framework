"""Regression and local-only integration tests for CAPE's bounded attack modules."""
from __future__ import annotations

import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest

from cape.attack.models import AttackSession, ModuleContext
from cape.attack.modules.basic import (
    AuthModule,
    DirectoryEnumerationModule,
    HTTPHeadersModule,
    SQLiModule,
    XSSModule,
    _validate_same_lab_host,
    safe_http_get,
    validate_lab_target,
)
from cape.plan.models import WorkflowStep
from cape.shared.enums import AttackDomain, SessionState


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/admin")
            self.end_headers()
            return
        if parsed.path == "/admin":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"admin page")
            return
        if parsed.path == "/auth":
            expected = "Basic " + base64.b64encode(b"labuser:labpass").decode()
            if self.headers.get("Authorization") == expected:
                self.send_response(200)
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Basic realm=lab")
            self.end_headers()
            return
        if parsed.path == "/sqli":
            value = parse_qs(parsed.query).get("id", [""])[0]
            self.send_response(200)
            self.end_headers()
            if "'" in value:
                self.wfile.write(b"You have an error in your SQL syntax")
            else:
                self.wfile.write(b"normal response")
            return
        if parsed.path == "/reflect":
            value = parse_qs(parsed.query).get("q", [""])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(value.encode())
            return
        if parsed.path == "/headers":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"hello")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def lab_server(monkeypatch, tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    import cape.attack.modules.basic as basic
    monkeypatch.setattr(basic, "_evidence_path", lambda ctx, step: tmp_path / f"{step.id}.json")
    yield base
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


def make_context(target: str) -> ModuleContext:
    session = AttackSession(
        target=target, plan_id=uuid4(), operator="test-operator",
        scope_token="test-token", state=SessionState.ACTIVE,
    )
    return ModuleContext(target=target, session=session, findings=[])


def make_step(module, ctx):
    return module.get_steps(ctx)[0]


def test_lab_scope_allows_loopback_and_private_addresses():
    assert validate_lab_target("127.0.0.1")[0] == "127.0.0.1"
    assert validate_lab_target("http://10.10.0.5:8080")[0] == "10.10.0.5"


@pytest.mark.parametrize("target", ["8.8.8.8", "example.com", "192.168.1.0/24", "0.0.0.0"])
def test_lab_scope_blocks_public_dns_cidr_and_unspecified(target):
    with pytest.raises(ValueError):
        validate_lab_target(target)


def test_same_host_guard_blocks_other_private_ip():
    ctx = make_context("127.0.0.1")
    with pytest.raises(ValueError):
        _validate_same_lab_host(ctx, "http://10.0.0.2:8080/")


def test_http_fetch_does_not_follow_redirects(lab_server):
    status, _, _ = safe_http_get(lab_server + "/redirect")
    assert status == 302


def test_xss_probe_reports_reflection_only_not_confirmed_xss(lab_server):
    ctx = make_context(lab_server)
    module = XSSModule()
    result = module.execute_step(
        make_step(module, ctx), ctx,
        {"target_url": lab_server + "/reflect", "parameter": "q"},
    )
    assert result.success
    assert "not proof of executable XSS" in result.output
    assert result.findings
    assert "not-execution-verified" in result.findings[0].tags


def test_http_headers_module_creates_missing_header_findings(lab_server):
    ctx = make_context(lab_server)
    module = HTTPHeadersModule()
    result = module.execute_step(
        make_step(module, ctx), ctx, {"target_url": lab_server + "/headers"}
    )
    assert result.success
    assert "Content-Security-Policy" in result.output
    assert len(result.findings) >= 4


def test_auth_module_performs_one_http_basic_attempt_without_storing_secret(lab_server, tmp_path, monkeypatch):
    import cape.attack.modules.basic as basic
    monkeypatch.setattr(basic, "_evidence_path", lambda ctx, step: tmp_path / "auth.json")
    ctx = make_context(lab_server)
    module = AuthModule()
    result = module.execute_step(
        make_step(module, ctx), ctx,
        {"target_url": lab_server + "/auth", "username": "labuser", "password": "labpass"},
    )
    assert result.success
    assert "one attempt" in result.output.lower()
    assert "labpass" not in (tmp_path / "auth.json").read_text()


def test_sqli_python_fallback_detects_only_error_indicator(lab_server, tmp_path, monkeypatch):
    import cape.attack.modules.basic as basic
    monkeypatch.setattr(basic.shutil, "which", lambda name: None)
    monkeypatch.setattr(basic, "_evidence_path", lambda ctx, step: tmp_path / "sqli.json")
    ctx = make_context(lab_server)
    module = SQLiModule()
    result = module.execute_step(
        make_step(module, ctx), ctx,
        {"target_url": lab_server + "/sqli?id=1", "parameter": "id"},
    )
    assert result.success
    assert "Possible SQL Error Disclosure" == result.findings[0].title
    assert "not-confirmed" in result.findings[0].tags


def test_directory_enumeration_python_fallback_is_bounded(lab_server, monkeypatch, tmp_path):
    import cape.attack.modules.basic as basic
    monkeypatch.setattr(basic.shutil, "which", lambda name: None)
    monkeypatch.setattr(basic, "_evidence_path", lambda ctx, step: tmp_path / "dirs.json")
    ctx = make_context(lab_server)
    module = DirectoryEnumerationModule()
    result = module.execute_step(
        make_step(module, ctx), ctx, {"target_url": lab_server}
    )
    assert result.success
    assert "PYTHON_FALLBACK" in result.output
    assert len(basic.DEFAULT_WORDS) == 16


def test_web_opportunity_exposes_new_modules_without_removing_legacy_ones():
    from cape.attack.engine import AttackEngine
    from cape.show.models import Opportunity
    from cape.shared.enums import AttackDomain, Severity

    opportunity = Opportunity(
        target="127.0.0.1",
        domain=AttackDomain.WEB,
        attack_pattern_id="web-sqli-001",
        rule_id="opp-sqli-001",
        name="SQL Injection Assessment",
        description="Lab web service test",
        score=6.0,
        confidence=0.8,
        severity=Severity.MEDIUM,
        recommended_modules=[
            "SQLiModule", "DirectoryEnumerationModule", "HTTPHeadersModule"
        ],
        explanation="Unit test opportunity",
    )
    names = AttackEngine().list_modules([opportunity])
    assert "SQLiModule" in names
    assert "DirectoryEnumerationModule" in names
    assert "HTTPHeadersModule" in names
    # Legacy workflows remain registered for continuity.
    from cape.attack.modules import AVAILABLE_MODULES
    assert {"CMSModule", "APIModule", "NetworkModule"}.issubset(AVAILABLE_MODULES)


def test_smb_module_reports_missing_nmap_instead_of_fake_success(monkeypatch):
    import cape.attack.modules.basic as basic
    monkeypatch.setattr(basic.shutil, "which", lambda name: None)
    ctx = make_context("127.0.0.1")
    preparation = basic.SMBModule().prepare_tools(ctx)
    assert preparation.ready is False
    assert preparation.missing_tools == ["nmap"]


def test_legacy_workflows_do_not_report_placeholder_steps_as_success():
    from cape.attack.modules.api import APIModule
    from cape.attack.modules.smb import CMSModule, NetworkModule

    ctx = make_context("127.0.0.1")
    step = WorkflowStep(
        plan_id=uuid4(), step_number=1, name="legacy",
        description="legacy guided test", domain=AttackDomain.WEB,
    )
    for module in (APIModule(), CMSModule(), NetworkModule()):
        result = module.execute_step(step, ctx, {})
        assert result.success is False
        assert result.output.startswith("GUIDED_ONLY_NOT_EXECUTED")
