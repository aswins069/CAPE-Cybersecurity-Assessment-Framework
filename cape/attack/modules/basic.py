"""Small, bounded attack-assessment modules for explicitly authorized lab targets.

These modules perform verification-oriented checks only. They do not dump data,
modify remote systems, upload files, or run post-exploitation actions.
"""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.error import URLError

from cape.attack.models import AttackSession, ModuleContext, ToolPreparationResult, ValidationResult
from cape.attack.modules.base import BaseAttackModule
from cape.plan.models import WorkflowStep
from cape.scan.plugins.base import StepResult
from cape.shared.enums import AttackDomain, FindingCategory, Severity
from cape.shared.finding import Finding


DEFAULT_WORDS = [
    "admin", "api", "backup", "config", "dashboard", "docs", "health",
    "login", "robots.txt", "server-status", "static", "uploads",
    "user", "users", "v1", "swagger"
]
WEB_HEADERS = {
    "Content-Security-Policy": "MEDIUM",
    "Strict-Transport-Security": "MEDIUM",
    "X-Content-Type-Options": "LOW",
    "X-Frame-Options": "LOW",
    "Referrer-Policy": "LOW",
    "Permissions-Policy": "LOW",
}


class LabScopeError(ValueError):
    """Raised when a target is not an explicitly bounded private lab address."""


def _host_and_port(target: str) -> tuple[str, int, str, str]:
    value = target.strip()
    if "://" not in value:
        try:
            network_value = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network_value = None
        if network_value is not None and "/" in value:
            raise LabScopeError("CIDR ranges are not accepted; use one explicit lab host.")
        value = "http://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise LabScopeError("Only HTTP/HTTPS URLs or a single IP address are supported.")
    if parsed.username or parsed.password:
        raise LabScopeError("Credentials must not be embedded in target URLs.")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return host, port, parsed.scheme, path


def _literal_lab_ip(host: str) -> str:
    if host.lower() == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise LabScopeError(
            "For safety, executable tests require localhost or a literal private IP address; "
            "DNS hostnames are not accepted."
        ) from exc
    if not (address.is_private or address.is_loopback or address.is_link_local):
        raise LabScopeError("Public or non-private targets are blocked.")
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        raise LabScopeError("This IP address is not a valid lab target.")
    return str(address)


def validate_lab_target(target: str) -> tuple[str, int, str, str]:
    """Validate a single localhost/private-IP target; CIDRs and public hosts are rejected."""
    host, port, scheme, path = _host_and_port(target)
    ip = _literal_lab_ip(host)
    if not 1 <= port <= 65535:
        raise LabScopeError("Invalid target port.")
    return ip, port, scheme, path


def _validate_same_lab_host(ctx: ModuleContext, target_url: str) -> tuple[str, int, str, str]:
    base_host, _, _, _ = _host_and_port(ctx.target)
    base_ip = _literal_lab_ip(base_host)
    url_ip, port, scheme, path = validate_lab_target(target_url)
    if url_ip != base_ip:
        raise LabScopeError("The supplied URL must resolve to the same host as the approved CAPE target.")
    return url_ip, port, scheme, path


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, ip: str, host: str, port: int, timeout: float, use_tls: bool):
        super().__init__(host, port=port, timeout=timeout)
        self._ip = ip
        self._host = host
        self._use_tls = use_tls

    def connect(self) -> None:
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        if self._use_tls:
            context = ssl.create_default_context()
            self.sock = context.wrap_socket(raw, server_hostname=self._host)
        else:
            self.sock = raw


def safe_http_get(target: str, *, headers: Optional[dict[str, str]] = None,
                  timeout: float = 5.0, max_bytes: int = 1_000_000) -> tuple[int, dict[str, str], bytes]:
    """Fetch one HTTP response without following redirects, pinned to a validated IP."""
    ip, port, scheme, path = validate_lab_target(target)
    host, _, _, _ = _host_and_port(target)
    conn = _PinnedHTTPConnection(ip, host, port, timeout, scheme == "https")
    try:
        host_header = f"[{host}]" if ":" in host else host
        default_port = 443 if scheme == "https" else 80
        if port != default_port:
            host_header = f"{host_header}:{port}"
        request_headers = {"Host": host_header, "User-Agent": "CAPE-Lab-Assessment/1.0", "Connection": "close"}
        if headers:
            request_headers.update(headers)
        conn.request("GET", path, headers=request_headers)
        response = conn.getresponse()
        body = response.read(max_bytes)
        return response.status, {k.lower(): v for k, v in response.getheaders()}, body
    finally:
        conn.close()


def _run(argv: list[str], timeout: int, evidence_path: Path) -> StepResult:
    start = time.monotonic()
    try:
        safe_env = os.environ.copy()
        for proxy_key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            safe_env.pop(proxy_key, None)
        safe_env["NO_PROXY"] = "*"
        safe_env["no_proxy"] = "*"
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            shell=False, check=False, stdin=subprocess.DEVNULL, env=safe_env,
        )
        output = proc.stdout or ""
        error = proc.stderr or ""
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "argv": argv,
                "returncode": proc.returncode,
                "stdout": output,
                "stderr": error,
            }, indent=2),
            encoding="utf-8",
        )
        return StepResult(
            step_id="", success=proc.returncode == 0, output=output,
            error=error, duration=time.monotonic() - start,
        )
    except FileNotFoundError as exc:
        return StepResult(step_id="", success=False, output="TOOL_NOT_AVAILABLE",
                          error=str(exc), duration=time.monotonic() - start)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "argv": argv, "timeout": timeout, "stdout": stdout, "stderr": stderr,
            "status": "INCONCLUSIVE_TIMEOUT",
        }, indent=2), encoding="utf-8")
        return StepResult(step_id="", success=False, output=stdout,
                          error=f"INCONCLUSIVE_TIMEOUT after {timeout}s\n{stderr}",
                          duration=time.monotonic() - start)
    except OSError as exc:
        return StepResult(step_id="", success=False, output="EXECUTION_FAILED",
                          error=str(exc), duration=time.monotonic() - start)


def _evidence_path(ctx: ModuleContext, step: WorkflowStep) -> Path:
    base = Path.home() / ".cape" / "workspaces"
    safe_target = re.sub(r"[^A-Za-z0-9_.-]", "_", ctx.target)[:90]
    return base / safe_target / "sessions" / str(ctx.session.id) / "attack_evidence" / f"{step.id}.json"


def _finding(ctx: ModuleContext, tool: str, category: FindingCategory, severity: Severity,
             title: str, description: str, evidence: str, tags: list[str],
             evidence_file: Optional[Path] = None) -> Finding:
    host = _host_and_port(ctx.target)[0]
    return Finding(
        target=ctx.target, source_tool=tool, scan_profile="attack",
        category=category, severity=severity, confidence=0.85,
        title=title, description=description, evidence=evidence[:1500],
        host=host, tags=tags, raw_output_file=evidence_file,
    )


class _BasicModule(BaseAttackModule):
    requires_explicit_run = True
    step_name = "Controlled lab test"
    step_description = "Run a bounded verification test against the authorized lab target."
    required_inputs: list[str] = []

    def load_context(self, target: str, session: AttackSession, findings: list[Finding]) -> ModuleContext:
        return ModuleContext(target=target, session=session, findings=findings)

    def validate_preconditions(self, ctx: ModuleContext) -> ValidationResult:
        try:
            validate_lab_target(ctx.target)
        except ValueError as exc:
            return ValidationResult(valid=False, missing_requirements=[str(exc)])
        return ValidationResult(valid=True)

    def get_steps(self, ctx: ModuleContext) -> list[WorkflowStep]:
        return [WorkflowStep(
            id=uuid.uuid4(), plan_id=uuid.uuid4(), step_number=1,
            name=self.step_name, description=self.step_description,
            domain=self.domain, tool=self.required_tools[0] if self.required_tools else "python",
            tool_args_template=None, estimated_duration_seconds=120,
            operator_action_required=True,
            notes="Restricted to localhost or a single private IP. No destructive actions are performed.",
        )]

    def prepare_tools(self, ctx: ModuleContext) -> ToolPreparationResult:
        return self._check_tools()

    def collect_operator_inputs(self, ctx: ModuleContext, step: WorkflowStep) -> dict[str, str]:
        from getpass import getpass
        values: dict[str, str] = {}
        for field in self.required_inputs:
            if field == "password":
                values[field] = getpass("  Test account password (not stored): ")
            else:
                values[field] = input(f"  {field}: ").strip()
        return values

    def collect_results(self, step_results: list[StepResult]) -> list[Finding]:
        findings: list[Finding] = []
        for result in step_results:
            findings.extend(result.findings or [])
        return findings

    def persist_results(self, findings: list[Finding], session: AttackSession) -> None:
        if not findings:
            return
        try:
            from cape.db.models import FindingModel
            from cape.db.session import db_session
            from cape.show.compliance.mapper import ComplianceMapper
            mapper = ComplianceMapper()
            with db_session() as db:
                for finding in findings:
                    annotation = mapper.annotate_finding(finding)
                    db.merge(FindingModel(
                        id=str(finding.id), target=finding.target,
                        source_tool=finding.source_tool, scan_profile=finding.scan_profile,
                        timestamp=finding.timestamp, category=finding.category.value,
                        severity=finding.severity.value, confidence=finding.confidence,
                        title=finding.title, description=finding.description,
                        evidence=finding.evidence, host=finding.host,
                        port=finding.port, protocol=finding.protocol, service=finding.service,
                        cve_ids=finding.cve_ids, cvss_score=finding.cvss_score,
                        cvss_vector=finding.cvss_vector, remediation=finding.remediation,
                        references=finding.references, raw_output_file=str(finding.raw_output_file) if finding.raw_output_file else None,
                        tags=finding.tags, extra=finding.extra,
                        compliance_pci_dss=annotation.pci_dss,
                        compliance_soc2=annotation.soc2,
                        compliance_iso27001=annotation.iso27001,
                        compliance_nist_csf=annotation.nist_csf,
                        compliance_cis_controls=annotation.cis_controls,
                    ))
        except Exception:
            # The execution evidence remains on disk; persistence errors are surfaced by the caller's logs.
            import logging
            logging.getLogger(__name__).exception("Could not persist attack findings")


class SQLiModule(_BasicModule):
    name = "SQLiModule"
    domain = AttackDomain.WEB
    required_opportunity_ids = ["opp-sqli-001"]
    required_tools = []
    required_inputs = ["target_url", "parameter"]
    step_name = "SQL injection detection (non-destructive)"
    step_description = "Run SQLMap detection only; database enumeration and data extraction are disabled."

    def execute_step(self, step: WorkflowStep, ctx: ModuleContext, operator_inputs: dict) -> StepResult:
        try:
            _validate_same_lab_host(ctx, operator_inputs.get("target_url", ""))
        except ValueError as exc:
            return StepResult(step_id=str(step.id), success=False, output="BLOCKED_BY_VALIDATION", error=str(exc))
        url = operator_inputs["target_url"]
        sqlmap = shutil.which("sqlmap")
        if sqlmap:
            argv = [
                sqlmap, "-u", url, "--batch", "--smart", "--risk=1", "--level=1",
                "--threads=1", "--timeout=5", "--retries=0", "--technique=BEU",
                "--disable-coloring", "--ignore-redirects",
            ]
            result = _run(argv, 120, _evidence_path(ctx, step))
            result.step_id = str(step.id)
        else:
            # Conservative, read-only quote probe; never attempts writes or data extraction.
            try:
                parameter = operator_inputs["parameter"]
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", parameter):
                    raise ValueError("Parameter name contains unsupported characters.")
                parsed = urlsplit(url if "://" in url else "http://" + url)
                pairs = parse_qsl(parsed.query, keep_blank_values=True)
                if not any(key == parameter for key, _ in pairs):
                    raise ValueError("The selected parameter must already exist in the URL query string.")
                baseline_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(pairs), ""))
                probe_pairs = [(key, value + ("'" if key == parameter else "")) for key, value in pairs]
                probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(probe_pairs), ""))
                baseline_status, _, baseline_body = safe_http_get(baseline_url)
                probe_status, _, probe_body = safe_http_get(probe_url)
                signatures = (
                    "sql syntax", "mysql", "sqlite", "postgresql", "odbc",
                    "unclosed quotation mark", "you have an error in your sql",
                    "ora-00933", "syntax error near",
                )
                probe_text = probe_body.decode(errors="replace").lower()
                baseline_text = baseline_body.decode(errors="replace").lower()
                indicators = [sig for sig in signatures if sig in probe_text and sig not in baseline_text]
                result = StepResult(
                    step_id=str(step.id), success=True,
                    output=(
                        "EXECUTED_READ_ONLY_SQL_ERROR_PROBE\\n"
                        f"Baseline HTTP: {baseline_status}; quote-probe HTTP: {probe_status}\\n"
                        f"New SQL error indicators: {', '.join(indicators) or 'none'}\\n"
                        "This heuristic is not proof of SQL injection; confirm with SQLMap in the lab."
                    ),
                    duration=0.0,
                )
                evidence = _evidence_path(ctx, step)
                evidence.parent.mkdir(parents=True, exist_ok=True)
                evidence.write_text(json.dumps({
                    "target": url, "parameter": parameter, "baseline_status": baseline_status,
                    "probe_status": probe_status, "new_error_indicators": indicators,
                    "classification": "candidate only; SQLMap unavailable",
                }, indent=2), encoding="utf-8")
                if indicators:
                    result.findings.append(_finding(
                        ctx, "cape-sqli-error-probe", FindingCategory.VULNERABILITY, Severity.MEDIUM,
                        "Possible SQL Error Disclosure",
                        "A quote-only read-only probe caused a new database error signature. This is an indicator requiring manual/SQLMap confirmation, not a confirmed exploitable SQL injection.",
                        ", ".join(indicators), ["sqli-candidate", "error-based-indicator", "not-confirmed"],
                        _evidence_path(ctx, step),
                    ))
                return result
            except Exception as exc:
                return StepResult(step_id=str(step.id), success=False,
                                  output="EXECUTION_FAILED_OR_BLOCKED", error=str(exc))
        text = (result.output + "\\n" + result.error).lower()
        if result.success and ("is vulnerable" in text or "appears to be injectable" in text):
            result.findings.append(_finding(
                ctx, "sqlmap", FindingCategory.VULNERABILITY, Severity.HIGH,
                "SQL Injection Indicator Confirmed",
                "SQLMap reported an injectable parameter during a bounded detection-only test. No database enumeration or extraction was requested.",
                result.output, ["sqli", "sqlmap", "lab-verified"], _evidence_path(ctx, step),
            ))
            result.output = "SUCCESS_CONFIRMED\\n" + result.output
        elif result.success:
            result.output = "EXECUTED_NO_ISSUE_FOUND_OR_NOT_CONFIRMED\\n" + result.output
        return result


class XSSModule(_BasicModule):
    name = "XSSModule"
    domain = AttackDomain.WEB
    required_opportunity_ids = ["opp-xss-001"]
    required_tools = []
    required_inputs = ["target_url", "parameter"]
    step_name = "Reflected-input XSS probe"
    step_description = "Send a harmless unique marker and check whether it is reflected; this does not prove script execution."

    def execute_step(self, step: WorkflowStep, ctx: ModuleContext, operator_inputs: dict) -> StepResult:
        start = time.monotonic()
        try:
            target_url = operator_inputs["target_url"]
            ip, port, scheme, _ = _validate_same_lab_host(ctx, target_url)
            host, _, _, _ = _host_and_port(target_url)
            parameter = operator_inputs["parameter"]
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", parameter):
                raise ValueError("Parameter name contains unsupported characters.")
            parsed = urlsplit(target_url if "://" in target_url else "http://" + target_url)
            marker = "CAPE_REFLECT_" + uuid.uuid4().hex[:12]
            query = parse_qsl(parsed.query, keep_blank_values=True)
            query.append((parameter, marker))
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), ""))
            status, headers, body = safe_http_get(url)
            reflected = marker.encode() in body
            result = StepResult(
                step_id=str(step.id), success=True,
                output=f"EXECUTED\nHTTP status: {status}\nUnique marker reflected: {reflected}\n"
                       "Interpretation: reflection alone is not proof of executable XSS.",
                duration=time.monotonic() - start,
            )
            if reflected:
                result.findings.append(_finding(
                    ctx, "cape-xss-probe", FindingCategory.VULNERABILITY, Severity.LOW,
                    "User Input Reflected in HTTP Response",
                    "A harmless unique marker was reflected in the response. This is an XSS review candidate, not a confirmed XSS vulnerability; browser-context execution was not tested.",
                    f"HTTP {status}; marker={marker}; reflected=True",
                    ["xss-candidate", "reflection-only", "not-execution-verified"],
                    _evidence_path(ctx, step),
                ))
            evidence = _evidence_path(ctx, step)
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target_url, "http_status": status,
                "marker_reflected": reflected, "body_sample": body[:4000].decode(errors="replace"),
                "classification": "reflection-only; XSS execution not verified",
            }, indent=2), encoding="utf-8")
            return result
        except Exception as exc:
            return StepResult(step_id=str(step.id), success=False,
                              output="EXECUTION_FAILED_OR_BLOCKED", error=str(exc),
                              duration=time.monotonic() - start)


class DirectoryEnumerationModule(_BasicModule):
    name = "DirectoryEnumerationModule"
    domain = AttackDomain.WEB
    required_opportunity_ids = ["opp-sqli-001", "opp-xss-001"]
    required_tools = []
    required_inputs = ["target_url"]
    step_name = "Bounded directory enumeration"
    step_description = "Check a short built-in list of common paths with low concurrency."

    def execute_step(self, step: WorkflowStep, ctx: ModuleContext, operator_inputs: dict) -> StepResult:
        try:
            _validate_same_lab_host(ctx, operator_inputs.get("target_url", ""))
        except ValueError as exc:
            return StepResult(step_id=str(step.id), success=False, output="BLOCKED_BY_VALIDATION", error=str(exc))
        wordfile = None
        try:
            gobuster = shutil.which("gobuster")
            if gobuster:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, prefix="cape_words_") as handle:
                    handle.write("\\n".join(DEFAULT_WORDS) + "\\n")
                    wordfile = Path(handle.name)
                argv = [
                    gobuster, "dir", "-u", operator_inputs["target_url"], "-w", str(wordfile),
                    "-t", "3", "--timeout", "5s", "--no-error", "-q",
                    "-s", "200,204,301,302,307,401,403", "-b", "", "--no-redirect",
                ]
                result = _run(argv, 90, _evidence_path(ctx, step))
                result.step_id = str(step.id)
                paths = [line for line in result.output.splitlines() if line.strip()]
            else:
                # Small sequential fallback for environments without Gobuster.
                found = []
                base_url = operator_inputs["target_url"]
                parsed_base = urlsplit(base_url if "://" in base_url else "http://" + base_url)
                for word in DEFAULT_WORDS:
                    path = (parsed_base.path.rstrip("/") + "/" + word).replace("//", "/")
                    candidate = urlunsplit((parsed_base.scheme, parsed_base.netloc, path, "", ""))
                    try:
                        status, _, _ = safe_http_get(candidate, timeout=3.0, max_bytes=2048)
                    except Exception:
                        continue
                    if status in (200, 204, 301, 302, 307, 401, 403):
                        found.append(f"{status} {path}")
                paths = found
                result = StepResult(
                    step_id=str(step.id), success=True,
                    output="PYTHON_FALLBACK (Gobuster not installed)\\n" + "\\n".join(paths),
                    duration=0.0,
                )
                evidence = _evidence_path(ctx, step)
                evidence.parent.mkdir(parents=True, exist_ok=True)
                evidence.write_text(json.dumps({
                    "target": base_url, "method": "bounded sequential HTTP path checks",
                    "wordlist": DEFAULT_WORDS, "results": paths,
                }, indent=2), encoding="utf-8")
            if result.success:
                result.output = ("EXECUTED_PATHS_FOUND\\n" if paths else "EXECUTED_NO_PATHS_FOUND\\n") + result.output
                for line in paths:
                    result.findings.append(_finding(
                        ctx, "gobuster" if gobuster else "cape-directory-probe",
                        FindingCategory.DIRECTORY, Severity.INFO,
                        "Web Path Discovered",
                        "A common web path returned a configured interesting HTTP status. Review whether it is intended to be public.",
                        line, ["directory-enumeration", "lab"], _evidence_path(ctx, step),
                    ))
            return result
        finally:
            if wordfile:
                wordfile.unlink(missing_ok=True)


class AuthModule(_BasicModule):
    name = "AuthModule"
    domain = AttackDomain.AUTH
    required_opportunity_ids = ["opp-default-creds-001", "opp-ssh-brute-001"]
    required_tools = []
    required_inputs = ["target_url", "username", "password"]
    step_name = "Single-credential HTTP Basic authentication check"
    step_description = "Make exactly one authentication attempt using operator-supplied lab credentials; no brute force."

    def validate_preconditions(self, ctx: ModuleContext) -> ValidationResult:
        base = super().validate_preconditions(ctx)
        if not base.valid:
            return base
        if ctx.findings and not any(
            finding.service in ("http", "https") or finding.port in (80, 443, 8000, 8080, 8443)
            for finding in ctx.findings
        ):
            return ValidationResult(valid=False, missing_requirements=[
                "This bounded AuthModule supports HTTP Basic authentication only; no HTTP service was identified."
            ])
        return ValidationResult(valid=True)

    def execute_step(self, step: WorkflowStep, ctx: ModuleContext, operator_inputs: dict) -> StepResult:
        start = time.monotonic()
        try:
            target_url = operator_inputs["target_url"]
            _validate_same_lab_host(ctx, target_url)
            username = operator_inputs["username"]
            password = operator_inputs["password"]
            if not username or len(username) > 128 or len(password) > 256:
                raise ValueError("A valid dedicated lab username and password are required.")
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            status, headers, body = safe_http_get(
                target_url, headers={"Authorization": f"Basic {token}"}
            )
            # Do not persist the password or Authorization header.
            evidence = _evidence_path(ctx, step)
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target_url, "http_status": status,
                "credential_secret_stored": False,
                "result": "credential accepted" if 200 <= status < 300 else (
                    "credential rejected" if status in (401, 403) else "inconclusive"
                ),
            }, indent=2), encoding="utf-8")
            result = StepResult(
                step_id=str(step.id), success=True,
                output=f"EXECUTED: exactly one attempt\nHTTP status: {status}\n"
                       f"Credential accepted by endpoint: {200 <= status < 300}\n"
                       "A 3xx/other response is inconclusive; no password or authorization header was stored.",
                duration=time.monotonic() - start,
            )
            if 200 <= status < 300:
                result.findings.append(_finding(
                    ctx, "cape-auth-basic", FindingCategory.CREDENTIAL_HINT, Severity.MEDIUM,
                    "Supplied Lab Credential Accepted",
                    "The single operator-supplied credential pair was accepted by the HTTP endpoint. This does not establish that the credential is a default credential.",
                    f"HTTP status {status}; one attempt; username={username}",
                    ["authentication-test", "single-attempt", "lab"], evidence,
                ))
            return result
        except Exception as exc:
            return StepResult(step_id=str(step.id), success=False,
                              output="EXECUTION_FAILED_OR_BLOCKED", error=str(exc),
                              duration=time.monotonic() - start)


class SMBModule(_BasicModule):
    name = "SMBModule"
    domain = AttackDomain.SMB
    required_opportunity_ids = ["opp-smb-relay-001"]
    required_tools = ["nmap"]
    required_inputs = []
    step_name = "Non-destructive SMB enumeration"
    step_description = "Check SMB service metadata, signing configuration and share enumeration using Nmap safe scripts."

    def validate_preconditions(self, ctx: ModuleContext) -> ValidationResult:
        base = super().validate_preconditions(ctx)
        if not base.valid:
            return base
        if ctx.findings and not any(f.port in (139, 445) for f in ctx.findings):
            return ValidationResult(valid=False, missing_requirements=["No SMB port 139/445 in existing findings."])
        return ValidationResult(valid=True)

    def execute_step(self, step: WorkflowStep, ctx: ModuleContext, operator_inputs: dict) -> StepResult:
        try:
            ip, _, _, _ = validate_lab_target(ctx.target)
        except ValueError as exc:
            return StepResult(step_id=str(step.id), success=False, output="BLOCKED_BY_VALIDATION", error=str(exc))
        argv = [
            "nmap", "-Pn", "-n", "-p", "139,445", "--reason",
            "--script", "smb-security-mode,smb2-security-mode,smb-enum-shares",
            "--script-timeout", "15s", ip,
        ]
        result = _run(argv, 60, _evidence_path(ctx, step))
        result.step_id = str(step.id)
        text = result.output.lower()
        if result.success:
            result.output = "EXECUTED\n" + result.output
            if "message_signing: disabled" in text or "signing: disabled" in text:
                result.findings.append(_finding(
                    ctx, "nmap", FindingCategory.SMB, Severity.MEDIUM,
                    "SMB Signing May Not Be Enforced",
                    "Nmap safe SMB scripts reported signing disabled or not required. Verify the exact server policy before concluding relay exposure.",
                    result.output, ["smb", "signing", "lab"], _evidence_path(ctx, step),
                ))
        return result


class HTTPHeadersModule(_BasicModule):
    name = "HTTPHeadersModule"
    domain = AttackDomain.WEB
    required_opportunity_ids = ["opp-sqli-001", "opp-xss-001"]
    required_tools = []
    required_inputs = ["target_url"]
    step_name = "HTTP security-header assessment"
    step_description = "Inspect common HTTP response security headers without modifying the application."

    def execute_step(self, step: WorkflowStep, ctx: ModuleContext, operator_inputs: dict) -> StepResult:
        start = time.monotonic()
        try:
            target_url = operator_inputs["target_url"]
            _validate_same_lab_host(ctx, target_url)
            status, headers, body = safe_http_get(target_url)
            missing = [name for name in WEB_HEADERS if not headers.get(name.lower())]
            if urlsplit(target_url if "://" in target_url else "http://" + target_url).scheme != "https":
                missing = [name for name in missing if name != "Strict-Transport-Security"]
            csp = headers.get("content-security-policy", "").lower()
            if "frame-ancestors" in csp:
                missing = [name for name in missing if name != "X-Frame-Options"]
            weak = []
            if "strict-transport-security" in headers and "max-age=" not in headers["strict-transport-security"].lower():
                weak.append("Strict-Transport-Security")
            if "content-security-policy" in headers and "unsafe-inline" in headers["content-security-policy"].lower():
                weak.append("Content-Security-Policy (contains unsafe-inline)")
            evidence = _evidence_path(ctx, step)
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text(json.dumps({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target_url, "http_status": status,
                "headers": headers, "missing_headers": missing, "weak_headers": weak,
            }, indent=2), encoding="utf-8")
            result = StepResult(
                step_id=str(step.id), success=True,
                output=f"EXECUTED\nHTTP status: {status}\nMissing headers: {', '.join(missing) or 'none'}\n"
                       f"Weak indicators: {', '.join(weak) or 'none'}",
                duration=time.monotonic() - start,
            )
            for name in missing:
                result.findings.append(_finding(
                    ctx, "cape-http-headers", FindingCategory.HEADER,
                    Severity[WEB_HEADERS[name]], f"Missing {name}",
                    f"The HTTP response did not include the {name} security header.",
                    f"HTTP {status}; missing header: {name}",
                    ["http-security-header", "missing-header"], evidence,
                ))
            for item in weak:
                result.findings.append(_finding(
                    ctx, "cape-http-headers", FindingCategory.HEADER, Severity.MEDIUM,
                    f"Weak {item}",
                    "The response contains a security-header configuration that warrants review.",
                    f"HTTP {status}; {item}",
                    ["http-security-header", "weak-header"], evidence,
                ))
            return result
        except Exception as exc:
            return StepResult(step_id=str(step.id), success=False,
                              output="EXECUTION_FAILED_OR_BLOCKED", error=str(exc),
                              duration=time.monotonic() - start)
