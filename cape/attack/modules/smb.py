"""SMB attack module for CAPE."""
from __future__ import annotations
import uuid
from cape.attack.models import AttackSession, ModuleContext, ToolPreparationResult, ValidationResult
from cape.attack.modules.base import BaseAttackModule
from cape.plan.models import WorkflowStep
from cape.scan.plugins.base import StepResult
from cape.shared.enums import AttackDomain, FindingCategory, Severity
from cape.shared.finding import Finding


class SMBModule(BaseAttackModule):
    name = "SMBModule"
    domain = AttackDomain.SMB
    required_opportunity_ids = ["opp-smb-relay-001"]
    required_tools = ["enum4linux", "nmap"]

    def load_context(self, target, session, findings):
        return ModuleContext(target=target, session=session, findings=findings)

    def validate_preconditions(self, ctx):
        smb = [f for f in ctx.findings if f.port in (139, 445)]
        if not smb:
            return ValidationResult(valid=False, missing_requirements=["No SMB port found (139/445)"])
        return ValidationResult(valid=True)

    def get_steps(self, ctx):
        pid = uuid.uuid4()
        s1, s2, s3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        return [
            WorkflowStep(id=s1, plan_id=pid, step_number=1, name="SMB Enumeration",
                domain=AttackDomain.SMB, tool="enum4linux",
                tool_args_template="enum4linux -a {target}",
                description="Enumerate SMB shares, users, OS info, and security settings",
                estimated_duration_seconds=300, operator_action_required=False),
            WorkflowStep(id=s2, plan_id=pid, step_number=2, name="SMB Signing Check",
                domain=AttackDomain.SMB, tool="nmap",
                tool_args_template="nmap -p 445 --script smb-security-mode,smb2-security-mode {target}",
                description="Check if SMB signing is enforced",
                prerequisites=[s1], estimated_duration_seconds=60, operator_action_required=False),
            WorkflowStep(id=s3, plan_id=pid, step_number=3, name="SMB Relay Feasibility Assessment",
                domain=AttackDomain.SMB, tool=None, tool_args_template=None,
                description="If signing disabled, assess relay attack. Use ntlmrelayx in authorized lab environment.",
                prerequisites=[s2], estimated_duration_seconds=900, operator_action_required=True,
                notes="Requires: responder + ntlmrelayx. ONLY in authorized network segment."),
        ]

    def prepare_tools(self, ctx): return self._check_tools()
    def execute_step(self, step, ctx, operator_inputs):
        return StepResult(step_id=str(step.id), success=False, output="GUIDED_ONLY_NOT_EXECUTED: this legacy workflow still requires manual implementation.", duration=0.0)
    def collect_results(self, step_results): return []
    def persist_results(self, findings, session): pass


class AuthModule(BaseAttackModule):
    name = "AuthModule"
    domain = AttackDomain.AUTH
    required_opportunity_ids = ["opp-default-creds-001", "opp-ssh-brute-001"]
    required_tools = ["hydra"]

    def load_context(self, target, session, findings):
        return ModuleContext(target=target, session=session, findings=findings)

    def validate_preconditions(self, ctx):
        auth_services = [f for f in ctx.findings if f.port in (21, 22, 23, 80, 443, 3306)]
        if not auth_services:
            return ValidationResult(valid=False, missing_requirements=["No authentication services found"])
        return ValidationResult(valid=True)

    def get_steps(self, ctx):
        pid = uuid.uuid4()
        s1, s2 = uuid.uuid4(), uuid.uuid4()
        return [
            WorkflowStep(id=s1, plan_id=pid, step_number=1, name="Default Credential Test",
                domain=AttackDomain.AUTH, tool="hydra",
                tool_args_template="hydra -L /usr/share/wordlists/metasploit/default_usernames.txt -P /usr/share/wordlists/metasploit/default_passwords.txt {target} ssh",
                description="Test SSH for default credentials",
                estimated_duration_seconds=600, operator_action_required=True,
                notes="Replace 'ssh' with target service. Always get written authorization first."),
            WorkflowStep(id=s2, plan_id=pid, step_number=2, name="Account Lockout Verification",
                domain=AttackDomain.AUTH, tool=None, tool_args_template=None,
                description="Manually verify account lockout policies to avoid locking out users",
                prerequisites=[s1], estimated_duration_seconds=300, operator_action_required=True),
        ]

    def prepare_tools(self, ctx): return self._check_tools()
    def execute_step(self, step, ctx, operator_inputs):
        return StepResult(step_id=str(step.id), success=False, output="GUIDED_ONLY_NOT_EXECUTED: this legacy workflow still requires manual implementation.", duration=0.0)
    def collect_results(self, step_results): return []
    def persist_results(self, findings, session): pass


class CMSModule(BaseAttackModule):
    execution_mode = "GUIDED_ONLY"
    name = "CMSModule"
    domain = AttackDomain.CMS
    required_opportunity_ids = ["opp-wordpress-001", "opp-cms-generic-001"]
    required_tools = ["wpscan"]

    def load_context(self, target, session, findings):
        return ModuleContext(target=target, session=session, findings=findings)

    def validate_preconditions(self, ctx):
        cms = [f for f in ctx.findings if f.category.value == "CMS"]
        if not cms:
            return ValidationResult(valid=False, missing_requirements=["No CMS detected in findings"])
        return ValidationResult(valid=True)

    def get_steps(self, ctx):
        pid = uuid.uuid4()
        s1, s2 = uuid.uuid4(), uuid.uuid4()
        url = f"http://{ctx.target}"
        return [
            WorkflowStep(id=s1, plan_id=pid, step_number=1, name="WordPress Deep Scan",
                domain=AttackDomain.CMS, tool="wpscan",
                tool_args_template=f"wpscan --url {url} --enumerate p,t,u,vp,vt --format json",
                description="Deep WordPress vulnerability and enumeration scan",
                estimated_duration_seconds=600, operator_action_required=False),
            WorkflowStep(id=s2, plan_id=pid, step_number=2, name="Plugin Vulnerability Exploit",
                domain=AttackDomain.CMS, tool=None, tool_args_template=None,
                description="Review wpscan output and exploit vulnerable plugins/themes",
                prerequisites=[s1], estimated_duration_seconds=900, operator_action_required=True,
                notes="Use searchsploit for CVEs found. Document exploitation steps."),
        ]

    def prepare_tools(self, ctx): return self._check_tools()
    def execute_step(self, step, ctx, operator_inputs):
        return StepResult(step_id=str(step.id), success=False, output="GUIDED_ONLY_NOT_EXECUTED: this legacy workflow still requires manual implementation.", duration=0.0)
    def collect_results(self, step_results): return []
    def persist_results(self, findings, session): pass


class NetworkModule(BaseAttackModule):
    execution_mode = "GUIDED_ONLY"
    name = "NetworkModule"
    domain = AttackDomain.NETWORK
    required_opportunity_ids = ["opp-snmp-001", "opp-rdp-001"]
    required_tools = ["nmap", "snmp-check"]

    def load_context(self, target, session, findings):
        return ModuleContext(target=target, session=session, findings=findings)

    def validate_preconditions(self, ctx): return ValidationResult(valid=True)

    def get_steps(self, ctx):
        pid = uuid.uuid4()
        s1, s2 = uuid.uuid4(), uuid.uuid4()
        return [
            WorkflowStep(id=s1, plan_id=pid, step_number=1, name="SNMP Enumeration",
                domain=AttackDomain.NETWORK, tool="snmp-check",
                tool_args_template="snmp-check {target} -c public -v 2c",
                description="Enumerate SNMP with default community string",
                estimated_duration_seconds=120, operator_action_required=False),
            WorkflowStep(id=s2, plan_id=pid, step_number=2, name="RDP Encryption Assessment",
                domain=AttackDomain.NETWORK, tool="nmap",
                tool_args_template="nmap -p 3389 --script rdp-enum-encryption {target}",
                description="Check RDP NLA enforcement and encryption level",
                estimated_duration_seconds=60, operator_action_required=False),
        ]

    def prepare_tools(self, ctx): return self._check_tools()
    def execute_step(self, step, ctx, operator_inputs):
        return StepResult(step_id=str(step.id), success=False, output="GUIDED_ONLY_NOT_EXECUTED: this legacy workflow still requires manual implementation.", duration=0.0)
    def collect_results(self, step_results): return []
    def persist_results(self, findings, session): pass


class XSSModule(BaseAttackModule):
    name = "XSSModule"
    domain = AttackDomain.WEB
    required_opportunity_ids = ["opp-xss-001"]
    required_tools = []

    def load_context(self, target, session, findings):
        return ModuleContext(target=target, session=session, findings=findings)

    def validate_preconditions(self, ctx):
        web = [f for f in ctx.findings if f.service in ("http", "https")]
        if not web:
            return ValidationResult(valid=False, missing_requirements=["No web service found"])
        return ValidationResult(valid=True)

    def get_steps(self, ctx):
        pid = uuid.uuid4()
        s1 = uuid.uuid4()
        return [
            WorkflowStep(id=s1, plan_id=pid, step_number=1, name="XSS Testing",
                domain=AttackDomain.WEB, tool=None, tool_args_template=None,
                description="Manually test for reflected, stored, and DOM-based XSS",
                estimated_duration_seconds=900, operator_action_required=True,
                notes="Test payloads: <script>alert(1)</script>, ><img src=x onerror=alert(1)>. Use browser DevTools."),
        ]

    def prepare_tools(self, ctx): return self._check_tools()
    def execute_step(self, step, ctx, operator_inputs):
        return StepResult(step_id=str(step.id), success=True, output="Manual XSS testing step", duration=0.0)
    def collect_results(self, step_results): return []
    def persist_results(self, findings, session): pass


class APIModule(BaseAttackModule):
    execution_mode = "GUIDED_ONLY"
    name = "APIModule"
    domain = AttackDomain.API
    required_opportunity_ids = ["opp-api-auth-001"]
    required_tools = ["gobuster"]

    def load_context(self, target, session, findings):
        return ModuleContext(target=target, session=session, findings=findings)

    def validate_preconditions(self, ctx): return ValidationResult(valid=True)

    def get_steps(self, ctx):
        pid = uuid.uuid4()
        s1, s2 = uuid.uuid4(), uuid.uuid4()
        return [
            WorkflowStep(id=s1, plan_id=pid, step_number=1, name="API Endpoint Discovery",
                domain=AttackDomain.API, tool="gobuster",
                tool_args_template="gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/big.txt -q",
                description="Enumerate API endpoints",
                estimated_duration_seconds=600, operator_action_required=False),
            WorkflowStep(id=s2, plan_id=pid, step_number=2, name="API Auth Testing",
                domain=AttackDomain.API, tool=None, tool_args_template=None,
                description="Test API authentication: missing auth, JWT manipulation, IDOR",
                prerequisites=[s1], estimated_duration_seconds=900, operator_action_required=True,
                notes="Test: unauthenticated endpoints, JWT alg=none, IDOR via ID manipulation"),
        ]

    def prepare_tools(self, ctx): return self._check_tools()
    def execute_step(self, step, ctx, operator_inputs):
        return StepResult(step_id=str(step.id), success=False, output="GUIDED_ONLY_NOT_EXECUTED: this legacy workflow still requires manual implementation.", duration=0.0)
    def collect_results(self, step_results): return []
    def persist_results(self, findings, session): pass


class UploadModule(BaseAttackModule):
    execution_mode = "GUIDED_ONLY"
    name = "UploadModule"
    domain = AttackDomain.WEB
    required_opportunity_ids = []
    required_tools = []

    def load_context(self, target, session, findings):
        return ModuleContext(target=target, session=session, findings=findings)

    def validate_preconditions(self, ctx): return ValidationResult(valid=True)
    def get_steps(self, ctx): return []
    def prepare_tools(self, ctx): return self._check_tools()
    def execute_step(self, step, ctx, operator_inputs):
        return StepResult(step_id=str(step.id), success=False, output="GUIDED_ONLY_NOT_EXECUTED: this legacy workflow still requires manual implementation.", duration=0.0)
    def collect_results(self, step_results): return []
    def persist_results(self, findings, session): pass


class WirelessModule(BaseAttackModule):
    execution_mode = "GUIDED_ONLY"
    name = "WirelessModule"
    domain = AttackDomain.WIRELESS
    required_opportunity_ids = []
    required_tools = ["aircrack-ng", "kismet"]

    def load_context(self, target, session, findings):
        return ModuleContext(target=target, session=session, findings=findings)

    def validate_preconditions(self, ctx):
        return ValidationResult(valid=True, warnings=["Requires monitor-mode wireless adapter"])
    def get_steps(self, ctx): return []
    def prepare_tools(self, ctx): return self._check_tools()
    def execute_step(self, step, ctx, operator_inputs):
        return StepResult(step_id=str(step.id), success=False, output="GUIDED_ONLY_NOT_EXECUTED: this legacy workflow still requires manual implementation.", duration=0.0)
    def collect_results(self, step_results): return []
    def persist_results(self, findings, session): pass


# Backward-compatible imports of the bounded implementations.
from cape.attack.modules.basic import SMBModule, AuthModule, XSSModule  # noqa: E402,F401
