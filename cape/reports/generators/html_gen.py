"""HTML report generator using Jinja2 templates.

CAPE report engine upgrade: dispatches to one of four audience-specific
renderers, all built from the same underlying ReportData so a single
assessment can produce a business-friendly CISO summary, an evidence-
oriented auditor report, a fully technical engineer report, or
everything combined.
"""
from __future__ import annotations

import logging
from pathlib import Path

from cape.reports.assembler import ReportData
from cape.reports.generators.base import BaseReportGenerator

logger = logging.getLogger(__name__)


class HTMLReportGenerator(BaseReportGenerator):
    """Generates a styled HTML report from ReportData using Jinja2.

    Dispatches to _render_ciso(), _render_auditor(), _render_engineer(),
    or _render_full() based on report_data.audience.
    """

    def generate(self, report_data: ReportData, output_path: Path) -> Path:
        """Generate the HTML report for whichever audience is set.

        Args:
            report_data: Assembled report data (audience field selects the template).
            output_path: Output file path (should end in .html).

        Returns:
            Path to the generated HTML file.
        """
        try:
            from jinja2 import Environment, select_autoescape
        except ImportError:
            logger.error("Jinja2 not installed: pip install jinja2")
            raise

        output_path.parent.mkdir(parents=True, exist_ok=True)

        env = Environment(autoescape=select_autoescape(["html"]))
        env.filters["severity_badge"] = _severity_badge_class

        dispatch = {
            "ciso": self._render_ciso,
            "auditor": self._render_auditor,
            "engineer": self._render_engineer,
            "full": self._render_full,
        }
        render_fn = dispatch.get(report_data.audience, self._render_full)
        html = render_fn(report_data, env)

        output_path.write_text(html, encoding="utf-8")
        return output_path

    # --- per-audience renderers -------------------------------------------------

    def _render_ciso(self, report_data: ReportData, env) -> str:
        """Executive, business-friendly summary. No technical detail, no port numbers."""
        template = env.from_string(_SHARED_STYLE + _CISO_TEMPLATE)
        top5 = sorted(report_data.opportunities, key=lambda o: o.score, reverse=True)[:5]
        return template.render(
            report=report_data, summary=report_data.scan_summary, top5=top5,
            drift=report_data.drift_summary, remediation_progress=report_data.remediation_progress,
            frameworks=report_data.compliance_frameworks_with_open_findings,
        )

    def _render_auditor(self, report_data: ReportData, env) -> str:
        """Scope, authorization, audit chain integrity, and compliance evidence."""
        template = env.from_string(_SHARED_STYLE + _AUDITOR_TEMPLATE)
        return template.render(
            report=report_data, summary=report_data.scan_summary,
            findings=report_data.findings, compliance=report_data.compliance_by_finding,
            audit_verification=report_data.audit_verification, drift=report_data.drift_summary,
        )

    def _render_engineer(self, report_data: ReportData, env) -> str:
        """Full technical detail: raw evidence, reproduction steps, remediation guidance."""
        template = env.from_string(_SHARED_STYLE + _ENGINEER_TEMPLATE)
        return template.render(
            report=report_data, summary=report_data.scan_summary,
            findings=report_data.findings, opportunities=report_data.opportunities,
            evidence=report_data.evidence, compliance=report_data.compliance_by_finding,
            remediation=report_data.remediation_by_opportunity,
        )

    def _render_full(self, report_data: ReportData, env) -> str:
        """Everything from all three sections, combined into one document."""
        template = env.from_string(_SHARED_STYLE + _FULL_TEMPLATE)
        top5 = sorted(report_data.opportunities, key=lambda o: o.score, reverse=True)[:5]
        return template.render(
            report=report_data, summary=report_data.scan_summary,
            findings=report_data.findings, opportunities=report_data.opportunities,
            evidence=report_data.evidence, compliance=report_data.compliance_by_finding,
            top5=top5, drift=report_data.drift_summary,
            remediation_progress=report_data.remediation_progress,
            frameworks=report_data.compliance_frameworks_with_open_findings,
            audit_verification=report_data.audit_verification,
            remediation=report_data.remediation_by_opportunity,
        )


def _severity_badge_class(severity: str) -> str:
    return f"badge-{str(severity).lower()}"


_SHARED_STYLE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CAPE Report - {{ report.target }}</title>
<style>
  :root { --critical: #dc2626; --high: #ea580c; --medium: #ca8a04; --low: #2563eb; --info: #6b7280; }
  body { font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #0f172a; color: #e2e8f0; }
  .header { background: linear-gradient(135deg, #1e293b, #334155); padding: 30px; border-radius: 12px; margin-bottom: 24px; border-left: 4px solid #3b82f6; }
  .header h1 { margin: 0; font-size: 2rem; color: #f8fafc; }
  .header p { margin: 8px 0 0; color: #94a3b8; }
  .grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }
  .stat-card { background: #1e293b; padding: 16px; border-radius: 8px; text-align: center; }
  .stat-card .num { font-size: 2rem; font-weight: bold; }
  .stat-card .label { font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }
  .critical .num { color: var(--critical); } .high .num { color: var(--high); }
  .medium .num { color: var(--medium); } .low .num { color: var(--low); } .info .num { color: var(--info); }
  section { background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 20px; }
  section h2 { margin-top: 0; color: #f1f5f9; border-bottom: 1px solid #334155; padding-bottom: 10px; }
  table { width: 100%; border-collapse: collapse; }
  th { background: #0f172a; color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; padding: 8px 12px; text-align: left; }
  td { padding: 10px 12px; border-bottom: 1px solid #1e293b; font-size: 0.875rem; }
  tr:hover td { background: #334155; }
  .badge { padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }
  .badge-critical { background: #fee2e2; color: #991b1b; } .badge-high { background: #ffedd5; color: #9a3412; }
  .badge-medium { background: #fef9c3; color: #713f12; } .badge-low { background: #dbeafe; color: #1e40af; }
  .badge-info { background: #f1f5f9; color: #475569; }
  .opp-card { background: #0f172a; border-radius: 8px; padding: 16px; margin-bottom: 12px; border-left: 4px solid #3b82f6; }
  .opp-card h3 { margin: 0 0 8px; color: #f1f5f9; }
  .opp-meta { font-size: 0.8rem; color: #94a3b8; }
  .mitre-link { color: #60a5fa; text-decoration: none; }
  .evidence-block { background: #0f172a; border-radius: 4px; padding: 12px; font-family: monospace; font-size: 0.8rem; color: #4ade80; margin-top: 8px; white-space: pre-wrap; }
  .remediation-block { background: #062e21; border-left: 3px solid #22c55e; border-radius: 4px; padding: 10px 14px; margin-top: 10px; }
  .remediation-block p { margin: 6px 0; }
  .verify-ok { color: #4ade80; font-weight: bold; } .verify-bad { color: #f87171; font-weight: bold; }
  footer { text-align: center; color: #475569; font-size: 0.75rem; margin-top: 20px; }
</style>
</head>
<body>
"""

_HEADER_BLOCK = """<div class="header">
  <h1>CAPE Assessment Report - {{ report.audience | upper }}</h1>
  <p>Target: <strong>{{ report.target }}</strong> &nbsp;|&nbsp;
     Generated: <strong>{{ report.generated_at.strftime('%Y-%m-%d %H:%M UTC') }}</strong>
     {% if report.client_id %} &nbsp;|&nbsp; Client: <strong>{{ report.client_id }}</strong>{% endif %}
  </p>
</div>
"""

_CISO_TEMPLATE = _HEADER_BLOCK + """
<section>
  <h2>Executive Summary</h2>
  <p>A security assessment was conducted against <strong>{{ report.target }}</strong>.
  This report summarizes overall risk posture in business terms - no technical
  detail, raw commands, or network port information is included.</p>
  <div class="grid">
    <div class="stat-card critical"><div class="num">{{ summary.critical_count }}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="num">{{ summary.high_count }}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="num">{{ summary.medium_count }}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="num">{{ summary.low_count }}</div><div class="label">Low</div></div>
    <div class="stat-card info"><div class="num">{{ summary.info_count }}</div><div class="label">Info</div></div>
  </div>
  {% if drift %}
  <p><strong>Trend since last assessment:</strong>
    {% if drift.trend_score > 0 %}improving{% elif drift.trend_score < 0 %}regressing{% else %}unchanged{% endif %}
    ({{ '%.2f' % drift.trend_score }})
  </p>
  {% endif %}
</section>

<section>
  <h2>Top 5 Risk Areas</h2>
  {% for opp in top5 %}
  <div class="opp-card">
    <h3>{{ opp.name }}</h3>
    <div class="opp-meta">Risk score: <strong>{{ '%.1f' % opp.score }}</strong> / 10
      &nbsp;|&nbsp; Severity: <strong>{{ opp.severity.value }}</strong></div>
    <p>{{ opp.description }}</p>
  </div>
  {% else %}
  <p>No significant risk areas identified above the reporting threshold.</p>
  {% endfor %}
</section>

{% if remediation_progress %}
<section>
  <h2>Remediation Progress</h2>
  <p>{{ remediation_progress }}</p>
</section>
{% endif %}

<section>
  <h2>Compliance Posture</h2>
  {% if frameworks %}
  <p>Open findings currently implicate the following compliance frameworks:
    <strong>{{ frameworks | join(', ') }}</strong>. Detailed control mappings are
    available in the auditor report.</p>
  {% else %}
  <p>No open findings currently implicate a tracked compliance framework.</p>
  {% endif %}
</section>

<footer><p>CAPE - Continuous Assurance Pentest Engine &nbsp;|&nbsp; Executive Summary &nbsp;|&nbsp; Confidential</p></footer>
</body></html>"""

_AUDITOR_TEMPLATE = _HEADER_BLOCK + """
<section>
  <h2>Assessment Info</h2>
  <p><strong>Operator:</strong> {{ report.operator or 'Not specified' }}</p>
  <p><strong>Report generated:</strong> {{ report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
</section>

<section>
  <h2>Audit Chain Verification</h2>
  {% if audit_verification %}
    {% if audit_verification.valid %}
      <p class="verify-ok">[OK] {{ audit_verification.message }}</p>
    {% else %}
      <p class="verify-bad">[BROKEN] {{ audit_verification.message }}</p>
    {% endif %}
    <p>Total entries inspected: {{ audit_verification.total_entries }}</p>
  {% else %}
    <p>Audit chain verification was not available at report generation time.</p>
  {% endif %}
</section>

<section>
  <h2>Findings with Compliance Control Mapping ({{ findings|length }})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>PCI-DSS</th><th>SOC2</th><th>ISO27001</th><th>NIST CSF</th><th>CIS</th></tr></thead>
    <tbody>
    {% for f in findings %}
      {% set c = compliance.get(f.id|string, {}) %}
      <tr>
        <td><span class="badge {{ f.severity.value | severity_badge }}">{{ f.severity.value }}</span></td>
        <td>{{ f.title | truncate(80) }}</td>
        <td>{{ c.get('pci_dss', []) | join(', ') or '-' }}</td>
        <td>{{ c.get('soc2', []) | join(', ') or '-' }}</td>
        <td>{{ c.get('iso27001', []) | join(', ') or '-' }}</td>
        <td>{{ c.get('nist_csf', []) | join(', ') or '-' }}</td>
        <td>{{ c.get('cis_controls', []) | join(', ') or '-' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</section>

{% if drift %}
<section>
  <h2>Drift Since Last Assessment</h2>
  <p>NEW: {{ drift.new_count }} &nbsp;|&nbsp; FIXED: {{ drift.fixed_count }} &nbsp;|&nbsp;
     REGRESSED: {{ drift.regressed_count }} &nbsp;|&nbsp; PERSISTENT: {{ drift.persistent_count }} &nbsp;|&nbsp;
     IMPROVED: {{ drift.improved_count }}</p>
</section>
{% endif %}

<footer><p>CAPE - Continuous Assurance Pentest Engine &nbsp;|&nbsp; Auditor Report &nbsp;|&nbsp; No exploitation detail included</p></footer>
</body></html>"""

_ENGINEER_TEMPLATE = _HEADER_BLOCK + """
<section>
  <h2>Full Findings Table ({{ findings|length }})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Tool</th><th>Host</th><th>Port</th><th>Service</th><th>Category</th></tr></thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td><span class="badge {{ f.severity.value | severity_badge }}">{{ f.severity.value }}</span></td>
        <td>{{ f.title }}</td><td>{{ f.source_tool }}</td><td>{{ f.host }}</td>
        <td>{{ f.port or '-' }}</td><td>{{ f.service or '-' }}</td><td>{{ f.category.value }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</section>

<section>
  <h2>Reproduction Steps &amp; Evidence</h2>
  {% for f in findings %}
  <div class="opp-card">
    <h3>{{ f.title }}</h3>
    <div class="opp-meta">Tool: {{ f.source_tool }} &nbsp;|&nbsp; Profile: {{ f.scan_profile }} &nbsp;|&nbsp;
      Confidence: {{ '%.0f%%' % (f.confidence * 100) }}</div>
    <p>{{ f.description }}</p>
    <div class="evidence-block">{{ f.evidence }}</div>
    {% if f.remediation %}<p><strong>Remediation:</strong> {{ f.remediation }}</p>{% endif %}
    {% set c = compliance.get(f.id|string, {}) %}
    {% if c.get('pci_dss') or c.get('soc2') or c.get('iso27001') or c.get('nist_csf') or c.get('cis_controls') %}
    <p><strong>Compliance:</strong>
      {% if c.get('pci_dss') %}PCI-DSS {{ c.pci_dss | join(', ') }}{% endif %}
      {% if c.get('soc2') %} &nbsp;SOC2 {{ c.soc2 | join(', ') }}{% endif %}
      {% if c.get('iso27001') %} &nbsp;ISO27001 {{ c.iso27001 | join(', ') }}{% endif %}
      {% if c.get('nist_csf') %} &nbsp;NIST CSF {{ c.nist_csf | join(', ') }}{% endif %}
      {% if c.get('cis_controls') %} &nbsp;CIS {{ c.cis_controls | join(', ') }}{% endif %}
    </p>
    {% endif %}
  </div>
  {% endfor %}
</section>

<section>
  <h2>Attack Opportunities &amp; Scoring ({{ opportunities|length }})</h2>
  {% for opp in opportunities %}
  <div class="opp-card">
    <h3>{{ opp.name }}</h3>
    <div class="opp-meta">Score: <strong>{{ '%.1f' % opp.score }}</strong> &nbsp;|&nbsp;
      Severity: {{ opp.severity.value }} &nbsp;|&nbsp; Domain: {{ opp.domain.value }} &nbsp;|&nbsp;
      Rule: {{ opp.rule_id }}
      {% if opp.mitre_technique %} &nbsp;|&nbsp; MITRE: <a class="mitre-link" href="https://attack.mitre.org/techniques/{{ opp.mitre_technique }}/">{{ opp.mitre_technique }}</a>{% endif %}
    </div>
    <p>{{ opp.description }}</p>
    <p><em>{{ opp.explanation }}</em></p>
    {% if opp.recommended_modules %}<p><strong>Recommended modules:</strong> {{ opp.recommended_modules | join(', ') }}</p>{% endif %}
    {% set r = remediation.get(opp.id|string) %}
    {% if r %}
    <div class="remediation-block">
      <p><strong>Remediation priority:</strong> {{ r.priority }}</p>
      {% for cm in r.countermeasures %}
      <p>&bull; <strong>[{{ cm.stage | replace('_', '-') }}] {{ cm.title }}</strong>{% if cm.mitre_mitigation %} <span class="opp-meta">(MITRE {{ cm.mitre_mitigation }})</span>{% endif %}<br>
        <span class="opp-meta">{{ cm.description }}</span></p>
      {% endfor %}
      {% if r.verification_steps %}
      <p><strong>Verify the fix:</strong></p>
      <ul>{% for step in r.verification_steps %}<li>{{ step }}</li>{% endfor %}</ul>
      {% endif %}
    </div>
    {% endif %}
    <p><em>Run <code>cape explain {{ report.target }} --opportunity-id {{ opp.id }} --deep</code> for the full scoring trace and countermeasures.</em></p>
  </div>
  {% endfor %}
</section>

{% if evidence %}
<section>
  <h2>Evidence Appendix - Commands Run</h2>
  {% for ev in evidence %}
  <div class="opp-card">
    <h3>{{ ev.tool }} - {{ ev.summary }}</h3>
    <div class="opp-meta">Timestamp: {{ ev.timestamp }}</div>
    <div class="evidence-block">{{ ev.command_run }}</div>
  </div>
  {% endfor %}
</section>
{% endif %}

<footer><p>CAPE - Continuous Assurance Pentest Engine &nbsp;|&nbsp; Engineer Report</p></footer>
</body></html>"""

_FULL_TEMPLATE = _HEADER_BLOCK + """
<section>
  <h2>Executive Summary</h2>
  <div class="grid">
    <div class="stat-card critical"><div class="num">{{ summary.critical_count }}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="num">{{ summary.high_count }}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="num">{{ summary.medium_count }}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="num">{{ summary.low_count }}</div><div class="label">Low</div></div>
    <div class="stat-card info"><div class="num">{{ summary.info_count }}</div><div class="label">Info</div></div>
  </div>
  {% if remediation_progress %}<p>{{ remediation_progress }}</p>{% endif %}
</section>

<section>
  <h2>Top 5 Opportunities</h2>
  {% for opp in top5 %}
  <div class="opp-card"><h3>{{ opp.name }}</h3>
    <div class="opp-meta">Score: {{ '%.1f' % opp.score }} | Severity: {{ opp.severity.value }}</div>
    <p>{{ opp.description }}</p></div>
  {% endfor %}
</section>

<section>
  <h2>Assessment Info</h2>
  <p><strong>Operator:</strong> {{ report.operator or 'Not specified' }}</p>
</section>

<section>
  <h2>Audit Chain Verification</h2>
  {% if audit_verification %}
    {% if audit_verification.valid %}<p class="verify-ok">[OK] {{ audit_verification.message }}</p>
    {% else %}<p class="verify-bad">[BROKEN] {{ audit_verification.message }}</p>{% endif %}
  {% else %}<p>Not available.</p>{% endif %}
</section>

<section>
  <h2>Compliance Posture</h2>
  <p>Frameworks with open findings: {{ frameworks | join(', ') if frameworks else 'None' }}</p>
</section>

{% if drift %}
<section>
  <h2>Drift Since Last Assessment</h2>
  <p>NEW: {{ drift.new_count }} | FIXED: {{ drift.fixed_count }} | REGRESSED: {{ drift.regressed_count }} |
     PERSISTENT: {{ drift.persistent_count }} | IMPROVED: {{ drift.improved_count }}</p>
</section>
{% endif %}

<section>
  <h2>Full Findings Table ({{ findings|length }})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Tool</th><th>Host</th><th>Port</th><th>Category</th><th>PCI-DSS</th></tr></thead>
    <tbody>
    {% for f in findings %}
      {% set c = compliance.get(f.id|string, {}) %}
      <tr>
        <td><span class="badge {{ f.severity.value | severity_badge }}">{{ f.severity.value }}</span></td>
        <td>{{ f.title | truncate(80) }}</td><td>{{ f.source_tool }}</td><td>{{ f.host }}</td>
        <td>{{ f.port or '-' }}</td><td>{{ f.category.value }}</td>
        <td>{{ c.get('pci_dss', []) | join(', ') or '-' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</section>

<section>
  <h2>Attack Opportunities ({{ opportunities|length }})</h2>
  {% for opp in opportunities %}
  <div class="opp-card"><h3>{{ opp.name }}</h3>
    <div class="opp-meta">Score: {{ '%.1f' % opp.score }} | Severity: {{ opp.severity.value }} | Rule: {{ opp.rule_id }}</div>
    <p>{{ opp.description }}</p><p><em>{{ opp.explanation }}</em></p>
    {% set r = remediation.get(opp.id|string) %}
    {% if r %}
    <div class="remediation-block">
      <p><strong>Remediation priority:</strong> {{ r.priority }}</p>
      {% for cm in r.countermeasures %}
      <p>&bull; <strong>[{{ cm.stage | replace('_', '-') }}] {{ cm.title }}</strong><br>
        <span class="opp-meta">{{ cm.description }}</span></p>
      {% endfor %}
    </div>
    {% endif %}
  </div>
  {% endfor %}
</section>

{% if evidence %}
<section>
  <h2>Evidence Appendix</h2>
  {% for ev in evidence %}
  <div class="opp-card"><h3>{{ ev.tool }} - {{ ev.summary }}</h3>
    <div class="opp-meta">Timestamp: {{ ev.timestamp }}</div>
    <div class="evidence-block">{{ ev.command_run }}</div></div>
  {% endfor %}
</section>
{% endif %}

<footer><p>CAPE - Continuous Assurance Pentest Engine &nbsp;|&nbsp; Full Report &nbsp;|&nbsp; Confidential</p></footer>
</body></html>"""
