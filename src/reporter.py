"""
reporter.py
-----------
Generates two output formats from a list of findings:
  1. JSON report  – machine-readable, CI/CD-friendly
  2. HTML report  – human-readable, send to client / interviewer

The HTML template is embedded as a Jinja2 string (no external files needed).
It includes:
  - Executive summary with severity counts
  - Full findings table with evidence links
  - Per-finding remediation guidance
  - Risk chart (pure CSS, no JavaScript required)
"""

import json
import os
from datetime import datetime, timezone
from jinja2 import Template


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vigilant-API Security Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e2e8f0; padding: 40px; }
  h1 { color: #63b3ed; font-size: 2rem; margin-bottom: 4px; }
  .subtitle { color: #718096; margin-bottom: 32px; font-size: 0.9rem; }
  .meta { background: #1a202c; border-radius: 8px; padding: 20px; margin-bottom: 32px; display: flex; gap: 40px; }
  .meta-item label { display: block; font-size: 0.75rem; color: #718096; text-transform: uppercase; letter-spacing: 1px; }
  .meta-item span  { font-size: 1.4rem; font-weight: 700; }
  .critical { color: #fc8181; } .high { color: #f6ad55; }
  .medium   { color: #f6e05e; } .low  { color: #68d391; }
  h2 { color: #63b3ed; margin: 32px 0 16px; font-size: 1.2rem; }
  table { width: 100%; border-collapse: collapse; background: #1a202c; border-radius: 8px; overflow: hidden; }
  th { background: #2d3748; padding: 12px 16px; text-align: left; font-size: 0.8rem;
       text-transform: uppercase; letter-spacing: 1px; color: #a0aec0; }
  td { padding: 12px 16px; border-top: 1px solid #2d3748; font-size: 0.9rem; vertical-align: top; }
  tr:hover td { background: #2d3748; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; }
  .badge-CRITICAL { background: #742a2a; color: #fc8181; }
  .badge-HIGH     { background: #7b341e; color: #f6ad55; }
  .badge-MEDIUM   { background: #744210; color: #f6e05e; }
  .badge-LOW      { background: #1c4532; color: #68d391; }
  .badge-INFO     { background: #2a4365; color: #90cdf4; }
  .code { font-family: monospace; font-size: 0.8rem; background: #2d3748; padding: 2px 6px; border-radius: 4px; }
  .remediation { font-size: 0.85rem; color: #a0aec0; border-left: 3px solid #3182ce; padding-left: 12px; margin-top: 6px; }
  a { color: #63b3ed; text-decoration: none; }
  a:hover { text-decoration: underline; }
  footer { margin-top: 40px; text-align: center; color: #4a5568; font-size: 0.8rem; }
</style>
</head>
<body>

<h1>🛡️ Vigilant-API Security Assessment</h1>
<p class="subtitle">Generated: {{ generated_at }} | Target: {{ target }}</p>

<div class="meta">
  <div class="meta-item"><label>Endpoints Tested</label><span>{{ endpoints_tested }}</span></div>
  <div class="meta-item"><label>Total Findings</label><span>{{ total_findings }}</span></div>
  <div class="meta-item"><label>Critical</label><span class="critical">{{ counts.CRITICAL }}</span></div>
  <div class="meta-item"><label>High</label><span class="high">{{ counts.HIGH }}</span></div>
  <div class="meta-item"><label>Medium</label><span class="medium">{{ counts.MEDIUM }}</span></div>
  <div class="meta-item"><label>Low</label><span class="low">{{ counts.LOW }}</span></div>
</div>

<h2>Findings</h2>
{% if findings %}
<table>
  <thead>
    <tr>
      <th>ID</th><th>Type</th><th>Check</th><th>Severity</th>
      <th>Endpoint / Parameter</th><th>Evidence & Remediation</th>
    </tr>
  </thead>
  <tbody>
  {% for f in findings %}
    {% set vuln = f.vulnerability %}
    <tr>
      <td><span class="code">{{ f.metadata.finding_id }}</span></td>
      <td>{{ vuln.type }}</td>
      <td>{{ vuln.check }}</td>
      <td><span class="badge badge-{{ vuln.severity }}">{{ vuln.severity }}</span></td>
      <td>
        <span class="code">{{ vuln.endpoint or '—' }}</span>
        {% if vuln.parameter %}<br><small>param: {{ vuln.parameter }}</small>{% endif %}
        {% if vuln.resource_id %}<br><small>id: {{ vuln.resource_id }}</small>{% endif %}
      </td>
      <td>
        {% if f.evidence.payload %}
          <div><small>Payload:</small> <span class="code">{{ f.evidence.payload }}</span></div>
        {% endif %}
        {% if f.evidence.body_preview %}
          <div><small>Response:</small> <span class="code">{{ f.evidence.body_preview[:120] }}</span></div>
        {% endif %}
        <p class="remediation">{{ f.remediation }}</p>
        {% if f._evidence_href %}
          <a href="{{ f._evidence_href }}">📄 Full Evidence</a>
        {% endif %}
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p style="color: #68d391;">✅ No vulnerabilities detected.</p>
{% endif %}

<footer>
  Vigilant-API v1.0 · rootverdict · Built as part of 32-Week AppSec Roadmap
</footer>
</body>
</html>
"""


class ReportGenerator:

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def generate_json(self, findings: list, meta: dict, output_file: str = None) -> str:
        """
        Write a machine-readable JSON report.
        Returns the file path.
        """
        if output_file is None:
            output_file = os.path.join(self.output_dir, 'report.json')

        report = {
            'scan_meta':   meta,
            'summary':     self._build_summary(findings),
            'findings':    findings,
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        return output_file

    def generate_html(self, findings: list, meta: dict, output_file: str = None) -> str:
        """
        Write a styled HTML report.
        Returns the file path.
        """
        if output_file is None:
            output_file = os.path.join(self.output_dir, 'report.html')

        counts   = self._build_summary(findings)
        template = Template(HTML_TEMPLATE)
        output_dir = os.path.dirname(output_file)

        rendered_findings = []
        for finding in findings:
            rendered = dict(finding)
            evidence_file = rendered.get('_evidence_file')
            if evidence_file:
                rendered['_evidence_href'] = os.path.relpath(evidence_file, start=output_dir).replace('\\', '/')
            rendered_findings.append(rendered)

        html = template.render(
            generated_at     = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
            target           = meta.get('target', 'Unknown'),
            endpoints_tested = meta.get('endpoints_tested', '—'),
            total_findings   = len(findings),
            counts           = counts,
            findings         = rendered_findings,
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_file

    # ------------------------------------------------------------------ #
    #  Private                                                             #
    # ------------------------------------------------------------------ #

    def _build_summary(self, findings: list) -> dict:
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in findings:
            sev = f.get('vulnerability', {}).get('severity', 'INFO')
            summary[sev] = summary.get(sev, 0) + 1
        return summary
