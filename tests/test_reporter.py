"""Tests for report generation.

The HTML report embeds data captured from the *target* - response bodies,
payloads, endpoint paths. That data is attacker-influenced, so the escaping
behaviour of the template is a security property of the tool itself, not a
cosmetic detail: an analyst opens report.html locally, and an unescaped
response body would execute script in their browser.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from reporter import ReportGenerator


def _finding(**overrides):
    finding = {
        'metadata': {'finding_id': 'ABC123'},
        'vulnerability': {
            'type': 'SSRF',
            'check': 'Basic SSRF',
            'severity': 'CRITICAL',
            'method': 'GET',
            'endpoint': '/fetch',
            'parameter': 'url',
            'resource_id': None,
        },
        'evidence': {'payload': 'http://169.254.169.254/', 'body_preview': 'ami-id'},
        'remediation': 'Use an allowlist.',
    }
    finding.update(overrides)
    return finding


class TestHtmlEscaping:

    def test_script_in_response_body_is_escaped(self, tmp_path):
        """A malicious target response must not become live markup in the report."""
        payload = '<script>alert(1)</script>'
        generator = ReportGenerator(str(tmp_path))
        path = generator.generate_html(
            [_finding(evidence={'payload': 'x', 'body_preview': payload})],
            {'target': 'http://target', 'endpoints_tested': 1},
        )
        html = Path(path).read_text(encoding='utf-8')

        assert '<script>alert(1)</script>' not in html
        assert '&lt;script&gt;' in html

    def test_script_in_target_metadata_is_escaped(self, tmp_path):
        """Scan metadata is rendered outside the findings loop - escape it too."""
        generator = ReportGenerator(str(tmp_path))
        path = generator.generate_html(
            [],
            {'target': '<img src=x onerror=alert(1)>', 'endpoints_tested': 0},
        )
        html = Path(path).read_text(encoding='utf-8')

        assert '<img src=x onerror=alert(1)>' not in html
        assert '&lt;img' in html

    def test_script_in_endpoint_path_is_escaped(self, tmp_path):
        """Endpoint strings come from the spec, which may itself be untrusted."""
        vuln = dict(_finding()['vulnerability'], endpoint='/x"><script>alert(1)</script>')
        generator = ReportGenerator(str(tmp_path))
        path = generator.generate_html(
            [_finding(vulnerability=vuln)],
            {'target': 'http://target', 'endpoints_tested': 1},
        )
        html = Path(path).read_text(encoding='utf-8')

        assert '<script>alert(1)</script>' not in html


class TestHtmlContent:

    def test_mock_only_findings_are_badged(self, tmp_path):
        """Findings that are only meaningful against the bundled mock server are
        labelled, so a reader never mistakes one for a live-target result."""
        generator = ReportGenerator(str(tmp_path))
        path = generator.generate_html(
            [_finding(evidence={'mock_only': True, 'payload': 'c', 'body_preview': 'b'})],
            {'target': 'http://target', 'endpoints_tested': 1},
        )
        html = Path(path).read_text(encoding='utf-8')

        assert 'mock-server only' in html
        assert 'class="mock-badge"' in html

    def test_genuine_findings_are_not_badged(self, tmp_path):
        generator = ReportGenerator(str(tmp_path))
        path = generator.generate_html(
            [_finding()], {'target': 'http://target', 'endpoints_tested': 1},
        )
        html = Path(path).read_text(encoding='utf-8')

        assert 'mock-server only' not in html

    def test_empty_scan_reports_no_vulnerabilities(self, tmp_path):
        generator = ReportGenerator(str(tmp_path))
        path = generator.generate_html([], {'target': 'http://target', 'endpoints_tested': 5})
        html = Path(path).read_text(encoding='utf-8')

        assert 'No vulnerabilities detected' in html

    def test_evidence_link_is_relative_to_the_report(self, tmp_path):
        """The href must resolve when the reports directory is moved or zipped,
        so it is stored relative to report.html with forward slashes."""
        evidence = tmp_path / 'evidence' / 'evidence_1.json'
        evidence.parent.mkdir()
        evidence.write_text('{}', encoding='utf-8')

        generator = ReportGenerator(str(tmp_path))
        path = generator.generate_html(
            [_finding(_evidence_file=str(evidence))],
            {'target': 'http://target', 'endpoints_tested': 1},
        )
        html = Path(path).read_text(encoding='utf-8')

        assert 'href="evidence/evidence_1.json"' in html
        assert '\\' not in 'evidence/evidence_1.json'


class TestJsonReport:

    def test_summary_counts_findings_by_severity(self, tmp_path):
        generator = ReportGenerator(str(tmp_path))
        findings = [
            _finding(),
            _finding(vulnerability=dict(_finding()['vulnerability'], severity='LOW')),
            _finding(vulnerability=dict(_finding()['vulnerability'], severity='LOW')),
        ]
        path = generator.generate_json(findings, {'target': 'http://target'})
        report = json.loads(Path(path).read_text(encoding='utf-8'))

        assert report['summary']['CRITICAL'] == 1
        assert report['summary']['LOW'] == 2
        assert report['summary']['HIGH'] == 0
        assert len(report['findings']) == 3

    def test_unserialisable_values_do_not_crash_the_report(self, tmp_path):
        """Detectors may attach objects json cannot encode; the report must still
        be written, since it is the only durable output of a scan."""
        generator = ReportGenerator(str(tmp_path))
        path = generator.generate_json(
            [_finding(evidence={'response': object()})], {'target': 'http://target'},
        )
        report = json.loads(Path(path).read_text(encoding='utf-8'))

        assert len(report['findings']) == 1
