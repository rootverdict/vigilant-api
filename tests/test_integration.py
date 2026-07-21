"""
tests/test_integration.py
--------------------------
End-to-end integration test: starts the mock Flask server on port 5099,
runs a full Scanner scan against it, and asserts that all expected
vulnerability classes are detected with the correct severity levels.

Run with:
    python -m pytest tests/test_integration.py -v -s

The mock server is started once per module in a background daemon thread.
Port 5099 is chosen to avoid conflict with an already-running development
instance on port 5000.
"""

import os
import sys
import json
import time
import threading

import pytest
import requests as req_lib

# ── Path setup ────────────────────────────────────────────────────────────────

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(_ROOT, 'src'))
sys.path.insert(0, os.path.join(_ROOT, 'mock_server'))

_MOCK_PORT = 5099
_MOCK_BASE = f'http://127.0.0.1:{_MOCK_PORT}'

# ── Mock server lifecycle ─────────────────────────────────────────────────────

def _start_server():
    """Start the Flask mock server on _MOCK_PORT in a daemon thread."""
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)

    from app import app
    app.run(host='127.0.0.1', port=_MOCK_PORT, debug=False, use_reloader=False)


def _server_ready(timeout: float = 10.0) -> bool:
    """Poll /health until the server responds or timeout elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = req_lib.get(f'{_MOCK_BASE}/health', timeout=1)
            if r.status_code == 200:
                return True
        except req_lib.RequestException:
            pass
        time.sleep(0.15)
    return False


@pytest.fixture(scope='module')
def mock_server():
    """
    Module-scoped fixture: start the mock server once, yield, then let the
    daemon thread die when the test process exits.
    """
    t = threading.Thread(target=_start_server, daemon=True)
    t.start()
    if not _server_ready():
        pytest.skip('Mock server did not become ready within 10 s')
    yield _MOCK_BASE


# ── Spec factory ──────────────────────────────────────────────────────────────

import yaml

@pytest.fixture(scope='module')
def patched_spec(mock_server, tmp_path_factory):
    """
    Copy fintech.yaml but point its server URL at the test mock server.
    Written to a temp file so the scanner can load it normally.
    """
    src = os.path.join(_ROOT, 'sample_specs', 'fintech.yaml')
    with open(src, encoding='utf-8') as f:
        spec = yaml.safe_load(f)

    spec['servers'] = [{'url': _MOCK_BASE}]

    tmp = tmp_path_factory.mktemp('specs') / 'fintech_test.yaml'
    with open(tmp, 'w', encoding='utf-8') as f:
        yaml.dump(spec, f)
    return str(tmp)


# ── Scanner fixture ───────────────────────────────────────────────────────────

@pytest.fixture(scope='module')
def scan_result(mock_server, patched_spec, tmp_path_factory):
    """Run a full scan (BOLA + SSRF; OAuth skipped) and return the result dict."""
    from scanner import Scanner

    out_dir = str(tmp_path_factory.mktemp('reports'))

    config = {
        'spec_file':    patched_spec,
        'users': [
            {
                'name': 'alice', 'token': 'token_alice',
                'user_id': 1, 'role': 'customer',
            },
            {
                'name': 'bob', 'token': 'token_bob',
                'user_id': 2, 'role': 'customer',
            },
            {
                'name': 'admin', 'token': 'token_admin',
                'user_id': 9, 'role': 'admin', 'owns_all': True,
            },
        ],
        'resource_ids': [1, 2, 3],
        'output_dir':   out_dir,
        'skip':         ['oauth'],      # OAuth checks need real OAuth server
        'callback_url': None,
        'oauth_config': None,
        'delay':        0.0,
        'insecure':     False,
        'proxy':        None,
        'verbose':      False,
        'active':       True,
        'max_requests': 1000,
    }

    return Scanner(config).run()


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestIntegration:

    # ── Health / basic sanity ─────────────────────────────────────────────────

    def test_mock_server_health(self, mock_server):
        r = req_lib.get(f'{mock_server}/health')
        assert r.status_code == 200
        assert r.json()['status'] == 'ok'

    def test_scan_produces_findings(self, scan_result):
        assert len(scan_result['findings']) > 0

    def test_reports_exist(self, scan_result):
        assert os.path.exists(scan_result['json_report'])
        assert os.path.exists(scan_result['html_report'])

    def test_json_report_parseable(self, scan_result):
        with open(scan_result['json_report'], encoding='utf-8') as f:
            data = json.load(f)
        assert 'findings' in data
        # reporter uses 'scan_meta' as the top-level metadata key
        assert 'scan_meta' in data or 'meta' in data

    # ── BOLA findings ─────────────────────────────────────────────────────────

    def test_bola_simple_idor_detected(self, scan_result):
        checks = {f['vulnerability']['check'] for f in scan_result['findings']}
        assert 'Simple IDOR' in checks, f'Expected Simple IDOR; got {checks}'

    def test_bola_mass_assignment_detected(self, scan_result):
        checks = {f['vulnerability']['check'] for f in scan_result['findings']}
        assert 'Mass Assignment' in checks, f'Expected Mass Assignment; got {checks}'

    def test_method_specific_findings_are_not_deduplicated(self, scan_result):
        methods = {
            f['vulnerability'].get('method')
            for f in scan_result['findings']
            if f['vulnerability']['check'] == 'Mass Assignment'
            and f['vulnerability']['endpoint'] == '/user/update'
        }
        assert {'POST', 'PUT', 'PATCH'} <= methods

    def test_bola_body_idor_detected(self, scan_result):
        checks = {f['vulnerability']['check'] for f in scan_result['findings']}
        assert 'Body IDOR' in checks, f'Expected Body IDOR; got {checks}'
        body_findings = [
            finding for finding in scan_result['findings']
            if finding['vulnerability']['check'] == 'Body IDOR'
        ]
        assert {
            finding['vulnerability'].get('unauthorized_user')
            for finding in body_findings
        } == {'bob'}

    def test_bola_param_pollution_detected(self, scan_result):
        checks = {f['vulnerability']['check'] for f in scan_result['findings']}
        assert 'Parameter Pollution IDOR' in checks, f'Expected Parameter Pollution IDOR; got {checks}'

    def test_bola_indirect_reference_detected(self, scan_result):
        checks = {f['vulnerability']['check'] for f in scan_result['findings']}
        assert 'Indirect Reference Enumeration' in checks, \
            f'Expected Indirect Reference Enumeration; got {checks}'

    # ── SSRF findings ─────────────────────────────────────────────────────────

    def test_ssrf_basic_detected(self, scan_result):
        ssrf = [f for f in scan_result['findings']
                if f['vulnerability']['type'] == 'SSRF']
        assert len(ssrf) > 0, 'No SSRF findings detected'

    def test_ssrf_critical_severity(self, scan_result):
        critical_ssrf = [
            f for f in scan_result['findings']
            if f['vulnerability']['type'] == 'SSRF'
            and f['vulnerability']['severity'] == 'CRITICAL'
        ]
        assert len(critical_ssrf) > 0, 'No CRITICAL SSRF findings'

    # ── Severity distribution ─────────────────────────────────────────────────

    def test_summary_counts_match_findings(self, scan_result):
        summary = scan_result['summary']
        assert sum(summary.values()) == len(scan_result['findings'])

    def test_critical_findings_present(self, scan_result):
        assert scan_result['summary']['CRITICAL'] > 0

    # ── False-positive guards ─────────────────────────────────────────────────

    def test_no_false_positive_alice_own_transactions(self, scan_result):
        """
        Alice (user_id=1) owns transactions 1 and 3.
        Bob (user_id=2) owns transaction 2.
        Alice should NOT be flagged as an unauthorised accessor for her own resources
        (resources 1 or 3 — both owned by alice).
        """
        simple_idor = [
            f for f in scan_result['findings']
            if f['vulnerability']['check'] == 'Simple IDOR'
        ]
        for finding in simple_idor:
            vuln = finding['vulnerability']
            # 'unauthorized_user' is stored on the top-level finding dict
            unauth = finding.get('unauthorized_user') or vuln.get('unauthorized_user', '')
            rid    = vuln.get('resource_id')
            # Alice owns resources 1 and 3 — she must never appear as unauthorised
            if rid in (1, 3) and 'alice' in str(unauth).lower():
                pytest.fail(
                    f'False positive: alice flagged as unauthorised accessor '
                    f'for resource {rid} (which she owns).\nFinding: {vuln}'
                )

    def test_privileged_admin_is_not_flagged_as_unauthorized(self, scan_result):
        bola_findings = [
            finding for finding in scan_result['findings']
            if finding['vulnerability']['type'] == 'BOLA/IDOR'
        ]
        assert all(
            finding['vulnerability'].get('unauthorized_user') != 'admin'
            for finding in bola_findings
        )

    def test_evidence_files_written(self, scan_result):
        """Every finding must have a corresponding forensic evidence file."""
        for f in scan_result['findings']:
            fp = f.get('_evidence_file')
            assert fp and os.path.exists(fp), f'Missing evidence file for finding: {f}'

    def test_evidence_contains_http_block(self, scan_result):
        """logger must enrich every finding with an http block."""
        for f in scan_result['findings']:
            assert 'http' in f, f'Missing http block in finding: {f["vulnerability"]}'
            assert 'request' in f['http']
            assert 'response' in f['http']
