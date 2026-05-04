"""
tests/test_oauth_detector.py
-----------------------------
Unit tests for OAuthFlawDetector helpers:
  - _make_finding        (finding dict structure)
  - _MOCK_ONLY_CHECKS    (frozenset content)
  - run_all_checks       (returns a list, no crash without server)
  - _check_missing_state (logic via mocked requests)
  - _check_open_redirect (logic via mocked requests)
"""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from oauth_detector import OAuthFlawDetector


@pytest.fixture
def detector():
    return OAuthFlawDetector(
        auth_url='http://localhost:5000/oauth/authorize',
        token_url='http://localhost:5000/oauth/token',
        client_id='test-client',
        client_secret='test-secret',
        redirect_uri='http://localhost/callback',
    )


class TestMakeFinding:

    def test_required_keys_present(self, detector):
        f = detector._make_finding(
            check='Missing state Parameter',
            severity='HIGH',
            description='No state param.',
            remediation='Add state param.',
            evidence={'request_params': {}},
        )
        for key in ('type', 'check', 'vulnerable', 'severity',
                    'description', 'remediation', 'evidence'):
            assert key in f, f'Missing key: {key}'

    def test_type_is_oauth_flaw(self, detector):
        f = detector._make_finding('X', 'HIGH', 'desc', 'fix', {})
        assert f['type'] == 'OAuth Flaw'

    def test_vulnerable_always_true(self, detector):
        f = detector._make_finding('X', 'HIGH', 'desc', 'fix', {})
        assert f['vulnerable'] is True

    def test_severity_preserved(self, detector):
        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            f = detector._make_finding('X', sev, 'desc', 'fix', {})
            assert f['severity'] == sev


class TestMockOnlyChecks:

    def test_code_reuse_is_mock_only(self):
        assert 'Authorization Code Reuse' in OAuthFlawDetector._MOCK_ONLY_CHECKS

    def test_token_leakage_is_mock_only(self):
        assert 'Token Leakage in URL / Referer' in OAuthFlawDetector._MOCK_ONLY_CHECKS

    def test_missing_state_not_mock_only(self):
        assert 'Missing state Parameter' not in OAuthFlawDetector._MOCK_ONLY_CHECKS

    def test_open_redirect_not_mock_only(self):
        assert 'Open Redirect Abuse via redirect_uri' not in OAuthFlawDetector._MOCK_ONLY_CHECKS


class TestRunAllChecks:

    def test_returns_list_on_connection_error(self, detector):
        """With no server running, all checks should fail silently and return []."""
        result = detector.run_all_checks()
        assert isinstance(result, list)

    @patch('oauth_detector.requests.request')
    def test_missing_state_fires_on_302_with_code(self, mock_req, detector):
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {'Location': 'http://localhost/callback?code=abc123'}
        mock_req.return_value = mock_resp

        findings = detector._check_missing_state()
        assert len(findings) == 1
        assert findings[0]['check'] == 'Missing state Parameter'
        assert findings[0]['severity'] == 'HIGH'

    @patch('oauth_detector.requests.request')
    def test_missing_state_no_finding_when_state_present(self, mock_req, detector):
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {'Location': 'http://localhost/callback?code=abc&state=xyz'}
        mock_req.return_value = mock_resp

        findings = detector._check_missing_state()
        assert findings == []

    @patch('oauth_detector.requests.request')
    def test_open_redirect_fires_on_evil_uri_in_location(self, mock_req, detector):
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {'Location': 'https://evil-attacker.com/steal?code=abc'}
        mock_req.return_value = mock_resp

        findings = detector._check_open_redirect()
        assert len(findings) == 1
        assert findings[0]['check'] == 'Open Redirect Abuse via redirect_uri'
        assert findings[0]['severity'] == 'CRITICAL'
