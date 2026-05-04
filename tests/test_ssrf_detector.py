"""
tests/test_ssrf_detector.py
----------------------------
Unit tests for SSRFDetector helpers:
  - _contains_metadata   (pattern matching)
  - _make_finding        (finding dict structure)
  - _request             (param_in dispatch — mocked, no real network)
"""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ssrf_detector import SSRFDetector


@pytest.fixture
def detector():
    return SSRFDetector()


# ── _contains_metadata ────────────────────────────────────────────────────────

class TestContainsMetadata:

    def test_aws_access_key(self, detector):
        assert detector._contains_metadata('AKIAIOSFODNN7EXAMPLE is leaked')

    def test_aws_ami_id(self, detector):
        assert detector._contains_metadata('ami-0abcdef1234567890')

    def test_aws_ec2_hostname(self, detector):
        assert detector._contains_metadata('ip-10-0-1-42.ec2.internal')

    def test_aws_creds_json_key(self, detector):
        assert detector._contains_metadata('"accessKeyId": "AKI..."')

    def test_gcp_marker(self, detector):
        assert detector._contains_metadata('{"computeMetadata": true}')

    def test_azure_marker(self, detector):
        assert detector._contains_metadata('"x-ms-azure": true')

    def test_instance_id_key(self, detector):
        assert detector._contains_metadata('"instanceId": "i-1234567890abcdef0"')

    def test_raw_metadata_ip(self, detector):
        assert detector._contains_metadata('fetched 169.254.169.254 ok')

    def test_case_insensitive(self, detector):
        assert detector._contains_metadata('COMPUTEMETADATA')

    def test_benign_response_not_matched(self, detector):
        assert not detector._contains_metadata('{"status": "ok", "data": []}')

    def test_empty_string(self, detector):
        assert not detector._contains_metadata('')


# ── _make_finding ─────────────────────────────────────────────────────────────

class TestMakeFinding:

    def test_required_keys_present(self, detector):
        f = detector._make_finding(
            check='Basic SSRF',
            url='http://localhost:5000/fetch',
            param='url',
            payload='http://169.254.169.254/latest/meta-data/',
            status=200,
            body_preview='ami-0abc...',
            severity='CRITICAL',
            description='Cloud metadata exposed.',
        )
        for key in ('type', 'check', 'vulnerable', 'severity', 'endpoint',
                    'parameter', 'evidence', 'description', 'remediation'):
            assert key in f, f'Missing key: {key}'

    def test_type_is_ssrf(self, detector):
        f = detector._make_finding('X', 'http://x', 'p', 'pay', 200, 'b', 'HIGH', 'desc')
        assert f['type'] == 'SSRF'

    def test_vulnerable_true(self, detector):
        f = detector._make_finding('X', 'http://x', 'p', 'pay', 200, 'b', 'HIGH', 'desc')
        assert f['vulnerable'] is True

    def test_evidence_structure(self, detector):
        f = detector._make_finding('X', 'http://x', 'p', 'pay', 200, 'body', 'CRITICAL', 'd')
        ev = f['evidence']
        assert ev['payload'] == 'pay'
        assert ev['status_code'] == 200
        assert ev['body_preview'] == 'body'


# ── _request param_in dispatch (mocked) ───────────────────────────────────────

class TestRequestDispatch:
    """
    Verify that _request sends the payload via the correct mechanism
    depending on param_in — without making real network calls.
    """

    MOCK_URL   = 'http://localhost:5000/fetch'
    MOCK_TOKEN = 'token_alice'

    def _make_mock_response(self, status=200, text='ok'):
        mock = MagicMock()
        mock.status_code = status
        mock.text = text
        mock.content = text.encode()
        return mock

    @patch('ssrf_detector.requests.request')
    def test_query_param_appended_to_url(self, mock_req, detector):
        mock_req.return_value = self._make_mock_response()
        detector._request('GET', self.MOCK_URL, self.MOCK_TOKEN,
                          'url', 'http://evil.com', 'query')
        call_args = mock_req.call_args
        called_url = call_args[0][1]   # positional: method, url
        assert 'url=' in called_url
        assert 'evil.com' in called_url

    @patch('ssrf_detector.requests.request')
    def test_header_param_set_in_headers(self, mock_req, detector):
        mock_req.return_value = self._make_mock_response()
        detector._request('GET', self.MOCK_URL, self.MOCK_TOKEN,
                          'X-Target-URL', 'http://evil.com', 'header')
        call_kwargs = mock_req.call_args[1]
        headers = call_kwargs.get('headers', {})
        assert headers.get('X-Target-URL') == 'http://evil.com'

    @patch('ssrf_detector.requests.request')
    def test_cookie_param_set_in_cookie_header(self, mock_req, detector):
        mock_req.return_value = self._make_mock_response()
        detector._request('GET', self.MOCK_URL, self.MOCK_TOKEN,
                          'redirect_url', 'http://evil.com', 'cookie')
        call_kwargs = mock_req.call_args[1]
        headers = call_kwargs.get('headers', {})
        cookie_header = headers.get('Cookie', '')
        assert 'redirect_url=http://evil.com' in cookie_header

    @patch('ssrf_detector.requests.request')
    def test_body_param_sent_as_json(self, mock_req, detector):
        mock_req.return_value = self._make_mock_response()
        detector._request('POST', self.MOCK_URL, self.MOCK_TOKEN,
                          'target', 'http://evil.com', 'body')
        call_kwargs = mock_req.call_args[1]
        assert call_kwargs.get('json') == {'target': 'http://evil.com'}

    @patch('ssrf_detector.requests.request')
    def test_network_error_returns_none(self, mock_req, detector):
        import requests as req_lib
        mock_req.side_effect = req_lib.RequestException('connection refused')
        result = detector._request('GET', self.MOCK_URL, self.MOCK_TOKEN,
                                   'url', 'http://evil.com', 'query')
        assert result is None
