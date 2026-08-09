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
        assert not detector._contains_metadata('fetched 169.254.169.254 ok')

    def test_case_insensitive(self, detector):
        assert detector._contains_metadata('{"COMPUTEMETADATA": true}')

    def test_reflected_metadata_payload_is_not_confirmation(self, detector):
        payload = 'http://metadata.google.internal/computeMetadata/v1/'
        assert not detector._contains_metadata(f'echo: {payload}', payload)

    def test_reflected_protocol_payload_is_removed(self, detector):
        payload = 'dict://localhost:11211/'
        assert 'localhost' not in detector._without_reflection(f'echo: {payload}', payload)

    def test_benign_response_not_matched(self, detector):
        assert not detector._contains_metadata('{"status": "ok", "data": []}')

    def test_empty_string(self, detector):
        assert not detector._contains_metadata('')

    def test_generic_localhost_text_is_not_protocol_evidence(self, detector):
        assert not detector._contains_protocol_evidence(
            'dict://localhost:11211/', 'service running on localhost'
        )

    def test_memcached_signature_is_protocol_evidence(self, detector):
        assert detector._contains_protocol_evidence(
            'dict://localhost:11211/', 'STAT pid 123\nEND\n'
        )

    def test_passwd_signature_is_file_protocol_evidence(self, detector):
        assert detector._contains_protocol_evidence(
            'file:///etc/passwd', 'root:x:0:0:root:/root:/bin/bash\n'
        )


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
    def test_path_param_replaces_path_segment(self, mock_req, detector):
        mock_req.return_value = self._make_mock_response()
        detector._request(
            'GET', 'http://localhost:5000/fetch/{target_url}', self.MOCK_TOKEN,
            'target_url', 'http://evil.com', 'path',
        )
        called_url = mock_req.call_args[0][1]
        assert '?' not in called_url
        assert '{target_url}' not in called_url
        assert 'http%3A%2F%2Fevil.com' in called_url

    @patch('ssrf_detector.requests.request')
    def test_nested_body_param_uses_declared_path(self, mock_req, detector):
        mock_req.return_value = self._make_mock_response()
        detector._request(
            'POST', self.MOCK_URL, self.MOCK_TOKEN,
            'delivery.target', 'http://evil.com', 'body', ['delivery', 'target'],
        )
        assert mock_req.call_args[1]['json'] == {
            'delivery': {'target': 'http://evil.com'}
        }

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


def _mock_response(status=200, text='ok'):
    mock = MagicMock()
    mock.status_code = status
    mock.text = text
    mock.content = text.encode()
    return mock


class TestBlindSSRF:
    """The blind check was previously unexercised: no test supplied a callback
    URL, so the whole sub-check ran zero times.

    Its central property is restraint. The scanner cannot observe an out-of-band
    hit, so a plain 200 proves nothing; only reflection of the callback URL is
    reported, and only at LOW.
    """

    PARAM = {'name': 'url', 'in': 'query', 'schema': {'type': 'string'}}
    USER = {'name': 'alice', 'token': 't'}
    CALLBACK = 'https://abc123.oob.example.test'

    @patch('ssrf_detector.requests.request')
    def test_skipped_without_callback_url(self, mock_req):
        """No --callback means no requests at all, not a silent pass."""
        detector = SSRFDetector()
        assert detector._blind_ssrf('GET', 'http://t/fetch', self.PARAM, self.USER) == []
        mock_req.assert_not_called()

    @patch('ssrf_detector.requests.request')
    def test_plain_200_is_not_a_finding(self, mock_req):
        """A 200 without reflection just means the input was accepted."""
        mock_req.return_value = _mock_response(text='{"status": "queued"}')
        detector = SSRFDetector(callback_url=self.CALLBACK)
        assert detector._blind_ssrf('GET', 'http://t/fetch', self.PARAM, self.USER) == []

    @patch('ssrf_detector.requests.request')
    def test_reflected_callback_is_reported_low(self, mock_req):
        mock_req.return_value = _mock_response(text=f'fetching {self.CALLBACK} now')
        detector = SSRFDetector(callback_url=self.CALLBACK)
        findings = detector._blind_ssrf('GET', 'http://t/fetch', self.PARAM, self.USER)

        assert len(findings) == 1
        assert findings[0]['severity'] == 'LOW'
        assert findings[0]['evidence']['payload'] == self.CALLBACK

    @patch('ssrf_detector.requests.request')
    def test_finding_states_it_is_unconfirmed(self, mock_req):
        """Severity alone is easy to misread — the text must say it is unconfirmed
        and name the out-of-band step required to escalate."""
        mock_req.return_value = _mock_response(text=self.CALLBACK)
        detector = SSRFDetector(callback_url=self.CALLBACK)
        finding = detector._blind_ssrf('GET', 'http://t/fetch', self.PARAM, self.USER)[0]

        assert 'unconfirmed' in finding['check'].lower()
        assert 'does NOT confirm' in finding['description']

    @patch('ssrf_detector.requests.request')
    def test_network_failure_yields_no_finding(self, mock_req):
        mock_req.side_effect = __import__('requests').RequestException('boom')
        detector = SSRFDetector(callback_url=self.CALLBACK)
        assert detector._blind_ssrf('GET', 'http://t/fetch', self.PARAM, self.USER) == []


class TestSafeMode:

    @patch('ssrf_detector.requests.request')
    def test_write_method_skipped_without_active(self, mock_req):
        """Safe mode is the default; a POST probe must not be sent."""
        detector = SSRFDetector()
        result = detector.test_endpoint(
            'POST', 'http://t/x',
            [{'name': 'url', 'in': 'query', 'schema': {}}],
            {'name': 'alice', 'token': 't'},
        )
        assert result == []
        mock_req.assert_not_called()


class TestBaseBody:
    """_base_body builds the filler payload that carries an SSRF probe into a
    request body. Required fields only, with the schema deciding the value."""

    def _detector(self, params):
        detector = SSRFDetector()
        detector._body_params = params
        return detector

    def test_optional_fields_are_omitted(self):
        d = self._detector([{'name': 'note', 'in': 'body', 'required': False, 'schema': {}}])
        assert d._base_body() == {}

    def test_example_wins_over_type(self):
        d = self._detector([{'name': 'a', 'in': 'body', 'required': True,
                             'schema': {'type': 'integer', 'example': 42}}])
        assert d._base_body() == {'a': 42}

    def test_default_is_used_when_no_example(self):
        d = self._detector([{'name': 'a', 'in': 'body', 'required': True,
                             'schema': {'type': 'string', 'default': 'dflt'}}])
        assert d._base_body() == {'a': 'dflt'}

    def test_first_enum_member_is_used(self):
        d = self._detector([{'name': 'a', 'in': 'body', 'required': True,
                             'schema': {'enum': ['one', 'two']}}])
        assert d._base_body() == {'a': 'one'}

    @pytest.mark.parametrize('declared,expected', [
        ('integer', 7), ('number', 0.01), ('boolean', False),
        ('array', []), ('object', {}), ('string', 'vigilant-test'),
        (None, 'vigilant-test'),
    ])
    def test_type_defaults(self, declared, expected):
        schema = {'type': declared} if declared else {}
        d = self._detector([{'name': 'a', 'in': 'body', 'required': True, 'schema': schema}])
        assert d._base_body() == {'a': expected}

    def test_declared_path_builds_nested_body(self):
        d = self._detector([{'name': 'meta.role', 'path': ['meta', 'role'], 'in': 'body',
                             'required': True, 'schema': {'type': 'string'}}])
        assert d._base_body() == {'meta': {'role': 'vigilant-test'}}

    def test_dotted_name_without_path_is_split(self):
        d = self._detector([{'name': 'meta.role', 'in': 'body', 'required': True,
                             'schema': {'type': 'string'}}])
        assert d._base_body() == {'meta': {'role': 'vigilant-test'}}


class TestSetNested:

    def test_builds_missing_containers(self):
        body: dict = {}
        SSRFDetector._set_nested(body, ['a', 'b', 'c'], 1)
        assert body == {'a': {'b': {'c': 1}}}

    def test_scalar_intermediate_is_replaced(self):
        """A sibling param may already have claimed the key as a scalar. Probing
        the nested field matters more than preserving a filler value, so the
        scalar is overwritten instead of raising TypeError."""
        body = {'a': 'filler'}
        SSRFDetector._set_nested(body, ['a', 'b'], 1)
        assert body == {'a': {'b': 1}}

    def test_existing_siblings_are_preserved(self):
        body = {'a': {'keep': 1}}
        SSRFDetector._set_nested(body, ['a', 'b'], 2)
        assert body == {'a': {'keep': 1, 'b': 2}}
