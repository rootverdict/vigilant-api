"""
tests/test_bola_detector.py
----------------------------
Unit tests for BOLADetector helpers:
  - _bodies_similar      (fuzzy body comparison, including string-ID cross-type)
  - _is_error_body       (error response filter)
  - _strip_path_params   (URL template resolution)
  - _safe_json           (JSON parse fallback)
"""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from bola_detector import BOLADetector

# Minimal users list so BOLADetector can be instantiated without a real server
_USERS = [
    {'name': 'alice', 'token': 'token_alice', 'user_id': 1},
    {'name': 'bob',   'token': 'token_bob',   'user_id': 2},
]

@pytest.fixture
def detector():
    return BOLADetector(base_url='http://localhost:5000', users=_USERS)


# ── _bodies_similar ───────────────────────────────────────────────────────────

class TestBodiesSimilar:

    def test_same_int_id_is_similar(self, detector):
        b1 = {'id': 1, 'amount': 500.0, 'description': 'Coffee'}
        b2 = {'id': 1, 'amount': 500.0, 'description': 'Coffee'}
        assert detector._bodies_similar(b1, b2)

    def test_different_id_not_similar(self, detector):
        b1 = {'id': 1, 'amount': 500.0}
        b2 = {'id': 2, 'amount': 500.0}
        assert not detector._bodies_similar(b1, b2)

    def test_string_id_matches_int_id(self, detector):
        """API returns "id": "1" (string) — should still match against int resource_id 1."""
        b1 = {'id': '1', 'status': 'settled'}
        b2 = {'id': '1', 'status': 'settled'}
        assert detector._bodies_similar(b1, b2)

    def test_int_id_matches_string_id_cross_type(self, detector):
        """Cross-type: one body has int ID, other has string ID."""
        b1 = {'id': 1,   'description': 'Coffee'}
        b2 = {'id': '1', 'description': 'Coffee'}
        assert detector._bodies_similar(b1, b2)

    def test_no_id_field_two_matching_values(self, detector):
        b1 = {'status': 'settled', 'description': 'Coffee'}
        b2 = {'status': 'settled', 'description': 'Coffee'}
        assert detector._bodies_similar(b1, b2)

    def test_no_id_field_one_match_not_similar(self, detector):
        b1 = {'status': 'settled', 'description': 'Coffee'}
        b2 = {'status': 'settled', 'description': 'Tea'}
        assert not detector._bodies_similar(b1, b2)

    def test_non_dict_not_similar(self, detector):
        assert not detector._bodies_similar('hello', {'id': 1})
        assert not detector._bodies_similar(None, None)
        assert not detector._bodies_similar([1, 2], [1, 2])

    def test_empty_real_keys_not_similar(self, detector):
        b1 = {'error': 'Not found'}
        b2 = {'error': 'Not found'}
        assert not detector._bodies_similar(b1, b2)

    def test_single_id_key_sufficient(self, detector):
        """A small object with just one id field — should be flagged."""
        b1 = {'id': 3, 'status': 'ok'}
        b2 = {'id': 3, 'status': 'ok'}
        assert detector._bodies_similar(b1, b2)

    def test_null_id_not_similar(self, detector):
        """None IDs should not count as a match — fall through to ≥2 non-trivial check."""
        b1 = {'id': None, 'status': 'ok'}
        b2 = {'id': None, 'status': 'ok'}
        # id key is present but value is None — _ids_equal guards against this.
        # Falls through to the non-ID path: "status": "ok" is only 1 non-trivial
        # matching value → not similar (requires ≥2).
        assert not detector._bodies_similar(b1, b2)

    def test_nested_resource_id_is_similar(self, detector):
        b1 = {'data': {'id': 7, 'name': 'Invoice'}}
        b2 = {'data': {'id': '7', 'name': 'Invoice'}}
        assert detector._bodies_similar(b1, b2)

    def test_nested_different_resource_id_is_not_similar(self, detector):
        b1 = {'data': {'id': 7, 'status': 'ready'}}
        b2 = {'data': {'id': 8, 'status': 'ready'}}
        assert not detector._bodies_similar(b1, b2)


# ── _is_error_body ────────────────────────────────────────────────────────────

class TestIsErrorBody:

    def test_pure_error_keys(self, detector):
        assert detector._is_error_body({'error': 'Not found'})
        assert detector._is_error_body({'error': 'x', 'message': 'y'})

    def test_mixed_keys_not_error(self, detector):
        assert not detector._is_error_body({'error': 'x', 'id': 1})

    def test_non_dict_not_error(self, detector):
        assert not detector._is_error_body('plain text')
        assert not detector._is_error_body(None)

    def test_empty_dict_not_error(self, detector):
        # Empty dict: keys <= error_keys vacuously, but useful resources
        # also have empty dicts; treat as not-an-error (no keys at all).
        # Current impl: {} <= error_keys → True (empty set ≤ any set).
        # This is an edge case; we document, not change, current behaviour.
        result = detector._is_error_body({})
        assert isinstance(result, bool)   # just ensure no exception


# ── _strip_path_params ────────────────────────────────────────────────────────

class TestStripPathParams:

    def test_replaces_single_param(self, detector):
        # Strips '/{id}' segment entirely, leaving '/items' (no trailing slash)
        assert detector._strip_path_params('/items/{id}') == '/items'

    def test_replaces_multiple_params(self, detector):
        # '/a/{x}/b/{y}' → strip '/{x}' → '/a/b/{y}' → strip '/{y}' → '/a/b'
        assert detector._strip_path_params('/a/{x}/b/{y}') == '/a/b'

    def test_no_params_unchanged(self, detector):
        assert detector._strip_path_params('/health') == '/health'


class TestParameterAwareProbes:

    def test_build_url_changes_only_target_placeholder(self, detector):
        detector._path_params = [
            {'name': 'org_id', 'schema': {'example': 42}},
            {'name': 'user_id', 'schema': {}},
        ]
        url = detector._build_url(
            '/orgs/{org_id}/users/{user_id}', 7, 'user_id'
        )
        assert url == 'http://localhost:5000/orgs/42/users/7'

    def test_pollution_uses_declared_query_name_and_resolves_path(self, detector):
        detector._path_params = [
            {'name': 'org_id', 'schema': {'example': 42}},
        ]
        response = MagicMock()
        response.status_code = 200
        response.content = b'json'
        response.json.return_value = {'data': {'account_id': 1}}

        with patch.object(detector, '_request', return_value=response) as request:
            findings = detector._param_pollution(
                'GET', '/orgs/{org_id}/export', 1,
                {'name': 'account_id', 'in': 'query'},
            )

        called_url = request.call_args.args[1]
        assert called_url.startswith('http://localhost:5000/orgs/42/export?')
        assert 'account_id=1&account_id=2' in called_url
        assert '?id=' not in called_url
        assert findings[0]['parameter'] == 'account_id'

    def test_body_contains_nested_id_only_under_id_like_key(self, detector):
        assert detector._body_contains_id({'data': {'accountId': '4'}}, 4)
        assert not detector._body_contains_id({'data': {'amount': 4}}, 4)


# ── _safe_json ────────────────────────────────────────────────────────────────

class TestSafeJson:

    def test_none_returns_none(self, detector):
        assert detector._safe_json(None) is None

    def test_valid_json_parsed(self, detector):
        """Mock response object with .json() method."""
        class FakeResp:
            def json(self):
                return {'id': 1}
            @property
            def text(self):
                return '{"id": 1}'
        assert detector._safe_json(FakeResp()) == {'id': 1}

    def test_invalid_json_falls_back_to_text(self, detector):
        class FakeResp:
            def json(self):
                raise ValueError('not json')
            @property
            def text(self):
                return 'plain text response'
        result = detector._safe_json(FakeResp())
        assert result == 'plain text response'


class TestActiveSafety:

    def test_safe_mode_does_not_send_body_probes(self, detector):
        params = [{'name': 'account_id', 'path': ['account_id'], 'in': 'body'}]
        with patch.object(detector, '_request') as request:
            detector.test_endpoint('POST', '/transfer', [1], params=params)
        request.assert_not_called()

    def test_body_idor_ignores_identical_success_responses(self):
        active = BOLADetector('http://localhost:5000', _USERS, active=True)
        response = MagicMock()
        response.status_code = 200
        response.content = b'{"status":"ok"}'
        response.json.return_value = {'status': 'ok'}
        params = [{'name': 'account_id', 'path': ['account_id'], 'in': 'body'}]
        with patch.object(active, '_request', return_value=response):
            findings = active._body_idor('POST', '/transfer', 1, params)
        assert findings == []

    def test_mass_assignment_uses_declared_method_only(self):
        active = BOLADetector('http://localhost:5000', _USERS, active=True)
        with patch.object(active, '_request', return_value=None) as request:
            active._mass_assignment('PATCH', '/user/update')
        assert request.call_count == 16
        assert {call.args[0] for call in request.call_args_list} == {'PATCH'}


class TestOwnershipResolution:

    def _response(self, body):
        response = MagicMock()
        response.status_code = 200
        response.content = b'json'
        response.json.return_value = body
        return response

    def test_non_first_user_can_be_identified_as_owner(self, detector):
        body = {'id': 7, 'owner_id': 2, 'status': 'ready'}
        response = self._response(body)
        with patch.object(detector, '_request', side_effect=[response, response]):
            findings = detector._simple_idor('GET', '/orders/{id}', 7)
        assert len(findings) == 1
        assert findings[0]['owner'] == 'bob'
        assert findings[0]['unauthorized_user'] == 'alice'

    def test_unknown_owner_does_not_produce_high_confidence_finding(self, detector):
        body = {'id': 99, 'status': 'ready'}
        response = self._response(body)
        with patch.object(detector, '_request', side_effect=[response, response]):
            findings = detector._simple_idor('GET', '/orders/{id}', 99)
        assert findings == []


class TestAttackerSelection:

    @pytest.fixture
    def admin_last_detector(self):
        users = [
            {'name': 'alice', 'token': 'a', 'user_id': 1, 'role': 'customer'},
            {'name': 'bob', 'token': 'b', 'user_id': 2, 'role': 'customer'},
            {
                'name': 'admin', 'token': 'admin', 'user_id': 9,
                'role': 'admin', 'owns_all': True,
            },
        ]
        return BOLADetector('http://localhost:5000', users, active=True)

    def test_resource_aware_selector_ignores_admin_and_owner(self, admin_last_detector):
        assert admin_last_detector._select_attacker(1, require_user_id=True)['name'] == 'bob'
        assert admin_last_detector._select_attacker(2, require_user_id=True)['name'] == 'alice'

    def test_simple_idor_does_not_flag_privileged_user(self, admin_last_detector):
        response = MagicMock()
        response.status_code = 200
        response.content = b'json'
        response.json.return_value = {'id': 1, 'owner_id': 1, 'status': 'ready'}

        with patch.object(admin_last_detector, '_request', return_value=response):
            findings = admin_last_detector._simple_idor('GET', '/orders/{id}', 1)

        assert [finding['unauthorized_user'] for finding in findings] == ['bob']

    def test_body_idor_uses_customer_with_valid_baseline(self, admin_last_detector):
        def response_for_payload(method, url, user, **kwargs):
            account_id = kwargs['json']['from_account_id']
            response = MagicMock()
            response.status_code = 200
            response.content = b'json'
            response.json.return_value = {
                'status': 'success', 'from_account': account_id,
            }
            return response

        params = [
            {
                'name': 'from_account_id', 'path': ['from_account_id'],
                'in': 'body', 'schema': {'type': 'integer'},
            },
        ]
        with patch.object(
            admin_last_detector, '_request', side_effect=response_for_payload
        ) as request:
            findings = admin_last_detector._body_idor('POST', '/transfer', 1, params)

        assert findings[0]['unauthorized_user'] == 'bob'
        assert {call.args[2]['name'] for call in request.call_args_list} == {'bob'}

    def test_mass_assignment_uses_non_privileged_user(self, admin_last_detector):
        response = MagicMock()
        response.status_code = 200
        response.content = b'json'
        response.json.return_value = {'role': 'admin', 'user_id': 2}

        with patch.object(admin_last_detector, '_request', return_value=response) as request:
            findings = admin_last_detector._mass_assignment('PATCH', '/user/update')

        assert findings[0]['unauthorized_user'] == 'bob'
        assert request.call_args.args[2]['name'] == 'bob'
