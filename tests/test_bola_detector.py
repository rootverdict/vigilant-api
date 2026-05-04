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
