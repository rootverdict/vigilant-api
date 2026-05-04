"""
tests/test_auth.py
-------------------
Unit tests for AuthHandler.check_jwt_algorithm — the static method that
inspects JWT headers for weak/dangerous algorithm choices.

Tokens are crafted with base64url-encoded headers so no real JWT library
secret is required; check_jwt_algorithm uses unverified header parsing.
"""

import os
import sys
import base64
import json
import pytest
import jwt as _pyjwt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from auth import AuthHandler


# ── Token factory ─────────────────────────────────────────────────────────────

def _b64url(data: dict) -> str:
    raw = json.dumps(data, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def _make_jwt(header: dict, payload: dict = None) -> str:
    """
    Build a JWT with the given header dict that PyJWT can parse with
    get_unverified_header().

    - alg=none  → empty signature segment (RFC 7515 §6)
    - alg=HS256 → PyJWT encode with a dummy secret (gives a real signature)
    - anything else (RS256/ES256/...) → random base64url signature; PyJWT only
      reads the header so the signature content does not matter for header tests
    """
    claims = payload or {'sub': 'test', 'iat': 1700000000}
    alg    = header.get('alg', '').lower()

    if alg == 'hs256':
        # Use PyJWT to produce a syntactically valid HS256 token.
        # Override the header to match exactly what the test supplies.
        token = _pyjwt.encode(claims, 'dummy-secret-key-for-testing', algorithm='HS256',
                               headers={k: v for k, v in header.items() if k != 'alg'})
        return token   # already a str in PyJWT ≥ 2.0

    h = _b64url(header)
    p = _b64url(claims)

    if alg == 'none':
        # RFC 7515 §6: unsecured JWT has an empty signature segment
        return f'{h}.{p}.'

    # For asymmetric algorithms (RS256, ES256, PS256, …) we don't have a real
    # private key, but get_unverified_header() only decodes the header segment —
    # it does not validate the signature.  A random 32-byte base64url dummy is
    # syntactically acceptable.
    sig = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
    return f'{h}.{p}.{sig}'


# ── Tests: alg=none (CRITICAL) ────────────────────────────────────────────────

class TestAlgNone:

    def test_alg_none_lowercase_detected(self):
        token = _make_jwt({'alg': 'none', 'typ': 'JWT'})
        finding = AuthHandler.check_jwt_algorithm(token)
        assert finding is not None
        assert finding['severity'] == 'CRITICAL'
        assert finding['vulnerable'] is True

    def test_alg_none_mixed_case_detected(self):
        # JWT spec is case-sensitive for "none" but some parsers normalise
        token = _make_jwt({'alg': 'None', 'typ': 'JWT'})
        finding = AuthHandler.check_jwt_algorithm(token)
        assert finding is not None
        assert finding['severity'] == 'CRITICAL'

    def test_alg_none_check_label(self):
        token = _make_jwt({'alg': 'none', 'typ': 'JWT'})
        finding = AuthHandler.check_jwt_algorithm(token)
        assert 'none' in finding['check'].lower()

    def test_alg_none_evidence_has_header(self):
        token = _make_jwt({'alg': 'none', 'typ': 'JWT'})
        finding = AuthHandler.check_jwt_algorithm(token)
        assert 'alg' in finding['evidence']
        assert finding['evidence']['alg'] == 'none'


# ── Tests: alg=HS256 (INFO, not vulnerable) ───────────────────────────────────

class TestAlgHS256:

    def test_hs256_detected(self):
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'})
        finding = AuthHandler.check_jwt_algorithm(token)
        assert finding is not None
        assert finding['severity'] == 'INFO'

    def test_hs256_not_vulnerable(self):
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'})
        finding = AuthHandler.check_jwt_algorithm(token)
        assert finding['vulnerable'] is False

    def test_hs256_check_label_informational(self):
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'})
        finding = AuthHandler.check_jwt_algorithm(token)
        assert 'informational' in finding['check'].lower() or 'hs256' in finding['check'].lower()


# ── Tests: acceptable algorithms → no finding ─────────────────────────────────

class TestAcceptableAlgorithms:

    @pytest.mark.parametrize('alg', ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'PS256'])
    def test_strong_alg_returns_none(self, alg):
        token = _make_jwt({'alg': alg, 'typ': 'JWT'})
        finding = AuthHandler.check_jwt_algorithm(token)
        assert finding is None, f'Unexpected finding for {alg}: {finding}'


# ── Tests: non-JWT tokens (opaque) ────────────────────────────────────────────

class TestOpaqueTokens:

    def test_opaque_token_returns_none(self):
        # Simple bearer token — not a JWT
        assert AuthHandler.check_jwt_algorithm('token_alice') is None

    def test_empty_string_returns_none(self):
        assert AuthHandler.check_jwt_algorithm('') is None

    def test_malformed_jwt_returns_none(self):
        # Two segments only (missing signature) — PyJWT raises an exception
        assert AuthHandler.check_jwt_algorithm('abc.def') is None

    def test_random_base64_returns_none(self):
        assert AuthHandler.check_jwt_algorithm('aGVsbG8=') is None
