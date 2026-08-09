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

from auth import AuthHandler, build_auth_handler
from unittest.mock import patch, MagicMock


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
        # already a str in PyJWT >= 2.0
        return _pyjwt.encode(claims, 'dummy-secret-key-for-testing', algorithm='HS256',
                             headers={k: v for k, v in header.items() if k != 'alg'})

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


class TestRequestAuthentication:

    def test_openapi_api_key_header_is_applied(self):
        user = {'name': 'service', 'key': 'secret'}
        scheme = {'type': 'apiKey', 'in': 'header', 'name': 'X-Service-Key'}
        kwargs = AuthHandler.from_user(user, scheme).apply()
        assert kwargs['headers']['X-Service-Key'] == 'secret'
        assert 'Authorization' not in kwargs['headers']

    def test_openapi_api_key_query_is_applied(self):
        user = {'name': 'service', 'token': 'secret'}
        scheme = {'type': 'apiKey', 'in': 'query', 'name': 'api_key'}
        kwargs = AuthHandler.from_user(user, scheme).apply({'params': {'page': 1}})
        assert kwargs['params'] == {'page': 1, 'api_key': 'secret'}

    def test_supplied_oauth_access_token_needs_no_token_request(self):
        user = {'name': 'oauth-user', 'scheme': 'oauth2', 'access_token': 'ready'}
        with patch('auth.requests.post') as post:
            kwargs = AuthHandler.from_user(user).apply()
        post.assert_not_called()
        assert kwargs['headers']['Authorization'] == 'Bearer ready'

    def test_compound_auth_applies_every_required_scheme(self):
        user = {'name': 'service', 'token': 'bearer-token', 'key': 'api-secret'}
        options = [[
            {'type': 'http', 'scheme': 'bearer', '_name': 'BearerAuth'},
            {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key', '_name': 'ApiKeyAuth'},
        ]]
        kwargs = build_auth_handler(user, options).apply()
        assert kwargs['headers']['Authorization'] == 'Bearer bearer-token'
        assert kwargs['headers']['X-API-Key'] == 'api-secret'

    def test_or_auth_selects_best_matching_credentials(self):
        user = {'name': 'service', 'token': 'bearer-token'}
        options = [
            [{'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key', '_name': 'ApiKeyAuth'}],
            [{'type': 'http', 'scheme': 'bearer', '_name': 'BearerAuth'}],
        ]
        kwargs = build_auth_handler(user, options).apply()
        assert kwargs['headers'] == {'Authorization': 'Bearer bearer-token'}

    def test_anonymous_or_alternative_adds_no_credentials(self):
        user = {'name': 'service', 'token': 'bearer-token'}
        options = [[], [{'type': 'http', 'scheme': 'bearer', '_name': 'BearerAuth'}]]
        assert build_auth_handler(user, options).apply() == {}


class TestOAuthGrants:
    """get_token() should perform the correct OAuth 2.0 grant for each credential shape."""

    @staticmethod
    def _resp(data: dict):
        resp = MagicMock()
        resp.json.return_value = data
        resp.raise_for_status.return_value = None
        return resp

    def test_password_grant_requests_token_and_caches_refresh(self):
        user = {
            'name': 'alice', 'scheme': 'oauth2',
            'username': 'alice', 'password': 'pw',
            'client_id': 'cid', 'token_url': 'http://ts/token',
        }
        handler = AuthHandler.from_user(user)
        with patch('auth.requests.post') as post:
            post.return_value = self._resp({'access_token': 'AT', 'refresh_token': 'RT'})
            token = handler.get_token()

        assert token == 'AT'
        sent = post.call_args.kwargs['data']
        assert sent['grant_type'] == 'password'
        assert sent['username'] == 'alice'
        # A returned refresh token is cached for subsequent silent refresh.
        assert handler.credentials['refresh_token'] == 'RT'

    def test_refresh_grant_used_when_refresh_token_present(self):
        user = {
            'name': 'alice', 'scheme': 'oauth2',
            'refresh_token': 'old-refresh',
            'client_id': 'cid', 'token_url': 'http://ts/token',
        }
        handler = AuthHandler.from_user(user)
        with patch('auth.requests.post') as post:
            post.return_value = self._resp({'access_token': 'AT2', 'refresh_token': 'new-refresh'})
            token = handler.get_token()

        assert token == 'AT2'
        assert post.call_args.kwargs['data']['grant_type'] == 'refresh_token'
        assert handler.credentials['refresh_token'] == 'new-refresh'

    def test_client_credentials_grant_when_no_user_or_refresh(self):
        user = {
            'name': 'svc', 'scheme': 'oauth2',
            'client_id': 'cid', 'client_secret': 'sec',
            'token_url': 'http://ts/token',
        }
        handler = AuthHandler.from_user(user)
        with patch('auth.requests.post') as post:
            post.return_value = self._resp({'access_token': 'AT3'})
            token = handler.get_token()

        assert token == 'AT3'
        assert post.call_args.kwargs['data']['grant_type'] == 'client_credentials'


class TestGetSession:
    """get_session() bakes credentials into a reusable requests.Session.

    The detectors use apply() instead, so these are the only tests exercising
    this path — without them the whole method is unverified.
    """

    def test_bearer_sets_authorization_header(self):
        session = AuthHandler('bearer', {'token': 'abc'}).get_session()
        assert session.headers['Authorization'] == 'Bearer abc'

    def test_oauth_access_token_sets_authorization_header(self):
        handler = AuthHandler('oauth2', {'access_token': 'xyz'})
        assert handler.get_session().headers['Authorization'] == 'Bearer xyz'

    def test_api_key_defaults_to_header(self):
        session = AuthHandler('apikey', {'key': 'secret'}).get_session()
        assert session.headers['X-API-Key'] == 'secret'

    def test_api_key_honours_custom_header_name(self):
        session = AuthHandler(
            'apikey', {'key': 'secret', 'api_key_name': 'X-Tenant-Key'},
        ).get_session()
        assert session.headers['X-Tenant-Key'] == 'secret'

    def test_api_key_in_query_sets_session_params(self):
        session = AuthHandler(
            'apikey', {'key': 'secret', 'api_key_name': 'apikey', 'api_key_in': 'query'},
        ).get_session()
        assert session.params == {'apikey': 'secret'}

    def test_api_key_in_cookie_sets_session_cookie(self):
        session = AuthHandler(
            'apikey', {'key': 'secret', 'api_key_name': 'sid', 'api_key_in': 'cookie'},
        ).get_session()
        assert session.cookies.get('sid') == 'secret'

    def test_unsupported_scheme_is_rejected(self):
        with pytest.raises(ValueError, match='Unsupported auth scheme'):
            AuthHandler('basic', {'token': 'x'}).get_session()
