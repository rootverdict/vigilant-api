"""
auth.py
-------
Handles three auth schemes that Vigilant-API supports:
    1. Bearer JWT  – pass the raw token
    2. API Key     – passed as header or query param
    3. OAuth 2.0   – Resource Owner Password Credentials grant (for automation)

Produces a ready-to-use requests.Session with auth baked in.
"""

import requests
import jwt                  # PyJWT – used for token inspection only
from datetime import datetime, timezone
from typing import Any


class AuthHandler:
    def __init__(self, scheme_type: str, credentials: dict[str, Any]):
        """
        scheme_type : 'bearer' | 'apiKey' | 'oauth2'
        credentials : dict with keys depending on scheme (see below)
        """
        self.scheme      = scheme_type.lower()
        self.credentials = credentials
        self._token: str | None = None     # cached token

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def get_token(self) -> str:
        """Return a valid token, refreshing if needed."""
        if self._token and not self._is_expired(self._token):
            return self._token

        if self.scheme == 'oauth2':
            supplied = self.credentials.get('access_token') or self.credentials.get('token')
            if supplied and not self._is_expired(supplied):
                self._token = str(supplied)
                return self._token
            # Use refresh_token if we have one, otherwise do a full password grant
            if self.credentials.get('refresh_token'):
                self._token = self._refresh_oauth_token()
            elif self.credentials.get('username'):
                self._token = self._oauth_password_grant()
            else:
                self._token = self._oauth_client_credentials_grant()
        elif self.scheme == 'bearer':
            self._token = str(self.credentials['token'])
        elif self.scheme == 'apikey':
            self._token = str(self.credentials['key'])
        else:
            raise ValueError(f"Unsupported auth scheme: {self.scheme}")

        if self._token is None:
            raise ValueError(f'No token available for auth scheme: {self.scheme}')
        return self._token

    def get_session(self) -> requests.Session:
        """
        Returns a requests.Session with the right auth header set.
        Reuse this session for all requests so TCP connections are pooled.
        """
        session = requests.Session()
        token   = self.get_token()

        if self.scheme in ('bearer', 'oauth2'):
            session.headers.update({'Authorization': f'Bearer {token}'})
        elif self.scheme == 'apikey':
            name = str(self.credentials.get('api_key_name') or self.credentials.get('header_name', 'X-API-Key'))
            if self.credentials.get('api_key_in', 'header') == 'query':
                session.params = {name: token}
            elif self.credentials.get('api_key_in') == 'cookie':
                session.cookies.set(name, token)
            else:
                session.headers.update({name: token})

        return session

    @classmethod
    def from_user(cls, user: dict | str,
                  security_scheme: dict | None = None) -> 'AuthHandler':
        """Build an auth handler from a token-file entry and OpenAPI scheme.

        Existing ``{"name": "alice", "token": "..."}`` entries remain
        bearer credentials. API-key entries may use ``key`` or ``token`` and
        OAuth entries may provide an access token, refresh token, password
        credentials, or client credentials.
        """
        if isinstance(user, str):
            return cls('bearer', {'token': user})

        scheme_def = security_scheme or {}
        declared_type = str(scheme_def.get('type', '')).lower()
        explicit = str(user.get('scheme') or user.get('auth_type') or '').lower()

        if explicit in ('apikey', 'api_key') or declared_type == 'apikey':
            credentials = dict(user)
            named_keys = user.get('api_keys') or {}
            credentials['key'] = (
                named_keys.get(scheme_def.get('_name'))
                or user.get('key') or user.get('token')
            )
            credentials['api_key_name'] = (
                user.get('api_key_name') or user.get('header_name') or
                scheme_def.get('name') or 'X-API-Key'
            )
            credentials['api_key_in'] = user.get('api_key_in') or scheme_def.get('in', 'header')
            return cls('apikey', credentials)

        if explicit == 'oauth2' or declared_type == 'oauth2':
            credentials = dict(user)
            flows = scheme_def.get('flows') or {}
            for flow_name in ('password', 'clientCredentials', 'authorizationCode'):
                flow = flows.get(flow_name) or {}
                if flow.get('tokenUrl') and not credentials.get('token_url'):
                    credentials['token_url'] = flow['tokenUrl']
                    break
            return cls('oauth2', credentials)

        return cls('bearer', {'token': user.get('token') or user.get('access_token', '')})

    def apply(self, request_kwargs: dict | None = None) -> dict:
        """Return request kwargs containing this handler's authentication."""
        kwargs = dict(request_kwargs or {})
        headers = dict(kwargs.pop('headers', {}) or {})
        token = self.get_token()

        if self.scheme in ('bearer', 'oauth2'):
            headers['Authorization'] = f'Bearer {token}'
        else:
            name = self.credentials.get('api_key_name') or self.credentials.get('header_name', 'X-API-Key')
            location = self.credentials.get('api_key_in', 'header')
            if location == 'query':
                params = dict(kwargs.get('params') or {})
                params[name] = token
                kwargs['params'] = params
            elif location == 'cookie':
                cookies = dict(kwargs.get('cookies') or {})
                cookies[name] = token
                kwargs['cookies'] = cookies
            else:
                headers[name] = token

        kwargs['headers'] = headers
        return kwargs

    def inspect_jwt(self, token: str | None = None) -> dict:
        """
        Decode a JWT WITHOUT verification to inspect its claims.
        Useful for detecting weak algorithms (e.g. 'none') or missing claims.
        Returns the decoded payload dict.
        """
        token = token or self._token
        if not token:
            return {}
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def check_jwt_algorithm(token: str) -> dict | None:
        """
        Inspect JWT header for weak or dangerous algorithm choices.
        Returns a finding dict if a weakness is detected, else None.

        Detects:
          - alg=none  : signature not verified → trivial forgery
          - alg=HS256 : symmetric HMAC → secret must be strong; flags for awareness
        """
        try:
            header = jwt.get_unverified_header(token)
        except Exception:
            return None   # not a JWT (opaque token) — skip

        alg = header.get('alg', '').lower()

        if alg == 'none':
            return {
                'type':      'OAuth Flaw',
                'check':     'JWT Algorithm: none',
                'vulnerable': True,
                'severity':  'CRITICAL',
                'description': (
                    'JWT uses algorithm "none", meaning the server accepts unsigned tokens. '
                    'An attacker can forge arbitrary claims by setting alg=none and omitting the signature.'
                ),
                'remediation': (
                    'Reject JWTs with alg=none at the server. '
                    'Enforce an explicit algorithm allowlist (e.g. RS256 or ES256).'
                ),
                'evidence': {'alg': header.get('alg'), 'header': header},
            }

        if alg == 'hs256':
            return {
                'type':      'OAuth Flaw',
                'check':     'JWT Algorithm: HS256 (informational)',
                'vulnerable': False,
                'severity':  'INFO',
                'description': (
                    'JWT uses HS256 (symmetric HMAC). HS256 is a valid and widely used algorithm. '
                    'It becomes a security risk only if the signing secret is weak, short, reused '
                    'across services, or leaked. Asymmetric algorithms (RS256/ES256) are preferred '
                    'for multi-service architectures where multiple consumers verify tokens.'
                ),
                'remediation': (
                    'No immediate action required if HS256 is used intentionally. '
                    'Prefer RS256 or ES256 for multi-service architectures. '
                    'If HS256 is kept, ensure the secret is cryptographically random and >= 256 bits, '
                    'rotated periodically, and never committed to source control.'
                ),
                'evidence': {'alg': header.get('alg'), 'header': header},
            }

        return None   # algorithm looks acceptable

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _oauth_password_grant(self) -> str:
        """
        OAuth 2.0 Resource Owner Password Credentials (ROPC) grant.
        Works against most test/internal OAuth servers.
        Real-world: prefer auth-code flow, but for scanner automation ROPC is fine.
        """
        creds = self.credentials
        resp = requests.post(
            creds['token_url'],
            data={
                'grant_type':    'password',
                'username':      creds['username'],
                'password':      creds['password'],
                'client_id':     creds['client_id'],
                'client_secret': creds.get('client_secret', ''),
                'scope':         creds.get('scope', ''),
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        # Cache refresh token for later
        if 'refresh_token' in data:
            self.credentials['refresh_token'] = data['refresh_token']

        return data['access_token']

    def _refresh_oauth_token(self) -> str:
        """Use refresh_token to get a new access_token silently."""
        creds = self.credentials
        resp = requests.post(
            creds['token_url'],
            data={
                'grant_type':    'refresh_token',
                'refresh_token': creds['refresh_token'],
                'client_id':     creds['client_id'],
                'client_secret': creds.get('client_secret', ''),
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        self.credentials['refresh_token'] = data.get('refresh_token', creds['refresh_token'])
        return data['access_token']

    def _oauth_client_credentials_grant(self) -> str:
        """Acquire an OAuth token using the client-credentials grant."""
        creds = self.credentials
        resp = requests.post(
            creds['token_url'],
            data={
                'grant_type':    'client_credentials',
                'client_id':     creds['client_id'],
                'client_secret': creds.get('client_secret', ''),
                'scope':         creds.get('scope', ''),
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return data['access_token']

    def _is_expired(self, token: str) -> bool:
        """
        Try to decode the token and check 'exp' claim.
        Returns True if expired or can't decode.
        Only meaningful for JWTs.
        """
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp = payload.get('exp')
            if exp:
                return datetime.now(timezone.utc).timestamp() >= exp
            return False   # no exp claim → assume still valid
        except Exception:
            return False   # not a JWT (e.g. opaque token) → don't touch it


class CompositeAuthHandler:
    """Apply every auth scheme in one OpenAPI security requirement."""

    def __init__(self, handlers: list[AuthHandler]):
        self.handlers = handlers

    def apply(self, request_kwargs: dict | None = None) -> dict:
        kwargs = dict(request_kwargs or {})
        for handler in self.handlers:
            kwargs = handler.apply(kwargs)
        return kwargs


class AnonymousAuthHandler:
    """Leave a request unauthenticated for an anonymous OpenAPI alternative."""

    @staticmethod
    def apply(request_kwargs: dict | None = None) -> dict:
        return dict(request_kwargs or {})


def _scheme_score(user: dict | str, scheme: dict) -> int:
    declared_type = str(scheme.get('type', '')).lower()
    if isinstance(user, str):
        return 2 if declared_type in ('', 'http', 'oauth2', 'openidconnect') else 0

    if declared_type == 'apikey':
        named_keys = user.get('api_keys') or {}
        if named_keys.get(scheme.get('_name')) or user.get('key'):
            return 3
        explicit = str(user.get('scheme') or user.get('auth_type') or '').lower()
        if user.get('token') and explicit in ('apikey', 'api_key'):
            return 2
        return 1 if user.get('token') and not explicit else 0
    if declared_type in ('oauth2', 'openidconnect'):
        return 3 if (
            user.get('token') or user.get('access_token') or user.get('refresh_token')
            or (user.get('client_id') and user.get('username') and user.get('password'))
            or (user.get('client_id') and user.get('client_secret'))
        ) else 0
    if declared_type == 'http':
        if str(scheme.get('scheme', '')).lower() != 'bearer':
            return 0
        return 2 if user.get('token') or user.get('access_token') else 0
    return 0


def build_auth_handler(user: dict | str, security_options=None):
    """Choose an OpenAPI OR alternative and compose its AND schemes."""
    if not security_options:
        return AuthHandler.from_user(user)
    if isinstance(security_options, dict):
        return AuthHandler.from_user(user, security_options)
    if security_options and isinstance(security_options[0], dict):
        security_options = [security_options]
    if any(not option for option in security_options):
        return AnonymousAuthHandler()

    candidates = []
    for index, option in enumerate(security_options):
        scores = [_scheme_score(user, scheme) for scheme in option]
        if option and all(scores):
            candidates.append((sum(scores), -index, option))
    if candidates:
        _, _, selected = max(candidates, key=lambda item: (item[0], item[1]))
        return CompositeAuthHandler([
            AuthHandler.from_user(user, scheme) for scheme in selected
        ])
    raise ValueError('Configured user credentials do not satisfy any OpenAPI security requirement.')
