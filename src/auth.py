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


class AuthHandler:
    def __init__(self, scheme_type: str, credentials: dict):
        """
        scheme_type : 'bearer' | 'apiKey' | 'oauth2'
        credentials : dict with keys depending on scheme (see below)
        """
        self.scheme      = scheme_type.lower()
        self.credentials = credentials
        self._token      = None            # cached token

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def get_token(self) -> str:
        """Return a valid token, refreshing if needed."""
        if self._token and not self._is_expired(self._token):
            return self._token

        if self.scheme == 'oauth2':
            # Use refresh_token if we have one, otherwise do a full password grant
            if self.credentials.get('refresh_token'):
                self._token = self._refresh_oauth_token()
            else:
                self._token = self._oauth_password_grant()
        elif self.scheme == 'bearer':
            self._token = self.credentials['token']
        elif self.scheme == 'apikey':
            self._token = self.credentials['key']
        else:
            raise ValueError(f"Unsupported auth scheme: {self.scheme}")

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
            # Common convention: X-API-Key header
            header_name = self.credentials.get('header_name', 'X-API-Key')
            session.headers.update({header_name: token})

        return session

    def inspect_jwt(self, token: str = None) -> dict:
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
                'check':     'JWT Algorithm: weak HS256',
                'vulnerable': True,
                'severity':  'MEDIUM',
                'description': (
                    'JWT uses HS256 (symmetric HMAC). If the secret is weak, reused across services, '
                    'or leaked, tokens can be forged. Asymmetric algorithms (RS256/ES256) are preferred '
                    'for APIs where multiple services verify tokens.'
                ),
                'remediation': (
                    'Prefer RS256 or ES256 for multi-service architectures. '
                    'If HS256 is required, ensure the secret is cryptographically random and ≥ 256 bits.'
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
