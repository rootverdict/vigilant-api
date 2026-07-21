"""
oauth_detector.py
-----------------
Detects common OAuth 2.0 implementation flaws:

  1. State integrity failure – authorization response changes/omits client state
  2. Token leakage in Referer – access_token in URL → leaked via Referer header
  3. Improper scope validation – server grants more scope than requested
  4. Authorization code reuse – server accepts the same code twice
  5. Open redirect abuse       – redirect_uri not validated → steal auth code

These are logic flaws — they can't be found by a port scanner.
They require understanding the OAuth flow and probing the authorization server.
"""

import time
import requests
from urllib.parse import parse_qs, urljoin, urlparse

from request_utils import RequestBudget


class OAuthFlawDetector:

    def __init__(self, auth_url: str, token_url: str, client_id: str,
                 client_secret: str = '', redirect_uri: str = 'http://localhost/callback',
                 verify: bool = True, proxy: str = None, verbose: bool = False,
                 delay: float = 0.0, active: bool = False,
                 budget: RequestBudget = None):
        self.auth_url      = auth_url
        self.token_url     = token_url
        self.client_id     = client_id
        self.client_secret = client_secret
        self.redirect_uri  = redirect_uri
        self.verify        = verify
        self.proxies       = {'http': proxy, 'https': proxy} if proxy else None
        self.verbose       = verbose
        self.delay         = delay
        self.active        = active
        self.budget        = budget

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    # Checks that rely on synthetic payloads — effective only against the
    # Vigilant-API mock server.  Against a real OAuth server they will return
    # no findings (silent false-negative, NOT a false-positive).
    _MOCK_ONLY_CHECKS = frozenset({
        'Authorization Code Reuse',
        'Token Leakage in URL / Referer',
    })

    def run_all_checks(self) -> list:
        if self.verbose:
            print(
                '      [OAuth] NOTE: "Authorization Code Reuse" and '
                '"Token Leakage in URL / Referer" checks use synthetic payloads '
                'and are only effective against the Vigilant-API mock server. '
                'A negative result against a real OAuth server does NOT confirm '
                'those controls are implemented correctly.'
            )
        findings = []
        findings += self._check_state_integrity()
        if self.active:
            findings += self._check_token_leakage_in_url()
            findings += self._check_improper_scope()
            findings += self._check_code_reuse()
        findings += self._check_open_redirect()
        return findings

    # ------------------------------------------------------------------ #
    #  Sub-checks                                                          #
    # ------------------------------------------------------------------ #

    def _check_state_integrity(self) -> list:
        """
        Send a unique state value and verify that the authorization response
        preserves it exactly. Whether a client sends and validates state is a
        client-side concern; an omitted state request alone is not proof that
        the authorization server is vulnerable.
        """
        expected_state = 'vigilant-state-integrity-check'
        params = {
            'response_type': 'code',
            'client_id':     self.client_id,
            'redirect_uri':  self.redirect_uri,
            'scope':         'read',
            'state':         expected_state,
        }
        if self.verbose:
            print(f'      [OAuth] State integrity check  url={self.auth_url}')
        # allow_redirects=False so we capture the 302 Location header directly.
        # With redirects enabled the final 200 response has no Location header
        # and the code= / state= check would never fire.
        resp = self._request('GET', self.auth_url, params=params, allow_redirects=False)

        if resp and resp.status_code in (200, 302):
            location = resp.headers.get('Location', '')
            query = parse_qs(urlparse(location).query)
            returned_state = (query.get('state') or [None])[0]
            if query.get('code') and returned_state != expected_state:
                return [self._make_finding(
                    check='OAuth State Integrity Failure',
                    severity='HIGH',
                    description=(
                        'Authorization response did not preserve the state value supplied in the '
                        'request. A client cannot reliably correlate the response with the login '
                        'request, weakening CSRF protection.'
                    ),
                    remediation=(
                        'Return the exact state value supplied by the client. Clients must generate '
                        'a cryptographically random state value and validate it on callback.'
                    ),
                    evidence={
                        'status_code': resp.status_code,
                        'payload': expected_state,
                        'body_preview': location,
                        'request_params': params,
                        'expected_state': expected_state,
                        'returned_state': returned_state,
                        'response_location': location,
                    },
                    method='GET',
                    endpoint=self.auth_url,
                    parameter='state',
                )]
        return []

    def _check_token_leakage_in_url(self) -> list:
        """
        Implicit grant / fragment tokens in URL are leaked via Referer headers
        when the page loads external resources.
        Check if the token_url returns access_token in the URL fragment.
        """
        if self.verbose:
            print(f'      [OAuth] Token leakage check  url={self.token_url}')
        resp = self._request('POST', self.token_url, data={
            'grant_type': 'implicit_test',
            'client_id':  self.client_id,
        })

        if resp:
            url = resp.url
            fragment = urlparse(url).fragment
            if 'access_token=' in fragment or 'access_token=' in url:
                return [self._make_finding(
                    check='Token Leakage in URL / Referer',
                    severity='HIGH',
                    description=(
                        'Access token found in the URL fragment or query string. '
                        'If this page loads any external resource (analytics, fonts, ads), '
                        'the token is leaked in the Referer header.'
                    ),
                    remediation='Use authorization code flow with PKCE instead of implicit flow. Never put tokens in URLs.',
                    evidence={
                        'status_code': resp.status_code,
                        'body_preview': url,
                        'request_data': {
                            'grant_type': 'implicit_test',
                            'client_id': self.client_id,
                        },
                        'leaking_url': url,
                    },
                    method='POST',
                    endpoint=self.token_url,
                )]
        return []

    def _check_improper_scope(self) -> list:
        """
        Request a limited scope ('read:own') but check if the returned token
        actually grants broader access than requested.
        """
        if self.verbose:
            print(f'      [OAuth] Scope validation check  url={self.token_url}')
        resp = self._request('POST', self.token_url, data={
            'grant_type':    'client_credentials',
            'client_id':     self.client_id,
            'client_secret': self.client_secret,
            'scope':         'read:own',  # restricted scope
        })

        if resp and resp.status_code == 200:
            try:
                data = resp.json() if resp.content else {}
            except ValueError:
                return []
            if not isinstance(data, dict):
                return []
            raw_scope = data.get('scope', '')
            if isinstance(raw_scope, str):
                granted_scopes = set(raw_scope.split())
            elif isinstance(raw_scope, list):
                granted_scopes = {str(item) for item in raw_scope}
            else:
                return []
            broad_indicators = {'admin', 'write', 'read:all', '*'}
            if granted_scopes & broad_indicators:
                granted_scope = ' '.join(sorted(granted_scopes))
                return [self._make_finding(
                    check='Improper Scope Validation',
                    severity='HIGH',
                    description=(
                        f'Requested scope "read:own" but server granted "{granted_scope}". '
                        'Server is not enforcing scope restrictions properly.'
                    ),
                    remediation='Server must validate requested scope against what the client is permitted. Never grant broader scope than requested.',
                    evidence={
                        'status_code': resp.status_code,
                        'payload': 'read:own',
                        'body_preview': str(data)[:300],
                        'requested_scope': 'read:own',
                        'granted_scope': granted_scope,
                    },
                    method='POST',
                    endpoint=self.token_url,
                    parameter='scope',
                )]
        return []

    def _check_code_reuse(self) -> list:
        """
        Use an authorization code twice. RFC 6749 requires servers to reject
        the second use AND revoke all tokens issued from that code.

        Limitation — mock server only:
          This check sends a hardcoded test code ('vigilant-test-reuse-code-12345').
          It works against the Vigilant-API mock server (which accepts any code for
          the authorization_code grant type) but will always return a false negative
          against a real OAuth server, because the test code is not a valid code
          issued by that server.

          A full implementation would require automating the authorization code
          flow: (1) redirect the user to the auth endpoint, (2) capture the code
          from the callback redirect, (3) exchange it once, (4) try again. This
          requires browser automation (Selenium / Playwright) and is out of scope
          for v1. The check is retained for mock-server testing and documentation.
        """
        test_code = 'vigilant-test-reuse-code-12345'

        payload = {
            'grant_type':    'authorization_code',
            'code':          test_code,
            'client_id':     self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri':  self.redirect_uri,
        }

        if self.verbose:
            print(f'      [OAuth] Code reuse check  url={self.token_url}')
        resp1 = self._request('POST', self.token_url, data=payload)
        resp2 = self._request('POST', self.token_url, data=payload)

        if resp1 and resp2 and resp1.status_code == 200 and resp2.status_code == 200:
            return [self._make_finding(
                check='Authorization Code Reuse',
                severity='HIGH',
                description=(
                    'The same authorization code was accepted twice. '
                    'An attacker who intercepts a code (e.g. via Referer) can exchange it for a token '
                    'even after the legitimate user has already used it. '
                    'NOTE: This check used a synthetic test code and is reliable only against the '
                    'Vigilant-API mock server. Verify against a real OAuth server by manually '
                    'capturing and replaying a live authorization code.'
                ),
                remediation='Authorization codes must be single-use. Invalidate immediately upon first exchange. On second use, revoke all issued tokens.',
                evidence={
                    'status_code': resp2.status_code,
                    'payload': test_code,
                    'body_preview': (
                        f'First exchange: HTTP {resp1.status_code}; '
                        f'second exchange: HTTP {resp2.status_code}'
                    ),
                    'request_data': payload,
                    'code': test_code,
                    'response_1_status': resp1.status_code,
                    'response_2_status': resp2.status_code,
                },
                method='POST',
                endpoint=self.token_url,
                parameter='code',
            )]
        return []

    def _check_open_redirect(self) -> list:
        """
        Send an authorization request with an unregistered redirect_uri.
        If the server redirects to it anyway, an attacker can steal the code.
        """
        evil_redirect = 'https://evil-attacker.com/steal'
        params = {
            'response_type': 'code',
            'client_id':     self.client_id,
            'redirect_uri':  evil_redirect,   # not registered
            'state':         'vigilant_test',
            'scope':         'read',
        }
        if self.verbose:
            print(f'      [OAuth] Open redirect check  url={self.auth_url}')
        resp = self._request('GET', self.auth_url, params=params, allow_redirects=False)

        if resp:
            location = resp.headers.get('Location', '')
            resolved_location = urljoin(self.auth_url, location)
            actual = urlparse(resolved_location)
            expected = urlparse(evil_redirect)
            same_destination = (
                actual.scheme.lower() == expected.scheme.lower()
                and actual.hostname == expected.hostname
                and (actual.port or self._default_port(actual.scheme))
                == (expected.port or self._default_port(expected.scheme))
                and actual.path.rstrip('/') == expected.path.rstrip('/')
            )
            if same_destination:
                return [self._make_finding(
                    check='Open Redirect Abuse via redirect_uri',
                    severity='CRITICAL',
                    description=(
                        f'Server redirected to unregistered URI: {evil_redirect}. '
                        'An attacker can craft a link to steal authorization codes by setting '
                        'redirect_uri to their own server.'
                    ),
                    remediation='Strictly validate redirect_uri against a pre-registered allowlist. Reject exact-match failures. No wildcard matching.',
                    evidence={
                        'status_code': resp.status_code,
                        'payload': evil_redirect,
                        'body_preview': location,
                        'request_params': params,
                        'evil_redirect_uri': evil_redirect,
                        'location_header': location,
                    },
                    method='GET',
                    endpoint=self.auth_url,
                    parameter='redirect_uri',
                )]
        return []

    @staticmethod
    def _default_port(scheme: str) -> int | None:
        return {'http': 80, 'https': 443}.get(scheme.lower())

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _request(self, method, url, allow_redirects=True, **kwargs):
        """Send a single OAuth probe request with optional rate-limit retry (429 backoff)."""
        for attempt in range(3):
            try:
                if self.budget and not self.budget.consume():
                    return None
                resp = requests.request(
                    method, url, timeout=8, allow_redirects=allow_redirects,
                    verify=self.verify, proxies=self.proxies, **kwargs
                )
                if resp.status_code == 429:
                    wait = (2 ** attempt) * max(self.delay, 1.0)
                    if self.verbose:
                        print(f'      [OAuth] 429 rate-limited — retrying in {wait:.1f}s')
                    time.sleep(wait)
                    continue
                if resp.status_code >= 500:
                    wait = (2 ** attempt) * max(self.delay, 0.5)
                    if self.verbose:
                        print(f'      [OAuth] {resp.status_code} server error — retrying in {wait:.1f}s')
                    time.sleep(wait)
                    continue
                if self.delay > 0:
                    time.sleep(self.delay)
                return resp
            except requests.RequestException:
                return None
        return None   # all retries exhausted

    def _make_finding(self, check, severity, description, remediation, evidence,
                      method: str | None = None, endpoint: str | None = None,
                      parameter: str | None = None) -> dict:
        return {
            'type':        'OAuth Flaw',
            'method':      method,
            'endpoint':    endpoint,
            'parameter':   parameter,
            'check':       check,
            'vulnerable':  True,
            'severity':    severity,
            'description': description,
            'remediation': remediation,
            'evidence':    evidence,
        }
