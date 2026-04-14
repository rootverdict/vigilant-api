"""
oauth_detector.py
-----------------
Detects common OAuth 2.0 implementation flaws:

  1. Missing state parameter  – CSRF against the auth flow
  2. Token leakage in Referer – access_token in URL → leaked via Referer header
  3. Improper scope validation – server grants more scope than requested
  4. Authorization code reuse – server accepts the same code twice
  5. Open redirect abuse       – redirect_uri not validated → steal auth code

These are logic flaws — they can't be found by a port scanner.
They require understanding the OAuth flow and probing the authorization server.
"""

import re
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class OAuthFlawDetector:

    def __init__(self, auth_url: str, token_url: str, client_id: str,
                 client_secret: str = '', redirect_uri: str = 'http://localhost/callback',
                 verify: bool = True, proxy: str = None, verbose: bool = False,
                 delay: float = 0.0):
        self.auth_url      = auth_url
        self.token_url     = token_url
        self.client_id     = client_id
        self.client_secret = client_secret
        self.redirect_uri  = redirect_uri
        self.verify        = verify
        self.proxies       = {'http': proxy, 'https': proxy} if proxy else None
        self.verbose       = verbose
        self.delay         = delay

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def run_all_checks(self) -> list:
        findings = []
        findings += self._check_missing_state()
        findings += self._check_token_leakage_in_url()
        findings += self._check_improper_scope()
        findings += self._check_code_reuse()
        findings += self._check_open_redirect()
        return findings

    # ------------------------------------------------------------------ #
    #  Sub-checks                                                          #
    # ------------------------------------------------------------------ #

    def _check_missing_state(self) -> list:
        """
        Send an auth request WITHOUT the 'state' param.
        If the server redirects back with a code anyway, it's vulnerable to CSRF.
        """
        params = {
            'response_type': 'code',
            'client_id':     self.client_id,
            'redirect_uri':  self.redirect_uri,
            'scope':         'read',
            # 'state' intentionally omitted
        }
        if self.verbose:
            print(f'      [OAuth] Missing state check  url={self.auth_url}')
        resp = self._request('GET', self.auth_url, params=params)

        if resp and resp.status_code in (200, 302):
            location = resp.headers.get('Location', '')
            if 'code=' in location and 'state=' not in location:
                return [self._make_finding(
                    check='Missing state Parameter',
                    severity='HIGH',
                    description=(
                        'Authorization endpoint accepted a request without a "state" parameter. '
                        'An attacker can trick a victim into authorizing an app via CSRF, '
                        'then capture the authorization code.'
                    ),
                    remediation='Require a cryptographically random "state" parameter on every authorization request. Validate it on callback.',
                    evidence={'request_params': params, 'response_location': location},
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
                    evidence={'leaking_url': url},
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
            data = resp.json() if resp.content else {}
            granted_scope = data.get('scope', '')
            broad_indicators = ('admin', 'write', 'read:all', '*')
            if any(s in granted_scope for s in broad_indicators):
                return [self._make_finding(
                    check='Improper Scope Validation',
                    severity='HIGH',
                    description=(
                        f'Requested scope "read:own" but server granted "{granted_scope}". '
                        'Server is not enforcing scope restrictions properly.'
                    ),
                    remediation='Server must validate requested scope against what the client is permitted. Never grant broader scope than requested.',
                    evidence={'requested_scope': 'read:own', 'granted_scope': granted_scope},
                )]
        return []

    def _check_code_reuse(self) -> list:
        """
        Use an authorization code twice. RFC 6749 requires servers to reject
        the second use AND revoke all tokens issued from that code.
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
                    'even after the legitimate user has already used it.'
                ),
                remediation='Authorization codes must be single-use. Invalidate immediately upon first exchange. On second use, revoke all issued tokens.',
                evidence={'code': test_code, 'response_1_status': resp1.status_code, 'response_2_status': resp2.status_code},
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
            if evil_redirect in location:
                return [self._make_finding(
                    check='Open Redirect Abuse via redirect_uri',
                    severity='CRITICAL',
                    description=(
                        f'Server redirected to unregistered URI: {evil_redirect}. '
                        'An attacker can craft a link to steal authorization codes by setting '
                        'redirect_uri to their own server.'
                    ),
                    remediation='Strictly validate redirect_uri against a pre-registered allowlist. Reject exact-match failures. No wildcard matching.',
                    evidence={'evil_redirect_uri': evil_redirect, 'location_header': location},
                )]
        return []

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _request(self, method, url, allow_redirects=True, **kwargs):
        try:
            resp = requests.request(
                method, url, timeout=8, allow_redirects=allow_redirects,
                verify=self.verify, proxies=self.proxies, **kwargs
            )
            if self.delay > 0:
                time.sleep(self.delay)
            return resp
        except requests.RequestException:
            return None

    def _make_finding(self, check, severity, description, remediation, evidence) -> dict:
        return {
            'type':        'OAuth Flaw',
            'check':       check,
            'vulnerable':  True,
            'severity':    severity,
            'description': description,
            'remediation': remediation,
            'evidence':    evidence,
        }
