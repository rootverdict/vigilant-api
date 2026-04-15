"""
bola_detector.py
----------------
Detects BOLA (Broken Object Level Authorization) aka IDOR.

Strategy: Differential Testing
  1. User A creates / owns resource #ID
  2. User B (different role) attempts to read the same #ID
  3. If User B gets 200 + meaningful data → BOLA confirmed

Sub-checks:
  - Simple IDOR           : GET /resource/{id} with another user's token
  - Parameter pollution   : GET /resource?id=A&id=B (two id values)
  - Body IDOR             : POST body contains another user's object id
  - Indirect reference    : Encoded IDs (base64, hex, UUID) are still enumerable
  - Mass assignment       : Privileged fields accepted in POST/PUT/PATCH body

All checks return findings into a shared list returned to the caller.
"""

import re
import time
import base64
import hashlib
import uuid as _uuid
import requests


class BOLADetector:

    # Privileged field names that should never be user-settable
    _PRIVILEGED_KEYS = {
        'role', 'is_admin', 'admin', 'user_type', 'account_type', 'plan',
        'balance', 'credit', 'credits', 'verified', 'email_verified',
        'phone_verified', 'is_verified', 'permissions', 'scope', 'subscription',
    }

    def __init__(self, base_url: str, users: list,
                 delay: float = 0.0, verify: bool = True,
                 proxy: str = None, verbose: bool = False):
        """
        base_url : e.g. 'http://localhost:5000'
        users    : [
                     {'name': 'alice', 'token': 'eyJ...', 'user_id': 1},
                     {'name': 'bob',   'token': 'eyJ...', 'user_id': 2},
                   ]
        delay    : seconds to sleep between requests (rate limiting).
        verify   : set False to skip TLS certificate verification.
        proxy    : HTTP proxy URL e.g. 'http://127.0.0.1:8080'.
        verbose  : print every request URL + payload to stdout.
        """
        self.base_url = base_url.rstrip('/')
        self.users    = users
        self.delay    = delay
        self.verify   = verify
        self.proxies  = {'http': proxy, 'https': proxy} if proxy else None
        self.verbose  = verbose

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def test_endpoint(self, method: str, path: str, resource_ids: list) -> list:
        """
        Run all BOLA sub-checks on a single endpoint.

        path         : OpenAPI path string, e.g. '/transactions/{id}'
        resource_ids : list of integer IDs to probe

        Returns a list of finding dicts (may be empty if nothing found).
        """
        findings = []
        body_method = method in ('POST', 'PUT', 'PATCH')

        for rid in resource_ids:
            findings += self._simple_idor(method, path, rid)
            findings += self._param_pollution(path, rid)
            if body_method:
                findings += self._body_idor(path, rid)

        # Indirect reference only needs one ID — if the server accepts encoded
        # references at all it will show on the first ID. Testing all 5 IDs
        # adds 20 extra requests per endpoint with zero additional insight.
        if resource_ids:
            findings += self._indirect_reference(method, path, resource_ids[0])

        # Body-only checks — only run on endpoints that accept a request body
        if body_method:
            findings += self._mass_assignment(path)

        return findings

    # ------------------------------------------------------------------ #
    #  Sub-checks                                                          #
    # ------------------------------------------------------------------ #

    def _simple_idor(self, method: str, path: str, resource_id: int) -> list:
        """
        Classic IDOR: each user tries to access every other user's resource.
        Vulnerable when User B can read User A's data.
        """
        findings  = []
        responses = {}

        # Step 1 – collect each user's response
        for user in self.users:
            url  = self._build_url(path, resource_id)
            if self.verbose:
                print(f'      [BOLA] Simple IDOR  user={user["name"]}  url={url}')
            resp = self._request(method, url, user['token'])
            responses[user['name']] = {
                'status': resp.status_code if resp else None,
                'body':   self._safe_json(resp),
                'size':   len(resp.content) if resp else 0,
            }

        # Step 2 – compare: any non-owner getting 200 + data?
        owner = self.users[0]
        owner_resp = responses[owner['name']]

        for user in self.users[1:]:
            ur = responses[user['name']]
            if (
                ur['status'] in (200, 201)
                and ur['body']
                and self._bodies_similar(ur['body'], owner_resp['body'])
            ):
                findings.append(self._make_finding(
                    check='Simple IDOR',
                    path=path,
                    resource_id=resource_id,
                    owner=owner['name'],
                    unauthorized_user=user['name'],
                    status=ur['status'],
                    body_preview=str(ur['body'])[:300],
                    severity='HIGH',
                ))

        return findings

    def _param_pollution(self, path: str, resource_id: int) -> list:
        """
        HTTP Parameter Pollution: send two values for the same id param.
        Some servers use the first, some use the last → may bypass auth.

        e.g. GET /transactions?id=1&id=2
        """
        findings = []
        victim_id = resource_id
        attacker  = self.users[-1]

        for params in [
            f'id={victim_id}&id={attacker.get("user_id", 999)}',
            f'id={attacker.get("user_id", 999)}&id={victim_id}',
        ]:
            url  = f'{self.base_url}{self._strip_path_params(path)}?{params}'
            if self.verbose:
                print(f'      [BOLA] Param Pollution  url={url}')
            resp = self._request('GET', url, attacker['token'])

            if resp and resp.status_code == 200 and resp.content:
                findings.append(self._make_finding(
                    check='Parameter Pollution IDOR',
                    path=path,
                    resource_id=resource_id,
                    owner='victim',
                    unauthorized_user=attacker['name'],
                    status=resp.status_code,
                    body_preview=str(self._safe_json(resp))[:300],
                    severity='MEDIUM',
                ))
                break

        return findings

    def _body_idor(self, path: str, resource_id: int) -> list:
        """
        Body IDOR: POST/PUT body contains another user's id.
        e.g. POST /transfer  {'from_account_id': 1, 'to_account_id': 2, 'amount': 500}
        """
        findings = []
        attacker = self.users[-1]

        payloads = [
            # snake_case conventional names
            {'user_id': resource_id, 'amount': 1},
            {'account_id': resource_id},
            {'from_account_id': resource_id, 'to_account_id': attacker.get('user_id', 999), 'amount': 0.01},
            {'owner_id': resource_id},
            {'customer_id': resource_id},
            {'profile_id': resource_id},
            {'resource_id': resource_id},
            {'object_id': resource_id},
            {'entity_id': resource_id},
            {'record_id': resource_id},
            {'subject_id': resource_id},
            {'target_id': resource_id},
            # camelCase variants
            {'userId': resource_id},
            {'accountId': resource_id},
            {'ownerId': resource_id},
            {'customerId': resource_id},
            {'profileId': resource_id},
            {'resourceId': resource_id},
            {'objectId': resource_id},
            {'entityId': resource_id},
        ]

        url = f'{self.base_url}{self._strip_path_params(path)}'

        for payload in payloads:
            for http_method in ('POST', 'PUT', 'PATCH'):
                if self.verbose:
                    print(f'      [BOLA] Body IDOR  {http_method} {url}  payload={payload}')
                resp = self._request(http_method, url, attacker['token'], json=payload)
                if resp and resp.status_code in (200, 201) and resp.content:
                    body = self._safe_json(resp)
                    # Only flag if body contains real data, not a generic success/error message
                    if body and not self._is_error_body(body):
                        findings.append(self._make_finding(
                            check='Body IDOR',
                            path=path,
                            resource_id=resource_id,
                            owner='victim',
                            unauthorized_user=attacker['name'],
                            status=resp.status_code,
                            body_preview=str(body)[:300],
                            severity='HIGH',
                        ))
                        return findings   # one finding per endpoint is enough

        return findings

    def _indirect_reference(self, method: str, path: str, resource_id: int) -> list:
        """
        Indirect Reference Enumeration: encode resource_id in formats that look
        opaque (base64, hex, MD5, UUID-from-int) and check if the server accepts
        them. Predictably encoded references are still enumerable by an attacker.

        A finding means the server accepted an encoded variant of a victim's ID
        without checking ownership.
        """
        findings = []
        attacker = self.users[-1]

        # Generate predictable alternative representations of resource_id
        encoded_ids = [
            base64.b64encode(str(resource_id).encode()).decode(),                     # "MQ==" for 1
            base64.urlsafe_b64encode(str(resource_id).encode()).decode().rstrip('='), # url-safe
            f'{resource_id:08x}',                                                     # "00000001"
            hashlib.md5(str(resource_id).encode()).hexdigest(),                       # MD5 hex
            str(_uuid.UUID(int=resource_id)),                                         # UUID from int
        ]

        for encoded in encoded_ids:
            resolved = re.sub(r'\{[^}]+\}', encoded, path)
            url = f'{self.base_url}{resolved}'
            if self.verbose:
                print(f'      [BOLA] Indirect Ref  url={url}  encoded={encoded!r}')

            resp = self._request(method, url, attacker['token'])
            if resp and resp.status_code == 200 and resp.content:
                body = self._safe_json(resp)
                if body and not self._is_error_body(body):
                    findings.append({
                        'type':              'BOLA/IDOR',
                        'check':             'Indirect Reference Enumeration',
                        'vulnerable':        True,
                        'severity':          'MEDIUM',
                        'endpoint':          path,
                        'resource_id':       resource_id,
                        'owner':             'victim',
                        'unauthorized_user': attacker['name'],
                        'evidence': {
                            'status_code':   resp.status_code,
                            'encoded_id':    encoded,
                            'body_preview':  str(body)[:300],
                        },
                        'description': (
                            f'Resource for ID {resource_id} accessible via encoded reference '
                            f'"{encoded}". This encoding is predictable — an attacker can '
                            'enumerate victim IDs by applying the same encoding to sequential integers.'
                        ),
                        'remediation': (
                            'Use cryptographically random, non-guessable UUIDs (v4) as resource identifiers. '
                            'Never use base64, hex, or hash encodings of sequential integers as references — '
                            'they provide no security. Enforce server-side ownership checks on every access '
                            'regardless of the reference format used.'
                        ),
                    })
                    break   # one finding per resource_id

        return findings

    def _mass_assignment(self, path: str) -> list:
        """
        Mass Assignment: send privileged fields (role, is_admin, balance, etc.)
        in a POST/PUT/PATCH body and check if the server reflects them back,
        indicating it accepted and stored the value without stripping it.

        Vulnerable when the server binds the raw request body directly to a
        database model without field-level allowlisting.
        """
        findings = []
        attacker = self.users[-1]
        url = f'{self.base_url}{self._strip_path_params(path)}'

        # Each payload probes a different category of privileged field
        privilege_payloads = [
            # Role / permission elevation
            {'role': 'admin'},
            {'is_admin': True},
            {'admin': True},
            {'user_type': 'admin'},
            {'permissions': ['admin', 'read', 'write', 'delete']},
            {'scope': 'admin:all'},
            # Financial manipulation
            {'balance': 999999},
            {'credit': 999999},
            {'credits': 9999},
            # Identity / verification bypass
            {'verified': True},
            {'email_verified': True},
            {'phone_verified': True},
            {'is_verified': True},
            # Subscription / tier escalation
            {'subscription': 'enterprise'},
            {'account_type': 'premium'},
            {'plan': 'unlimited'},
        ]

        for payload in privilege_payloads:
            for http_method in ('POST', 'PUT', 'PATCH'):
                if self.verbose:
                    print(f'      [BOLA] Mass Assignment  {http_method} {url}  payload={payload}')

                resp = self._request(http_method, url, attacker['token'], json=payload)
                if resp and resp.status_code in (200, 201) and resp.content:
                    body = self._safe_json(resp)
                    if isinstance(body, dict):
                        # Confirmed vulnerable: privileged field reflected back with sent value
                        for key, sent_val in payload.items():
                            if key in body and body[key] == sent_val:
                                findings.append({
                                    'type':              'BOLA/IDOR',
                                    'check':             'Mass Assignment',
                                    'vulnerable':        True,
                                    'severity':          'HIGH',
                                    'endpoint':          path,
                                    'resource_id':       None,
                                    'owner':             'system',
                                    'unauthorized_user': attacker['name'],
                                    'evidence': {
                                        'status_code':      resp.status_code,
                                        'method':           http_method,
                                        'payload':          payload,
                                        'reflected_field':  key,
                                        'reflected_value':  sent_val,
                                        'body_preview':     str(body)[:300],
                                    },
                                    'description': (
                                        f'Server accepted privileged field "{key}" = {sent_val!r} '
                                        f'via {http_method} and reflected it in the response. '
                                        'Mass assignment allows users to escalate privileges or '
                                        'manipulate server-controlled fields.'
                                    ),
                                    'remediation': (
                                        'Apply an explicit allowlist (DTO pattern) of fields users '
                                        'are permitted to set. Never bind the raw request body '
                                        'directly to a database model or ORM object. '
                                        'Strip or reject any field not in the allowlist before '
                                        'processing. In ORMs, use attr_accessible or equivalent.'
                                    ),
                                })
                                return findings   # one finding per endpoint is enough

        return findings

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _build_url(self, path: str, resource_id: int) -> str:
        """Replace ALL {param} placeholders in path with resource_id."""
        resolved = re.sub(r'\{[^}]+\}', str(resource_id), path)
        return f'{self.base_url}{resolved}'

    def _strip_path_params(self, path: str) -> str:
        """Remove {param} segments for endpoints used as base in query/body checks."""
        return re.sub(r'/\{[^}]+\}', '', path)

    def _request(self, method: str, url: str, token: str, **kwargs) -> requests.Response | None:
        try:
            headers = {'Authorization': f'Bearer {token}'}
            resp = requests.request(
                method, url, headers=headers, timeout=8,
                verify=self.verify, proxies=self.proxies, **kwargs
            )
            if self.delay > 0:
                time.sleep(self.delay)
            return resp
        except requests.RequestException:
            return None

    def _safe_json(self, resp: requests.Response | None):
        if resp is None:
            return None
        try:
            return resp.json()
        except Exception:
            return resp.text[:200] if resp.text else None

    def _is_error_body(self, body) -> bool:
        """Return True if the response body looks like a generic error, not real data."""
        if not isinstance(body, dict):
            return False
        keys = set(body.keys())
        error_keys = {'error', 'detail', 'message', 'msg', 'status', 'code'}
        # All keys are error-like → it's an error response, not real data
        return keys <= error_keys

    def _bodies_similar(self, b1, b2) -> bool:
        """
        Fuzzy comparison: checks if two response bodies share top-level keys
        and therefore represent the same type of resource.
        Avoids false positives from generic error messages.
        """
        if not isinstance(b1, dict) or not isinstance(b2, dict):
            return False
        shared_keys = set(b1.keys()) & set(b2.keys())
        error_indicators = {'error', 'detail', 'message'}
        if shared_keys - error_indicators:
            return len(shared_keys) >= 2
        return False

    def _make_finding(self, check, path, resource_id, owner,
                      unauthorized_user, status, body_preview, severity) -> dict:
        return {
            'type':              'BOLA/IDOR',
            'check':             check,
            'vulnerable':        True,
            'severity':          severity,
            'endpoint':          path,
            'resource_id':       resource_id,
            'owner':             owner,
            'unauthorized_user': unauthorized_user,
            'evidence': {
                'status_code':  status,
                'body_preview': body_preview,
            },
            'remediation': (
                'Enforce object-level authorization on every request. '
                'Verify that the authenticated user owns (or is explicitly permitted to access) '
                'the requested resource_id before returning data. '
                'Never rely solely on sequential IDs — use UUIDs and server-side ownership checks.'
            ),
        }
