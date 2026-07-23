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
  - Indirect reference    : Encoded IDs (base64, hex, MD5) are still enumerable
  - Mass assignment       : Privileged fields accepted in POST/PUT/PATCH body

Known limitations:
  - Mass Assignment detects reflection in the immediate response only.
    Persistence is not verified (a follow-up GET would require knowing the
    corresponding read endpoint, which is not guaranteed by the OpenAPI spec).
    Treat findings as "possible mass assignment" and confirm manually.
  - Indirect Reference uses realistic encodings only (base64, URL-safe base64,
    hex, MD5). UUID-from-int is excluded — no real API accepts that format.

All checks return findings into a shared list returned to the caller.
"""

import re
import time
import base64
import hashlib
import requests
from urllib.parse import quote as _urlquote

from auth import AnonymousAuthHandler, AuthHandler, CompositeAuthHandler, build_auth_handler
from request_utils import RequestBudget


class BOLADetector:

    # Privileged field names that should never be user-settable
    _PRIVILEGED_KEYS = {
        'role', 'is_admin', 'admin', 'user_type', 'account_type', 'plan',
        'balance', 'credit', 'credits', 'verified', 'email_verified',
        'phone_verified', 'is_verified', 'permissions', 'scope', 'subscription',
    }
    _PRIVILEGED_IDENTITIES = {
        'admin', 'administrator', 'root', 'superadmin', 'superuser', 'system',
    }

    def __init__(self, base_url: str, users: list,
                 delay: float = 0.0, verify: bool = True,
                 proxy: str = None, verbose: bool = False,
                 active: bool = False, budget: RequestBudget = None):
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
        self.active   = active
        self.budget   = budget
        self._auth_scheme: object = None
        self._auth_handlers: dict[
            tuple, AuthHandler | CompositeAuthHandler | AnonymousAuthHandler
        ] = {}
        self._method: str | None = None
        self._path_params: list = []

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def test_endpoint(self, method: str, path: str, resource_ids: list,
                      params: list = None, auth_scheme: dict = None) -> list:
        """
        Run all BOLA sub-checks on a single endpoint.

        path         : OpenAPI path string, e.g. '/transactions/{id}'
        resource_ids : list of integer IDs to probe

        Returns a list of finding dicts (may be empty if nothing found).
        """
        findings = []
        params = params or []
        self._auth_scheme = auth_scheme
        self._method = method
        body_method = method in ('POST', 'PUT', 'PATCH')
        body_idor_found = False   # stop retrying body IDOR after first hit

        path_params = [p for p in params if p.get('in') == 'path']
        if not path_params and '{' in path:
            path_params = [
                {'name': name, 'in': 'path', 'schema': {}}
                for name in re.findall(r'\{([^}]+)\}', path)
            ]
        self._path_params = path_params
        query_id_params = [
            p for p in params
            if p.get('in') == 'query' and 'id' in p.get('name', '').lower()
        ]
        body_params = [p for p in params if p.get('in') in ('body', 'form')]

        for path_param in path_params:
            for rid in resource_ids:
                if method in ('GET', 'HEAD', 'OPTIONS') or self.active:
                    findings += self._simple_idor(method, path, rid, path_param['name'])

        if query_id_params:
            for query_param in query_id_params:
                for rid in resource_ids:
                    if method in ('GET', 'HEAD', 'OPTIONS') or self.active:
                        findings += self._param_pollution(method, path, rid, query_param)

        if self.active and body_method and body_params:
            for rid in resource_ids:
                if body_idor_found:
                    break
                new = self._body_idor(method, path, rid, body_params)
                findings += new
                if new:
                    body_idor_found = True   # skip remaining rids for body IDOR

        # Indirect reference only applies to paths that have a {param} to encode.
        # Without a placeholder, re.sub has nothing to replace — the URL stays
        # identical across all encodings, so all 4 requests go to the same
        # endpoint with no useful test being performed.
        if resource_ids and (method in ('GET', 'HEAD', 'OPTIONS') or self.active):
            for path_param in path_params:
                findings += self._indirect_reference(
                    method, path, resource_ids[0], path_param['name']
                )

        # Body-only checks — only run on endpoints that accept a request body
        if self.active and body_method:
            findings += self._mass_assignment(method, path)

        return findings

    # ------------------------------------------------------------------ #
    #  Sub-checks                                                          #
    # ------------------------------------------------------------------ #

    def _simple_idor(self, method: str, path: str, resource_id: int,
                     param_name: str | None = None) -> list:
        """
        Classic IDOR: each user tries to access every other user's resource.
        Vulnerable when User B can read User A's data.
        """
        findings  = []
        responses = {}

        # Step 1 – collect each user's response
        # Send empty JSON body for POST/PUT/PATCH so Flask doesn't return 415
        body_kwargs: dict[str, object] = (
            {'json': {}} if method in ('POST', 'PUT', 'PATCH') else {}
        )
        for user in self.users:
            url = self._build_url(path, resource_id, param_name)
            if self.verbose:
                print(f'      [BOLA] Simple IDOR  user={user["name"]}  url={url}')
            resp = self._request(method, url, user, **body_kwargs)
            responses[user['name']] = {
                'status': resp.status_code if resp else None,
                'body':   self._safe_json(resp),
                'size':   len(resp.content) if resp else 0,
            }

        # Step 2 – identify the actual owner, then compare non-owner access.
        owner = self._identify_owner(path, resource_id, responses)
        if owner is None:
            return []
        owner_resp = responses[owner['name']]
        if owner_resp['status'] not in (200, 201) or not owner_resp['body']:
            return []

        for user in self.users:
            if self._is_authorized_user(user, owner, resource_id):
                continue
            ur = responses[user['name']]
            if not (
                ur['status'] in (200, 201)
                and ur['body']
                and self._bodies_similar(ur['body'], owner_resp['body'])
            ):
                continue

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

    def _identify_owner(self, path: str, resource_id: int,
                        responses: dict) -> dict | None:
        """Identify a resource owner from explicit config or response fields."""
        for user in self.users:
            owned = user.get('resource_ids') or []
            if any(str(item) == str(resource_id) for item in owned):
                return user

        ownership_keys = {
            'owner_id', 'user_id', 'account_id', 'customer_id',
            'profile_id', 'subject_id', 'tenant_id',
        }
        observed_owner_ids = set()

        def collect(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.lower() in ownership_keys and child not in (None, ''):
                        observed_owner_ids.add(str(child))
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        for response in responses.values():
            if response.get('status') in (200, 201):
                collect(response.get('body'))

        matches = [
            user for user in self.users
            if user.get('user_id') is not None
            and str(user['user_id']) in observed_owner_ids
        ]
        if len(matches) == 1:
            return matches[0]

        if any(keyword in path.lower() for keyword in ('user', 'profile', 'account')):
            direct = [
                user for user in self.users
                if user.get('user_id') is not None
                and str(user['user_id']) == str(resource_id)
            ]
            if len(direct) == 1:
                return direct[0]
        return None

    def _param_pollution(self, method: str, path: str, resource_id: int,
                         query_param: dict | None = None) -> list:
        """
        HTTP Parameter Pollution: send two values for the same id param.
        Some servers use the first, some use the last → may bypass auth.

        e.g. GET /transactions?id=1&id=2

        Only meaningful for GET endpoints — POST/PUT/PATCH ignore query-string
        id params in favour of the request body, so we skip them to avoid
        wasting requests that always return 405.
        """
        if method not in ('GET', 'DELETE'):
            return []   # query-string pollution irrelevant for body-method endpoints

        findings = []
        victim_id = resource_id
        attacker = self._select_attacker(resource_id, require_user_id=True)
        if attacker is None:
            return []

        attacker_id     = attacker.get('user_id')
        attacker_id_str = str(attacker_id) if attacker_id else None
        param_name = (query_param or {}).get('name', 'id')
        encoded_name = _urlquote(str(param_name), safe='')
        resolved_url = self._build_url(path, None)

        for params in [
            f'{encoded_name}={victim_id}&{encoded_name}={attacker.get("user_id", 999)}',
            f'{encoded_name}={attacker.get("user_id", 999)}&{encoded_name}={victim_id}',
        ]:
            separator = '&' if '?' in resolved_url else '?'
            url = f'{resolved_url}{separator}{params}'
            if self.verbose:
                print(f'      [BOLA] Param Pollution  url={url}')
            resp = self._request(method, url, attacker)

            if not (resp and resp.status_code == 200 and resp.content):
                continue

            body = self._safe_json(resp)

            # Skip generic error responses — they carry no resource data.
            if not body or self._is_error_body(body):
                continue

            if not self._body_contains_id(body, victim_id):
                continue

            # False-positive guard: if every ID-like field in the response
            # matches the *attacker's* own user_id, the server returned the
            # attacker's own resource (server used last/first value correctly
            # but the "last value" was the attacker's own id).  That is NOT
            # an IDOR — the attacker cannot access victim data.
            if attacker_id and isinstance(body, dict):
                id_vals = self._id_values(body)
                if id_vals and all(
                    (isinstance(v, int) and v == attacker_id) or
                    (isinstance(v, str) and v == attacker_id_str)
                    for v in id_vals
                ):
                    continue   # attacker is reading their own resource — not IDOR

            finding = self._make_finding(
                check='Parameter Pollution IDOR',
                path=path,
                resource_id=resource_id,
                owner='victim',
                unauthorized_user=attacker['name'],
                status=resp.status_code,
                body_preview=str(body)[:300],
                severity='MEDIUM',
            )
            finding['parameter'] = param_name
            finding['evidence']['parameter'] = param_name
            findings.append(finding)
            break

        return findings

    def _body_idor(self, method: str, path: str, resource_id: int,
                   body_params: list) -> list:
        """Differential body-IDOR check using fields declared by OpenAPI."""
        attacker = self._select_attacker(resource_id, require_user_id=True)
        if attacker is None:
            return []
        attacker_id = attacker.get('user_id')
        if attacker_id is None or str(attacker_id) == str(resource_id):
            return []

        id_params = [
            param for param in body_params
            if 'id' in param.get('name', '').lower()
        ]
        if not id_params:
            return []

        url = self._build_url(path, attacker_id)
        for param in id_params:
            own_payload = self._base_body(body_params)
            victim_payload = self._base_body(body_params)
            field_path = param.get('path') or param['name'].split('.')
            self._set_nested(own_payload, field_path, attacker_id)
            self._set_nested(victim_payload, field_path, resource_id)
            request_key = 'data' if param.get('in') == 'form' else 'json'

            if self.verbose:
                print(f'      [BOLA] Body IDOR  {method} {url}  field={param["name"]}')

            own_resp = self._request(method, url, attacker, **{request_key: own_payload})
            victim_resp = self._request(method, url, attacker, **{request_key: victim_payload})
            if not (own_resp and victim_resp):
                continue
            if own_resp.status_code not in (200, 201, 202) or victim_resp.status_code not in (200, 201, 202):
                continue

            own_body = self._safe_json(own_resp)
            victim_body = self._safe_json(victim_resp)
            if (
                not victim_body or self._is_error_body(victim_body)
                or own_body == victim_body
                or not self._response_confirms_id(victim_body, param['name'], resource_id)
            ):
                continue

            finding = self._make_finding(
                check='Body IDOR',
                path=path,
                resource_id=resource_id,
                owner='victim',
                unauthorized_user=attacker['name'],
                status=victim_resp.status_code,
                body_preview=str(victim_body)[:300],
                severity='HIGH',
            )
            finding['evidence']['field'] = param['name']
            finding['evidence']['attacker_baseline'] = str(own_body)[:300]
            finding['evidence']['payload'] = victim_payload
            return [finding]

        return []

    def _indirect_reference(self, method: str, path: str, resource_id: int,
                            param_name: str | None = None) -> list:
        """
        Indirect Reference Enumeration: encode resource_id in formats that look
        opaque (base64, hex, MD5) and check if the server accepts them.
        Predictably encoded references are still enumerable by an attacker.

        Encodings used:
          - Standard base64       e.g. "MQ==" for ID 1
          - URL-safe base64       e.g. "MQ"  for ID 1
          - Zero-padded hex       e.g. "00000001"
          - MD5 of string repr    e.g. "c4ca4238a0b923820dcc509a6f75849b"

        UUID-from-int is intentionally excluded: str(UUID(int=1)) produces
        '00000000-0000-0000-0000-000000000001', which no real API uses as an
        identifier format, making it a guaranteed false negative.

        A finding means the server accepted an encoded variant of a victim's ID
        without checking ownership.
        """
        findings = []
        attacker = self._select_attacker(resource_id, require_user_id=True)
        if attacker is None:
            return []

        # Realistic encodings only — all are actually used by real APIs
        encoded_ids = [
            base64.b64encode(str(resource_id).encode()).decode(),                     # "MQ==" for 1
            base64.urlsafe_b64encode(str(resource_id).encode()).decode().rstrip('='), # url-safe, no padding
            f'{resource_id:08x}',                                                     # "00000001"
            hashlib.md5(str(resource_id).encode()).hexdigest(),                       # MD5 hex digest
        ]

        for encoded in encoded_ids:
            url = self._build_url(path, encoded, param_name)
            if self.verbose:
                print(f'      [BOLA] Indirect Ref  url={url}  encoded={encoded!r}')

            resp = self._request(method, url, attacker)
            if resp and resp.status_code == 200 and resp.content:
                body = self._safe_json(resp)
                if body and not self._is_error_body(body):
                    # A successful response alone does not prove cross-user
                    # access: some APIs return a generic object or the caller's
                    # own resource for unknown references. Require the response
                    # to identify both the requested resource and a different,
                    # known owner before reporting an IDOR.
                    owner = self._identify_owner(
                        path,
                        resource_id,
                        {
                            attacker['name']: {
                                'status': resp.status_code,
                                'body': body,
                                'size': len(resp.content),
                            },
                        },
                    )
                    if (
                        owner is None
                        or self._is_authorized_user(attacker, owner, resource_id)
                        or not self._body_contains_id(body, resource_id)
                    ):
                        continue
                    findings.append({
                        'type':              'BOLA/IDOR',
                        'method':            method,
                        'check':             'Indirect Reference Enumeration',
                        'vulnerable':        True,
                        'severity':          'MEDIUM',
                        'endpoint':          path,
                        'resource_id':       resource_id,
                        'owner':             owner['name'],
                        'unauthorized_user': attacker['name'],
                        'evidence': {
                            'status_code':   resp.status_code,
                            'encoded_id':    encoded,
                            'body_preview':  str(body)[:300],
                        },
                        'description': (
                            f'Resource for ID {resource_id}, owned by "{owner["name"]}", was '
                            f'accessed by "{attacker["name"]}" via encoded reference "{encoded}". '
                            'This encoding is predictable — an attacker can enumerate victim IDs '
                            'by applying the same encoding to sequential integers.'
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

    def _mass_assignment(self, method: str, path: str) -> list:
        """
        Mass Assignment: send privileged fields (role, is_admin, balance, etc.)
        in a POST/PUT/PATCH body and check if the server reflects them back.

        Limitation — reflection only, not persistence:
          This check confirms that the server echoes the privileged field back
          in the immediate response. It does NOT verify that the value was
          persisted to the database (a follow-up GET would require knowing the
          corresponding read endpoint, which cannot be inferred from the spec).
          Some APIs echo request fields without storing them (e.g. for
          documentation/debugging purposes) → treat findings as "possible mass
          assignment" requiring manual confirmation.

        Severity is set to MEDIUM to reflect this uncertainty.
        """
        findings = []
        attacker = self._select_attacker()
        if attacker is None:
            return []
        url = self._build_url(path, attacker.get('user_id', 1))

        # Each payload probes a different category of privileged field
        privilege_payloads: list[dict[str, object]] = [
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
            if self.verbose:
                print(f'      [BOLA] Mass Assignment  {method} {url}  payload={payload}')

            resp = self._request(method, url, attacker, json=payload)
            if resp and resp.status_code in (200, 201) and resp.content:
                body = self._safe_json(resp)
                if isinstance(body, dict):
                    # Confirmed vulnerable: privileged field reflected back with sent value
                    for key, sent_val in payload.items():
                        if key in body and body[key] == sent_val:
                            findings.append({
                                    'type':              'BOLA/IDOR',
                                    'method':            method,
                                    'check':             'Mass Assignment',
                                    'vulnerable':        True,
                                    'severity':          'MEDIUM',
                                    'endpoint':          path,
                                    'resource_id':       None,
                                    'owner':             'system',
                                    'unauthorized_user': attacker['name'],
                                    'evidence': {
                                        'status_code':      resp.status_code,
                                        'method':           method,
                                        'payload':          payload,
                                        'reflected_field':  key,
                                        'reflected_value':  sent_val,
                                        'body_preview':     str(body)[:300],
                                    },
                                    'description': (
                                        f'Server accepted privileged field "{key}" = {sent_val!r} '
                                        f'via {method} and reflected it in the immediate response. '
                                        'NOTE: This check confirms reflection only — persistence was not '
                                        'verified. Confirm manually that the value is actually stored. '
                                        'If confirmed persistent, this is a HIGH severity mass assignment '
                                        'vulnerability allowing privilege escalation.'
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

    @classmethod
    def _is_privileged_user(cls, user: dict) -> bool:
        """Recognize accounts that should not be used as unauthorized attackers."""
        if user.get('owns_all') or user.get('is_admin') or user.get('admin'):
            return True

        identities = [user.get('role'), user.get('user_type'), user.get('name')]
        identities.extend(user.get('roles') or [])
        return any(
            str(identity).strip().lower() in cls._PRIVILEGED_IDENTITIES
            for identity in identities
            if identity is not None
        )

    @classmethod
    def _is_authorized_user(cls, user: dict, owner: dict, resource_id) -> bool:
        """Return True for the owner, explicitly authorized, or privileged users."""
        if user is owner or cls._is_privileged_user(user):
            return True
        owned = user.get('resource_ids') or []
        return any(str(item) == str(resource_id) for item in owned)

    def _select_attacker(self, resource_id=None,
                         require_user_id: bool = False) -> dict | None:
        """Choose a non-privileged user who does not own the probed resource."""
        candidates = []
        for user in self.users:
            user_id = user.get('user_id')
            if self._is_privileged_user(user):
                continue
            if require_user_id and user_id is None:
                continue
            if resource_id is not None:
                owned = user.get('resource_ids') or []
                if str(user_id) == str(resource_id):
                    continue
                if any(str(item) == str(resource_id) for item in owned):
                    continue
            candidates.append(user)
        return candidates[-1] if candidates else None

    def _base_body(self, body_params: list) -> dict:
        payload: dict[str, object] = {}
        for param in body_params:
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
            self._set_nested(payload, param.get('path') or param['name'].split('.'), value)
        return payload

    @staticmethod
    def _set_nested(payload: dict, path: list, value):
        node = payload
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = value

    @staticmethod
    def _response_confirms_id(body, field_name: str, expected) -> bool:
        """Require the response to associate the submitted field with the victim ID."""
        leaf = field_name.split('.')[-1]
        stems = {
            leaf.lower(),
            re.sub(r'_?id$', '', leaf, flags=re.IGNORECASE).lower(),
        }

        def walk(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    key_lower = key.lower()
                    if any(stem and stem in key_lower for stem in stems):
                        if str(child) == str(expected):
                            return True
                    if walk(child):
                        return True
            elif isinstance(value, list):
                return any(walk(item) for item in value)
            return False

        return walk(body)

    def _build_url(self, path: str, resource_id, param_name: str | None = None) -> str:
        """Replace one target placeholder and resolve all others with safe defaults."""
        placeholders = re.findall(r'\{([^}]+)\}', path)
        target = param_name or (
            placeholders[0] if placeholders and resource_id is not None else None
        )
        param_defs = {param.get('name'): param for param in self._path_params}

        def replacement(match):
            name = match.group(1)
            if name == target:
                value = resource_id
            else:
                schema = (param_defs.get(name) or {}).get('schema') or {}
                value = schema.get('example', schema.get('default', 1))
            return _urlquote(str(value), safe='')

        resolved = re.sub(r'\{([^}]+)\}', replacement, path)
        return f'{self.base_url}{resolved}'

    def _strip_path_params(self, path: str) -> str:
        """Remove /{param} segments so the path can be used as a base URL for body/query checks.

        e.g. '/transactions/{id}' → '/transactions'
        """
        return re.sub(r'/\{[^}]+\}', '', path)

    def _request(self, method: str, url: str, user: dict | str,
                 **kwargs) -> requests.Response | None:
        """Send a single HTTP request with rate-limit (429) and transient-error (5xx) retry."""
        identity = user.get('name', id(user)) if isinstance(user, dict) else user
        auth_key = (identity, repr(self._auth_scheme))
        auth = self._auth_handlers.setdefault(
            auth_key, build_auth_handler(user, self._auth_scheme)
        )
        for attempt in range(3):
            try:
                if self.budget and not self.budget.consume():
                    return None
                request_kwargs = auth.apply(kwargs)
                resp = requests.request(
                    method, url, timeout=8,
                    verify=self.verify, proxies=self.proxies, **request_kwargs
                )
                if resp.status_code == 429:
                    # Exponential backoff: 1 s, 2 s, 4 s (capped at 3 attempts).
                    # Respects --delay if set; otherwise defaults to 1 s base wait.
                    wait = (2 ** attempt) * max(self.delay, 1.0)
                    if self.verbose:
                        print(f'      [BOLA] 429 rate-limited — retrying in {wait:.1f}s')
                    time.sleep(wait)
                    continue
                if resp.status_code >= 500:
                    # Transient server error — retry once before giving up.
                    wait = (2 ** attempt) * max(self.delay, 0.5)
                    if self.verbose:
                        print(f'      [BOLA] {resp.status_code} server error — retrying in {wait:.1f}s')
                    time.sleep(wait)
                    continue
                if self.delay > 0:
                    time.sleep(self.delay)
                return resp
            except requests.RequestException:
                return None
        return None   # all retries exhausted

    def _safe_json(self, resp: requests.Response | None):
        """Parse response as JSON; fall back to first 200 chars of text on failure."""
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

    @staticmethod
    def _id_values(body) -> list:
        """Return non-empty scalar values stored under ID-like keys at any depth."""
        values = []

        def walk(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if 'id' in str(key).lower() and not isinstance(child, (dict, list)):
                        if child is not None and child != '':
                            values.append(child)
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(body)
        return values

    @classmethod
    def _body_contains_id(cls, body, expected) -> bool:
        """Return True when an ID-like response field equals the expected value."""
        return any(str(value) == str(expected) for value in cls._id_values(body))

    def _bodies_similar(self, b1, b2) -> bool:
        """
        Fuzzy comparison: two bodies represent the *same resource instance*
        (not just the same resource type).

        Strategy:
          1. Both must be objects with at least 1 overlapping non-error scalar path.
          2. If any nested ID-like field (name contains 'id') has the same value in
             both responses, the attacker received the owner's resource → IDOR.
             Single matching ID field is sufficient — some resources are small
             (e.g. {"id": 1, "status": "ok"}) and requiring ≥2 matches would
             cause false negatives on those endpoints.
          3. If no explicit ID field exists, require ≥2 matching non-trivial
             values to avoid flagging resources that happen to share a common
             constant field (e.g. {"status": "ok"}).

        This prevents false positives on endpoints like /user/update where both
        users legitimately get 200 but each receives their own distinct record
        (different user_id, different name).  An actual IDOR would return the
        *owner's* resource_id in the attacker's response.
        """
        if not isinstance(b1, dict) or not isinstance(b2, dict):
            return False

        error_indicators = {'error', 'detail', 'message'}

        def flatten(value, path=()):
            scalars = {}
            if isinstance(value, dict):
                for key, child in value.items():
                    key_text = str(key)
                    if key_text.lower() in error_indicators:
                        continue
                    scalars.update(flatten(child, path + (key_text,)))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    scalars.update(flatten(child, path + (str(index),)))
            else:
                scalars[path] = value
            return scalars

        flat1 = flatten(b1)
        flat2 = flatten(b2)
        real_paths = set(flat1) & set(flat2)
        if not real_paths:
            return False

        # ID-like fields: single match is enough to confirm same resource.
        # Rationale: {"id": 1, "status": "ok"} — only one non-trivial match
        # is available, but "id" matching is high-confidence evidence of IDOR.
        id_paths = {path for path in real_paths if path and 'id' in path[-1].lower()}
        if id_paths:
            # Compare both raw value AND string-coerced value so APIs that
            # return IDs as strings ("id": "1") match correctly against
            # integer resource_ids (1).  Use explicit equality checks to
            # avoid accidental matches on None/""/false-y values.
            def _ids_equal(v1, v2) -> bool:
                # Exclude trivial/falsy sentinel values so None/None or ""/""
                # are never treated as evidence of a shared resource ID.
                if v1 is None or v2 is None or v1 == '' or v2 == '':
                    return False
                if v1 == v2:
                    return True
                # Cross-type string comparison: int 1 == str "1"
                try:
                    return str(v1) == str(v2)
                except Exception:
                    return False
            return any(_ids_equal(flat1[path], flat2[path]) for path in id_paths)

        # No explicit ID field — require ≥2 matching non-trivial values to
        # reduce false positives from resources with only a single shared field.
        # Use a tuple (not a set) so `not in` works for any value type including
        # lists and dicts — sets require hashable elements and would raise
        # TypeError when a response field contains a list.
        trivial = (None, '', True, False)
        matching = sum(
            1 for path in real_paths
            if flat1[path] == flat2[path] and flat1[path] not in trivial
        )
        return matching >= 2

    # Per-check human-readable descriptions used in the report
    _CHECK_DESCRIPTIONS = {
        'Simple IDOR': (
            'User "{attacker}" accessed resource ID {rid} without any ownership check. '
            'The server returned the full object to any authenticated user '
            'who guessed or enumerated the numeric ID.'
        ),
        'Body IDOR': (
            'User "{attacker}" injected another user\'s resource ID ({rid}) into a request '
            'body field and the server acted on it without verifying ownership. '
            'The attacker controlled which account or object was read or mutated.'
        ),
        'Parameter Pollution IDOR': (
            'Sending duplicate values for an ID-like query parameter caused '
            'the server to process the last (or first) value and return resource ID {rid} to '
            'user "{attacker}" without an ownership check.'
        ),
    }

    def _make_finding(self, check, path, resource_id, owner,
                      unauthorized_user, status, body_preview, severity) -> dict:
        template = self._CHECK_DESCRIPTIONS.get(check, '')
        description = template.format(
            attacker=unauthorized_user, rid=resource_id, owner=owner
        ) if template else ''

        return {
            'type':              'BOLA/IDOR',
            'method':            self._method,
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
            'description': description,
            'remediation': (
                'Enforce object-level authorization on every request. '
                'Verify that the authenticated user owns (or is explicitly permitted to access) '
                'the requested resource_id before returning data. '
                'Never rely solely on sequential IDs — use UUIDs and server-side ownership checks.'
            ),
        }
