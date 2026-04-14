"""
spec_parser.py
--------------
Parses OpenAPI 3.x YAML/JSON specs.
Extracts: endpoints, parameters, security schemes, base URL.
"""

import yaml
import json


class OpenAPIParser:
    def __init__(self, spec_file: str):
        with open(spec_file, encoding='utf-8') as f:
            if spec_file.endswith(('.yaml', '.yml')):
                self.spec = yaml.safe_load(f)
            else:
                self.spec = json.load(f)

        self.base_url = self._extract_base_url()

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def get_endpoints(self) -> list:
        """
        Returns list of tuples:
            (method, path, params, security)
        e.g. ('GET', '/transactions/{id}', [...], [...])
        """
        endpoints = []
        paths = self.spec.get('paths', {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            path_params = path_item.get('parameters', [])
            path_security = path_item.get('security', [])

            for method, details in path_item.items():
                if method.lower() not in ('get', 'post', 'put', 'delete', 'patch'):
                    continue
                params   = self._extract_params(path_params, details)
                security = self._extract_security(path_security, details)
                endpoints.append((method.upper(), path, params, security))

        return endpoints

    def get_security_schemes(self) -> dict:
        """
        Returns the securitySchemes block, e.g.:
            {'BearerAuth': {'type': 'http', 'scheme': 'bearer'}}
        """
        return self.spec.get('components', {}).get('securitySchemes', {})

    def get_base_url(self) -> str:
        return self.base_url

    def get_id_params(self, params: list) -> list:
        """
        Filter path-params that look like resource IDs.
        Used by the BOLA detector to know which params to fuzz.
        """
        return [p for p in params if p['in'] == 'path' and 'id' in p['name'].lower()]

    def get_url_params(self, params: list) -> list:
        """Return query/path params that accept a URL value (for SSRF probing).

        Uses substring matching so params like 'callback_url', 'redirect_uri',
        'target_url', 'webhook_url' are all caught — not just exact names.
        """
        url_keywords = ('url', 'uri', 'endpoint', 'redirect', 'callback',
                        'next', 'src', 'dest', 'target', 'webhook', 'proxy', 'host')
        return [
            p for p in params
            if any(kw in p['name'].lower() for kw in url_keywords)
        ]

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _extract_base_url(self) -> str:
        servers = self.spec.get('servers', [])
        if servers:
            return servers[0].get('url', 'http://localhost:5000').rstrip('/')
        return 'http://localhost:5000'

    def _extract_params(self, path_params: list, details: dict) -> list:
        params = []
        seen = set()

        for param in list(path_params or []) + list(details.get('parameters', [])):
            name = param.get('name')
            location = param.get('in')
            if not name or not location:
                continue

            key = (name, location)
            if key in seen:
                continue
            seen.add(key)

            params.append({
                'name':     name,
                'in':       location,   # path | query | header | cookie
                'required': param.get('required', False),
            })

        return params

    def _extract_security(self, path_security: list, details: dict) -> list:
        if 'security' in details:
            return details.get('security', [])
        if path_security:
            return path_security
        return self.spec.get('security', [])
