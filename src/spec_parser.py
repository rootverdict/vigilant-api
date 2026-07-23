"""
spec_parser.py
--------------
Parses OpenAPI 3.x YAML/JSON specs.
Extracts: endpoints, parameters, security schemes, base URL.

$ref support
------------
In-document JSON Pointer refs (#/components/...) are resolved automatically
before parameter extraction.  External file refs (./other.yaml) and HTTP refs
are not supported and are silently skipped — log a warning in that case.
"""

import yaml
import json
import os
import re
import warnings


class OpenAPIParser:
    def __init__(self, spec_file: str):
        self.spec_file = os.path.abspath(spec_file)
        self.spec_dir = os.path.dirname(self.spec_file)
        self._document_cache: dict[str, dict] = {}
        self._origins: dict[int, tuple[dict, str]] = {}
        try:
            with open(spec_file, encoding='utf-8') as f:
                if spec_file.lower().endswith(('.yaml', '.yml')):
                    self.spec = yaml.safe_load(f)
                else:
                    self.spec = json.load(f)
        except yaml.YAMLError as e:
            raise ValueError(f'[ERROR] Failed to parse YAML spec file "{spec_file}": {e}')
        except json.JSONDecodeError as e:
            raise ValueError(f'[ERROR] Failed to parse JSON spec file "{spec_file}": {e}')

        if not isinstance(self.spec, dict):
            raise ValueError(f'[ERROR] Spec file "{spec_file}" is empty or not a valid OpenAPI document.')

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

            path_params   = path_item.get('parameters') or []
            path_security = path_item.get('security')   or []

            for method, details in path_item.items():
                if method.lower() not in ('get', 'post', 'put', 'delete', 'patch',
                                           'head', 'options', 'trace'):
                    continue
                params   = self._extract_params(path_params, details)
                params  += self._extract_body_params(details)
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
            server = servers[0] or {}
            url = server.get('url', 'http://localhost:5000')
            variables = server.get('variables') or {}

            def replace_variable(match):
                name = match.group(1)
                definition = variables.get(name) or {}
                if 'default' not in definition:
                    warnings.warn(
                        f'OpenAPI server variable "{name}" has no default; leaving it unchanged.',
                        stacklevel=2,
                    )
                    return match.group(0)
                return str(definition['default'])

            return re.sub(r'\{([^}]+)\}', replace_variable, url).rstrip('/')
        return 'http://localhost:5000'

    def _resolve_ref(self, obj: dict, document: dict = None,
                     base_dir: str = None, seen: set = None) -> dict:
        """Resolve local and local-file JSON References without network I/O."""
        ref = obj.get('$ref', '') if isinstance(obj, dict) else ''
        if not ref:
            return obj

        origin = self._origins.get(id(obj))
        document = document or (origin[0] if origin else self.spec)
        base_dir = base_dir or (origin[1] if origin else self.spec_dir)
        seen = set(seen or ())
        ref_key = (base_dir, ref)
        if ref_key in seen:
            warnings.warn(f'Circular OpenAPI reference skipped: {ref}', stacklevel=2)
            return obj
        seen.add(ref_key)

        if ref.startswith(('http://', 'https://')):
            warnings.warn(
                f'Remote OpenAPI reference is not fetched automatically: {ref}',
                stacklevel=2,
            )
            return obj

        target_document = document
        target_base_dir = base_dir
        fragment = ref
        if not ref.startswith('#/'):
            file_part, separator, fragment_part = ref.partition('#')
            ref_path = os.path.abspath(os.path.join(base_dir, file_part))
            try:
                if ref_path not in self._document_cache:
                    with open(ref_path, encoding='utf-8') as handle:
                        if ref_path.lower().endswith(('.yaml', '.yml')):
                            loaded = yaml.safe_load(handle)
                        else:
                            loaded = json.load(handle)
                    if not isinstance(loaded, dict):
                        raise ValueError('referenced document is not an object')
                    self._document_cache[ref_path] = loaded
                target_document = self._document_cache[ref_path]
                target_base_dir = os.path.dirname(ref_path)
                fragment = f'#{fragment_part}' if separator else ''
            except (OSError, ValueError, yaml.YAMLError, json.JSONDecodeError) as exc:
                warnings.warn(f'Unable to resolve OpenAPI reference {ref}: {exc}', stacklevel=2)
                return obj

        if fragment in ('', '#'):
            node = target_document
        elif fragment.startswith('#/'):
            node = target_document
            for raw_part in fragment[2:].split('/'):
                part = raw_part.replace('~1', '/').replace('~0', '~')
                if not isinstance(node, dict) or part not in node:
                    warnings.warn(f'Unresolvable OpenAPI reference skipped: {ref}', stacklevel=2)
                    return obj
                node = node[part]
        else:
            warnings.warn(f'Unsupported OpenAPI reference fragment skipped: {ref}', stacklevel=2)
            return obj

        if not isinstance(node, dict):
            return obj
        if '$ref' in node:
            return self._resolve_ref(node, target_document, target_base_dir, seen)
        self._register_origin(node, target_document, target_base_dir)
        return node

    def _register_origin(self, value, document: dict, base_dir: str):
        if isinstance(value, dict):
            self._origins[id(value)] = (document, base_dir)
            for child in value.values():
                self._register_origin(child, document, base_dir)
        elif isinstance(value, list):
            for child in value:
                self._register_origin(child, document, base_dir)

    def _extract_params(self, path_params: list, details: dict) -> list:
        params = []
        seen = set()

        # `or []` guards against `parameters: null` in the YAML spec — without
        # it, `list(None)` raises TypeError and aborts the entire scan.
        for raw_param in list(path_params or []) + list(details.get('parameters') or []):
            # Resolve $ref before accessing fields — handles specs that define
            # reusable parameters under #/components/parameters/.
            param = self._resolve_ref(raw_param)

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
                'schema':   self._resolve_ref(param.get('schema') or {}),
            })

        return params

    def _extract_body_params(self, details: dict) -> list:
        """Flatten OpenAPI 3 request-body properties into injectable params."""
        request_body = self._resolve_ref(details.get('requestBody') or {})
        content = request_body.get('content') or {}
        media_type = next(
            (item for item in content if item == 'application/json' or item.endswith('+json')),
            None,
        )
        preferred_types = ('application/x-www-form-urlencoded', 'multipart/form-data')
        if media_type is None:
            media_type = next((item for item in preferred_types if item in content), None)
        if media_type is None:
            media_type = next(iter(content), None)
        if not media_type:
            return []

        schema = self._resolve_ref((content.get(media_type) or {}).get('schema') or {})
        location = (
            'form' if media_type in ('application/x-www-form-urlencoded', 'multipart/form-data')
            else 'body'
        )
        params = []

        def walk(current_schema: dict, prefix: list, inherited_required: bool = False):
            current_schema = self._resolve_ref(current_schema or {})
            properties = dict(current_schema.get('properties') or {})
            required_names = set(current_schema.get('required') or [])
            for branch in current_schema.get('allOf') or []:
                resolved_branch = self._resolve_ref(branch)
                properties.update(resolved_branch.get('properties') or {})
                required_names.update(resolved_branch.get('required') or [])

            for name, raw_child in properties.items():
                child = self._resolve_ref(raw_child or {})
                path = prefix + [name]
                required = inherited_required or name in required_names
                if child.get('properties') or child.get('allOf'):
                    walk(child, path, required)
                    continue
                params.append({
                    'name': '.'.join(path),
                    'path': path,
                    'in': location,
                    'required': required,
                    'schema': child,
                    'media_type': media_type,
                })

        walk(schema, [])
        return params

    def _extract_security(self, path_security: list,
                          details: dict) -> list | None:
        if 'security' in details:
            return details.get('security', [])
        if path_security:
            return path_security
        if 'security' in self.spec:
            return self.spec.get('security', [])
        return None
