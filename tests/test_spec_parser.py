"""
tests/test_spec_parser.py
--------------------------
Unit tests for OpenAPIParser — spec loading, base URL extraction,
endpoint enumeration, and URL-param classification.
"""

import os
import sys
import textwrap
import pytest

# Allow importing from src/ without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from spec_parser import OpenAPIParser


# ── Fixtures ──────────────────────────────────────────────────────────────────

MINIMAL_SPEC = textwrap.dedent("""\
    openapi: "3.0.3"
    info:
      title: Test
      version: "1.0"
    servers:
      - url: http://localhost:5000
    paths:
      /items/{id}:
        get:
          summary: Get item
          parameters:
            - name: id
              in: path
              required: true
              schema:
                type: integer
          security:
            - BearerAuth: []
      /fetch:
        get:
          summary: SSRF endpoint
          parameters:
            - name: url
              in: query
              required: true
              schema:
                type: string
      /upload:
        post:
          summary: Upload with no security
          requestBody:
            required: true
            content:
              application/json:
                schema:
                  type: object
    components:
      securitySchemes:
        BearerAuth:
          type: http
          scheme: bearer
""")


@pytest.fixture
def spec_file(tmp_path):
    """Write the minimal spec to a temp file and return its path."""
    p = tmp_path / 'test_spec.yaml'
    p.write_text(MINIMAL_SPEC, encoding='utf-8')
    return str(p)


@pytest.fixture
def parser(spec_file):
    return OpenAPIParser(spec_file)


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestGetBaseUrl:
    def test_returns_server_url(self, parser):
        assert parser.get_base_url() == 'http://localhost:5000'

    def test_missing_servers_falls_back_to_localhost(self, tmp_path):
        # When 'servers' key is absent, the parser gracefully defaults to
        # http://localhost:5000 rather than raising — matches actual behaviour.
        spec = textwrap.dedent("""\
            openapi: "3.0.3"
            info:
              title: T
              version: "1"
            paths: {}
        """)
        f = tmp_path / 'noserver.yaml'
        f.write_text(spec, encoding='utf-8')
        base_url = OpenAPIParser(str(f)).get_base_url()
        assert base_url == 'http://localhost:5000'


class TestGetEndpoints:
    def test_endpoint_count(self, parser):
        endpoints = parser.get_endpoints()
        # /items/{id} GET, /fetch GET, /upload POST
        assert len(endpoints) == 3

    def test_endpoint_tuple_structure(self, parser):
        endpoints = parser.get_endpoints()
        for method, path, params, security in endpoints:
            assert isinstance(method, str)
            assert method.isupper()
            assert path.startswith('/')
            assert isinstance(params, list)

    def test_path_param_parsed(self, parser):
        endpoints = parser.get_endpoints()
        item_ep = next(
            (ep for ep in endpoints if '/items' in ep[1] and ep[0] == 'GET'), None
        )
        assert item_ep is not None
        params = item_ep[2]
        assert any(p['name'] == 'id' and p['in'] == 'path' for p in params)

    def test_query_param_parsed(self, parser):
        endpoints = parser.get_endpoints()
        fetch_ep = next(
            (ep for ep in endpoints if '/fetch' in ep[1]), None
        )
        assert fetch_ep is not None
        params = fetch_ep[2]
        assert any(p['name'] == 'url' and p['in'] == 'query' for p in params)

    def test_request_body_properties_are_flattened(self, tmp_path):
        spec = textwrap.dedent("""\
            openapi: "3.0.3"
            info: {title: T, version: "1"}
            paths:
              /callbacks:
                post:
                  requestBody:
                    content:
                      application/json:
                        schema:
                          type: object
                          properties:
                            delivery:
                              type: object
                              properties:
                                callback_url: {type: string}
        """)
        f = tmp_path / 'body.yaml'
        f.write_text(spec, encoding='utf-8')
        params = OpenAPIParser(str(f)).get_endpoints()[0][2]
        callback = next(p for p in params if p['name'] == 'delivery.callback_url')
        assert callback['in'] == 'body'
        assert callback['path'] == ['delivery', 'callback_url']

    def test_server_variables_use_defaults(self, tmp_path):
        spec = textwrap.dedent("""\
            openapi: "3.0.3"
            info: {title: T, version: "1"}
            servers:
              - url: https://{region}.api.example.com/{version}
                variables:
                  region: {default: eu}
                  version: {default: v2}
            paths: {}
        """)
        f = tmp_path / 'variables.yaml'
        f.write_text(spec, encoding='utf-8')
        assert OpenAPIParser(str(f)).get_base_url() == 'https://eu.api.example.com/v2'

    def test_explicit_public_security_differs_from_unspecified(self, tmp_path):
        spec = textwrap.dedent("""\
            openapi: "3.0.3"
            info: {title: T, version: "1"}
            paths:
              /public:
                get:
                  security: []
              /unspecified:
                get: {}
        """)
        f = tmp_path / 'security.yaml'
        f.write_text(spec, encoding='utf-8')
        endpoints = OpenAPIParser(str(f)).get_endpoints()
        public = next(ep for ep in endpoints if ep[1] == '/public')
        unspecified = next(ep for ep in endpoints if ep[1] == '/unspecified')
        assert public[3] == []
        assert unspecified[3] is None


class TestGetUrlParams:
    def test_url_param_detected(self, parser):
        params = [{'name': 'url', 'in': 'query', 'schema': {'type': 'string'}}]
        url_params = parser.get_url_params(params)
        assert len(url_params) == 1
        assert url_params[0]['name'] == 'url'

    def test_non_url_param_excluded(self, parser):
        params = [{'name': 'user_id', 'in': 'path', 'schema': {'type': 'integer'}}]
        url_params = parser.get_url_params(params)
        assert url_params == []

    def test_all_url_keywords_detected(self, parser):
        keywords = ['url', 'uri', 'redirect', 'callback', 'webhook', 'target', 'host', 'proxy']
        for kw in keywords:
            params = [{'name': kw, 'in': 'query', 'schema': {'type': 'string'}}]
            result = parser.get_url_params(params)
            assert len(result) == 1, f'Keyword "{kw}" not detected as URL param'

    def test_header_url_param_detected(self, parser):
        params = [{'name': 'X-Target-URL', 'in': 'header', 'schema': {'type': 'string'}}]
        url_params = parser.get_url_params(params)
        assert len(url_params) == 1
        assert url_params[0]['in'] == 'header'


class TestResolveRef:

    def test_local_ref_resolved(self, parser):
        """$ref pointing into components/parameters must be resolved."""
        # Inject a fake component into the parser's in-memory spec
        parser.spec.setdefault('components', {}).setdefault('parameters', {})
        parser.spec['components']['parameters']['UserId'] = {
            'name': 'user_id', 'in': 'path', 'required': True,
        }
        obj = {'$ref': '#/components/parameters/UserId'}
        resolved = parser._resolve_ref(obj)
        assert resolved['name'] == 'user_id'
        assert resolved['in'] == 'path'

    def test_non_ref_object_unchanged(self, parser):
        obj = {'name': 'id', 'in': 'path'}
        assert parser._resolve_ref(obj) is obj

    def test_external_ref_returned_unchanged(self, parser):
        """A missing external file is warned about and returned unchanged."""
        obj = {'$ref': './other.yaml#/components/parameters/Foo'}
        with pytest.warns(UserWarning, match='Unable to resolve'):
            assert parser._resolve_ref(obj) is obj

    def test_unresolvable_local_ref_returns_original(self, parser):
        obj = {'$ref': '#/components/parameters/DoesNotExist'}
        with pytest.warns(UserWarning, match='Unresolvable'):
            assert parser._resolve_ref(obj) is obj

    def test_spec_with_ref_param_parsed(self, tmp_path):
        """End-to-end: spec using $ref for a parameter must produce the correct param."""
        spec = textwrap.dedent("""\
            openapi: "3.0.3"
            info:
              title: Ref Test
              version: "1"
            servers:
              - url: http://localhost:5000
            components:
              parameters:
                TxnId:
                  name: id
                  in: path
                  required: true
                  schema:
                    type: integer
            paths:
              /transactions/{id}:
                get:
                  summary: Get txn
                  parameters:
                    - $ref: '#/components/parameters/TxnId'
        """)
        f = tmp_path / 'ref_spec.yaml'
        f.write_text(spec, encoding='utf-8')
        p = OpenAPIParser(str(f))
        endpoints = p.get_endpoints()
        assert len(endpoints) == 1
        params = endpoints[0][2]
        assert any(pr['name'] == 'id' and pr['in'] == 'path' for pr in params)

    def test_external_file_schema_ref_is_resolved(self, tmp_path):
        schemas = tmp_path / 'schemas.yaml'
        schemas.write_text(textwrap.dedent("""\
            components:
              schemas:
                Callback:
                  type: object
                  properties:
                    webhook_url: {type: string}
        """), encoding='utf-8')
        spec = tmp_path / 'openapi.yaml'
        spec.write_text(textwrap.dedent("""\
            openapi: "3.0.3"
            info: {title: T, version: "1"}
            paths:
              /hooks:
                post:
                  requestBody:
                    content:
                      application/json:
                        schema:
                          $ref: './schemas.yaml#/components/schemas/Callback'
        """), encoding='utf-8')
        params = OpenAPIParser(str(spec)).get_endpoints()[0][2]
        assert any(p['name'] == 'webhook_url' and p['in'] == 'body' for p in params)
