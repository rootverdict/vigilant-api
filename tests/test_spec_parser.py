"""
tests/test_spec_parser.py
--------------------------
Unit tests for OpenAPIParser — spec loading, base URL extraction,
endpoint enumeration, and URL-param classification.
"""

import os
import sys
import tempfile
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
        """External refs (not starting with #/) are not supported — returned as-is."""
        obj = {'$ref': './other.yaml#/components/parameters/Foo'}
        assert parser._resolve_ref(obj) is obj

    def test_unresolvable_local_ref_returns_original(self, parser):
        obj = {'$ref': '#/components/parameters/DoesNotExist'}
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
