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

    def test_uppercase_yaml_extension_is_parsed_as_yaml(self, tmp_path):
        f = tmp_path / 'OPENAPI.YAML'
        f.write_text(MINIMAL_SPEC, encoding='utf-8')

        parser = OpenAPIParser(str(f))

        assert parser.get_base_url() == 'http://localhost:5000'


class TestGetEndpoints:
    def test_endpoint_count(self, parser):
        endpoints = parser.get_endpoints()
        # /items/{id} GET, /fetch GET, /upload POST
        assert len(endpoints) == 3

    def test_endpoint_tuple_structure(self, parser):
        endpoints = parser.get_endpoints()
        for method, path, params, _security in endpoints:
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


class TestMalformedSpecs:
    """A malformed spec must degrade to a partial scan, never crash the run.

    YAML coerces unquoted scalars, so a hand-written spec can put a bool or int
    where the parser expects a string. Each case below crashed the whole scan
    before being guarded.
    """

    def _parse(self, tmp_path, body, name='spec.yaml'):
        spec = tmp_path / name
        spec.write_text(
            'openapi: "3.0.3"\ninfo: {title: T, version: "1"}\n' + textwrap.dedent(body),
            encoding='utf-8',
        )
        return OpenAPIParser(str(spec))

    def test_non_string_method_key_is_skipped(self, tmp_path):
        """`true:` under a path parses as a bool, which has no .lower()."""
        parser = self._parse(tmp_path, """
            paths:
              /x:
                true: {}
                get: {}
        """)
        methods = [m for m, _p, _params, _s in parser.get_endpoints()]
        assert methods == ['GET']

    def test_non_string_property_name_is_coerced(self, tmp_path):
        """An unquoted numeric body-property key breaks '.'.join()."""
        parser = self._parse(tmp_path, """
            paths:
              /x:
                post:
                  requestBody:
                    content:
                      application/json:
                        schema: {properties: {1: {type: string}}}
        """)
        params = parser.get_endpoints()[0][2]
        assert [p['name'] for p in params] == ['1']

    def test_non_string_server_url_falls_back(self, tmp_path):
        """A mapping where servers[0].url should be a string breaks re.sub()."""
        with pytest.warns(UserWarning, match=r'servers\[0\]\.url'):
            parser = self._parse(tmp_path, """
                servers: [{url: {a: b}}]
                paths: {}
            """)
        assert parser.get_base_url() == 'http://localhost:5000'

    def test_unreadable_spec_raises_value_error(self, tmp_path):
        """A path that exists but cannot be read must surface as ValueError.

        The CLI maps ValueError to exit 2 ("scan failed"); an escaping OSError
        would exit 1, which the CI gate reads as CRITICAL/HIGH findings.
        """
        unreadable = tmp_path / 'spec_dir'
        unreadable.mkdir()
        with pytest.raises(ValueError, match='Could not read spec file'):
            OpenAPIParser(str(unreadable))

    def test_non_utf8_spec_raises_value_error(self, tmp_path):
        spec = tmp_path / 'spec.yaml'
        spec.write_bytes(b'\xff\xfe\x00\x01openapi')
        with pytest.raises(ValueError, match='not valid UTF-8'):
            OpenAPIParser(str(spec))
