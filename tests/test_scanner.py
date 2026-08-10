import os
import sys
import textwrap
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scanner import Scanner


def _config(spec_file, output_dir, users, skip=None):
    return {
        'spec_file': str(spec_file),
        'users': users,
        'resource_ids': [1],
        'output_dir': str(output_dir),
        'skip': list(skip or []),
        'callback_url': None,
        'oauth_config': None,
        'delay': 0.0,
        'insecure': False,
        'proxy': None,
        'verbose': False,
        'active': False,
        'max_requests': 100,
    }


def test_unspecified_security_is_public_and_does_not_require_two_users(tmp_path):
    spec = tmp_path / 'public.yaml'
    spec.write_text(
        textwrap.dedent(
            """\
            openapi: "3.0.3"
            info: {title: Public API, version: "1"}
            servers:
              - url: https://api.example.test
            paths:
              /objects/{id}:
                get:
                  parameters:
                    - name: id
                      in: path
                      required: true
                      schema: {type: integer}
            """
        ),
        encoding='utf-8',
    )
    scanner = Scanner(
        _config(
            spec,
            tmp_path / 'reports',
            [{'name': 'alice', 'token': 'opaque-token', 'user_id': 1}],
            skip=['ssrf', 'oauth', 'jwt'],
        )
    )

    with patch('bola_detector.BOLADetector.test_endpoint') as test_endpoint:
        scanner.run()

    test_endpoint.assert_not_called()


def test_protected_bola_endpoint_fails_during_construction_without_requests(tmp_path):
    spec = tmp_path / 'mixed.yaml'
    spec.write_text(
        textwrap.dedent(
            """\
            openapi: "3.0.3"
            info: {title: Mixed API, version: "1"}
            servers:
              - url: https://api.example.test
            paths:
              /fetch:
                get:
                  security: []
                  parameters:
                    - name: url
                      in: query
                      schema: {type: string}
              /objects/{id}:
                get:
                  security:
                    - BearerAuth: []
                  parameters:
                    - name: id
                      in: path
                      required: true
                      schema: {type: integer}
            components:
              securitySchemes:
                BearerAuth:
                  type: http
                  scheme: bearer
            """
        ),
        encoding='utf-8',
    )
    reports = tmp_path / 'reports'

    with patch('requests.request') as request, \
            pytest.raises(ValueError, match='At least 2 users required'):
        Scanner(
            _config(
                spec,
                reports,
                [{'name': 'alice', 'token': 'opaque-token', 'user_id': 1}],
                skip=['oauth', 'jwt'],
            )
        )

    request.assert_not_called()
    assert not reports.exists()


def test_oauth_access_token_is_included_in_jwt_inspection(tmp_path):
    spec = tmp_path / 'empty.yaml'
    spec.write_text(
        textwrap.dedent(
            """\
            openapi: "3.0.3"
            info: {title: Empty API, version: "1"}
            paths: {}
            """
        ),
        encoding='utf-8',
    )
    scanner = Scanner(
        _config(
            spec,
            tmp_path / 'reports',
            [{
                'name': 'oauth-user',
                'scheme': 'oauth2',
                'access_token': 'oauth-jwt',
                'client_id': 'client',
            }],
            skip=['bola', 'ssrf', 'oauth'],
        )
    )

    with patch('scanner.AuthHandler.check_jwt_algorithm', return_value=None) as check:
        scanner.run()

    check.assert_called_once_with('oauth-jwt')


_MINIMAL_SPEC = """\
openapi: "3.0.3"
info: {title: T, version: "1"}
servers: [{url: "http://127.0.0.1:1"}]
paths: {}
"""


def _spec(tmp_path, text=_MINIMAL_SPEC, name='s.yaml'):
    p = tmp_path / name
    p.write_text(text, encoding='utf-8')
    return p


def _users(n=2):
    return [{'name': f'u{i}', 'token': f't{i}', 'user_id': i} for i in range(1, n + 1)]


class TestUserValidation:

    def test_empty_user_list_is_rejected(self, tmp_path):
        cfg = _config(_spec(tmp_path), tmp_path / 'r', [])
        with pytest.raises(ValueError, match='At least 1 user token'):
            Scanner(cfg)

    def test_single_user_is_allowed_when_no_bola_surface(self, tmp_path):
        """The two-user rule only applies where a protected BOLA surface exists."""
        cfg = _config(_spec(tmp_path), tmp_path / 'r', _users(1), skip=['oauth', 'jwt'])
        assert Scanner(cfg).bola is None


class TestOAuthConfigValidation:
    """--oauth-config is user-supplied JSON, so its shape is validated before the
    detector is constructed; a bad key would otherwise surface as a TypeError."""

    def _cfg(self, tmp_path, oauth_config):
        cfg = _config(_spec(tmp_path), tmp_path / 'r', _users(), skip=['jwt'])
        cfg['oauth_config'] = oauth_config
        return cfg

    def test_non_object_config_is_rejected(self, tmp_path):
        with pytest.raises(ValueError, match='must be a JSON object'):
            Scanner(self._cfg(tmp_path, ['not', 'an', 'object']))

    def test_missing_required_keys_are_named(self, tmp_path):
        with pytest.raises(ValueError, match='missing required keys'):
            Scanner(self._cfg(tmp_path, {'auth_url': 'http://a'}))

    def test_error_lists_every_missing_key(self, tmp_path):
        with pytest.raises(ValueError) as excinfo:
            Scanner(self._cfg(tmp_path, {}))
        message = str(excinfo.value)
        assert 'auth_url' in message and 'token_url' in message and 'client_id' in message

    def test_complete_config_builds_the_detector(self, tmp_path):
        scanner = Scanner(self._cfg(tmp_path, {
            'auth_url': 'http://a', 'token_url': 'http://t', 'client_id': 'c',
        }))
        assert scanner.oauth is not None

    def test_unknown_keys_are_filtered_out(self, tmp_path):
        """Comment/description keys in the JSON must not reach the constructor."""
        scanner = Scanner(self._cfg(tmp_path, {
            'auth_url': 'http://a', 'token_url': 'http://t', 'client_id': 'c',
            '_comment': 'ignore me', 'unexpected': 1,
        }))
        assert scanner.oauth.client_id == 'c'

    def test_rejected_config_creates_no_output_directory(self, tmp_path):
        """The shape check runs before ForensicLogger, which calls os.makedirs on
        construction. Validating after it left an empty reports/ behind on a run
        that never started."""
        reports = tmp_path / 'r'
        with pytest.raises(ValueError, match='missing required keys'):
            Scanner(self._cfg(tmp_path, {'auth_url': 'http://a'}))
        assert not reports.exists()

    def test_user_validation_is_reported_before_oauth_validation(self, tmp_path):
        """Both configs are invalid; the user-count error must still win, so the
        reordering above did not change which message the operator sees."""
        cfg = _config(_spec(tmp_path), tmp_path / 'r', [], skip=['jwt'])
        cfg['oauth_config'] = {'auth_url': 'http://a'}
        with pytest.raises(ValueError, match='user token is required'):
            Scanner(cfg)

    def test_absent_config_leaves_detector_unset(self, tmp_path):
        cfg = _config(_spec(tmp_path), tmp_path / 'r', _users(), skip=['jwt'])
        assert Scanner(cfg).oauth is None


class TestJwtInspectionDispatch:
    """JWT header inspection runs independently of the OAuth server probes, but
    only for schemes that actually carry a bearer-style token."""

    def _scanner(self, tmp_path, users, skip=None):
        return Scanner(_config(_spec(tmp_path), tmp_path / 'r', users,
                               skip=skip or ['oauth']))

    def test_api_key_identity_is_not_jwt_inspected(self, tmp_path):
        users = _users() + [{'name': 'svc', 'scheme': 'apiKey', 'key': 'k', 'user_id': 9}]
        result = self._scanner(tmp_path, users).run()
        assert result['findings'] == []

    def test_alg_none_token_is_reported(self, tmp_path):
        import base64 as _b64
        import json as _json

        def seg(d):
            return _b64.urlsafe_b64encode(
                _json.dumps(d).encode()).rstrip(b'=').decode()

        token = f'{seg({"alg": "none", "typ": "JWT"})}.{seg({"sub": "a"})}.'
        users = [{'name': 'a', 'token': token, 'user_id': 1},
                 {'name': 'b', 'token': token, 'user_id': 2}]
        result = self._scanner(tmp_path, users).run()

        checks = [f['vulnerability']['check'] for f in result['findings']]
        assert any('none' in c.lower() for c in checks)
        assert result['summary']['CRITICAL'] >= 1

    def test_skip_jwt_suppresses_inspection(self, tmp_path):
        import base64 as _b64
        import json as _json

        def seg(d):
            return _b64.urlsafe_b64encode(
                _json.dumps(d).encode()).rstrip(b'=').decode()

        token = f'{seg({"alg": "none", "typ": "JWT"})}.{seg({"sub": "a"})}.'
        users = [{'name': 'a', 'token': token, 'user_id': 1},
                 {'name': 'b', 'token': token, 'user_id': 2}]
        scanner = self._scanner(tmp_path, users, skip=['oauth', 'jwt'])
        assert scanner.run()['findings'] == []


class TestSecurityOptionResolution:
    """_get_auth_options preserves OpenAPI's OR-across-objects, AND-within-object
    structure, and drops requirements naming schemes the spec never defines."""

    def _scanner(self, tmp_path, spec_text):
        return Scanner(_config(_spec(tmp_path, spec_text), tmp_path / 'r',
                               _users(), skip=['oauth', 'jwt']))

    SPEC = """\
openapi: "3.0.3"
info: {title: T, version: "1"}
servers: [{url: "http://127.0.0.1:1"}]
paths: {}
components:
  securitySchemes:
    BearerAuth: {type: http, scheme: bearer}
    ApiKeyAuth: {type: apiKey, in: header, name: X-API-Key}
"""

    def test_absent_security_returns_none(self, tmp_path):
        assert self._scanner(tmp_path, self.SPEC)._get_auth_options(None) is None

    def test_and_within_one_object_is_preserved(self, tmp_path):
        options = self._scanner(tmp_path, self.SPEC)._get_auth_options(
            [{'BearerAuth': [], 'ApiKeyAuth': []}])
        assert len(options) == 1 and len(options[0]) == 2

    def test_or_across_objects_is_preserved(self, tmp_path):
        options = self._scanner(tmp_path, self.SPEC)._get_auth_options(
            [{'BearerAuth': []}, {'ApiKeyAuth': []}])
        assert len(options) == 2

    def test_scheme_name_is_attached_for_lookup(self, tmp_path):
        options = self._scanner(tmp_path, self.SPEC)._get_auth_options([{'BearerAuth': []}])
        assert options[0][0]['_name'] == 'BearerAuth'

    def test_requirement_naming_an_undefined_scheme_is_dropped(self, tmp_path):
        assert self._scanner(tmp_path, self.SPEC)._get_auth_options(
            [{'Nonexistent': []}]) is None

    def test_partially_resolvable_requirement_is_dropped(self, tmp_path):
        """All schemes in an AND group must resolve or the group is unusable."""
        options = self._scanner(tmp_path, self.SPEC)._get_auth_options(
            [{'BearerAuth': [], 'Nonexistent': []}, {'ApiKeyAuth': []}])
        assert len(options) == 1 and options[0][0]['_name'] == 'ApiKeyAuth'

    def test_non_object_requirement_is_ignored(self, tmp_path):
        assert self._scanner(tmp_path, self.SPEC)._get_auth_options(
            ['nonsense', {'BearerAuth': []}]) is not None


class TestFindingDeduplication:
    """A path with several write methods triggers the same body-level check once
    per method; identical findings must be logged once."""

    def test_identical_findings_are_logged_once(self, tmp_path):
        scanner = Scanner(_config(_spec(tmp_path), tmp_path / 'r', _users(),
                                  skip=['oauth', 'jwt']))
        finding = {
            'type': 'BOLA/IDOR', 'check': 'Mass Assignment', 'severity': 'MEDIUM',
            'endpoint': '/user/update', 'method': 'POST', 'resource_id': 1,
            'unauthorized_user': 'u2', 'evidence': {},
        }
        first = scanner.logger.log_finding(dict(finding))
        assert first is not None
        before = len(scanner.logger.findings)
        scanner.logger.log_finding(dict(finding))
        assert len(scanner.logger.findings) == before + 1


class TestReportGeneration:

    def test_run_writes_both_reports_and_metadata(self, tmp_path):
        reports = tmp_path / 'r'
        scanner = Scanner(_config(_spec(tmp_path), reports, _users(),
                                  skip=['oauth', 'jwt']))
        result = scanner.run()

        assert os.path.exists(result['json_report'])
        assert os.path.exists(result['html_report'])
        assert result['summary'] == {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0,
                                     'LOW': 0, 'INFO': 0}

    def test_budget_metadata_is_recorded(self, tmp_path):
        import json as _json
        from pathlib import Path
        scanner = Scanner(_config(_spec(tmp_path), tmp_path / 'r', _users(),
                                  skip=['oauth', 'jwt']))
        result = scanner.run()
        meta = _json.loads(
            Path(result['json_report']).read_text(encoding='utf-8'))['scan_meta']

        assert meta['request_budget'] == 100
        assert meta['budget_exhausted'] is False
        assert meta['endpoints_tested'] == 0
