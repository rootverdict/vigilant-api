import os
import sys
import textwrap
from unittest.mock import patch

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
