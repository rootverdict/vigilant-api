import os
import sys
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cli import _validate_oauth_config, _validate_user_entry, main


def test_oauth_client_credentials_are_accepted_without_existing_token():
    user = {
        'name': 'service',
        'scheme': 'oauth2',
        'client_id': 'client',
        'client_secret': 'secret',
    }
    assert _validate_user_entry(user, 0) is None


def test_oauth_password_credentials_are_accepted_without_existing_token():
    user = {
        'name': 'alice',
        'scheme': 'oauth2',
        'client_id': 'client',
        'username': 'alice',
        'password': 'secret',
    }
    assert _validate_user_entry(user, 0) is None


def test_incomplete_oauth_credentials_are_rejected():
    error = _validate_user_entry({'name': 'alice', 'scheme': 'oauth2'}, 2)
    assert error and 'incomplete OAuth credentials' in error


def test_named_api_key_mapping_is_accepted():
    user = {
        'name': 'service',
        'scheme': 'apiKey',
        'api_keys': {'X-API-Key': 'secret', 'tenant_key': 'tenant-secret'},
    }
    assert _validate_user_entry(user, 0) is None


def test_oauth_config_must_be_an_object():
    assert _validate_oauth_config([]) == 'OAuth config file must contain a JSON object.'
    assert _validate_oauth_config('not-an-object') is not None
    assert _validate_oauth_config({}) is None


def test_scanner_configuration_error_exits_with_runtime_failure_code(tmp_path):
    tokens = tmp_path / 'one_user.json'
    tokens.write_text(
        '[{"name": "alice", "token": "opaque-token", "user_id": 1}]',
        encoding='utf-8',
    )

    result = CliRunner().invoke(
        main,
        [
            '--spec',
            'sample_specs/fintech.yaml',
            '--tokens',
            str(tokens),
        ],
    )

    assert result.exit_code == 2
    assert 'At least 2 users required for differential BOLA testing' in result.output


def test_pre_scan_validation_error_exits_with_runtime_failure_code():
    result = CliRunner().invoke(
        main,
        [
            '--spec',
            'missing-spec.yaml',
            '--tokens',
            'missing-tokens.json',
        ],
    )

    assert result.exit_code == 2
    assert 'Spec file not found' in result.output


def test_unexpected_scan_error_fails_safe_with_code_2(tmp_path):
    """An unexpected error during the scan must exit 2 (scan failed), not leak an
    uncaught traceback — Python would exit with code 1, the signal the CI gate
    reserves for CRITICAL/HIGH findings."""
    tokens = tmp_path / 'two_users.json'
    tokens.write_text(
        '[{"name": "alice", "token": "t1", "user_id": 1},'
        ' {"name": "bob", "token": "t2", "user_id": 2}]',
        encoding='utf-8',
    )

    with patch('cli.Scanner') as scanner_cls:
        scanner_cls.return_value.run.side_effect = RuntimeError('boom')
        result = CliRunner().invoke(
            main,
            ['--spec', 'sample_specs/fintech.yaml', '--tokens', str(tokens)],
        )

    assert result.exit_code == 2
    assert 'Scan failed unexpectedly' in result.output


def _two_user_tokens(tmp_path):
    tokens = tmp_path / 'two_users.json'
    tokens.write_text(
        '[{"name": "alice", "token": "t1", "user_id": 1},'
        ' {"name": "bob", "token": "t2", "user_id": 2}]',
        encoding='utf-8',
    )
    return str(tokens)


def test_read_map_is_parsed_into_config(tmp_path):
    """--read-map WRITE=READ pairs reach the Scanner config as a dict."""
    clean_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    with patch('cli.Scanner') as scanner_cls:
        scanner_cls.return_value.run.return_value = {'summary': clean_summary}
        result = CliRunner().invoke(
            main,
            [
                '--spec', 'sample_specs/fintech.yaml',
                '--tokens', _two_user_tokens(tmp_path),
                '--read-map', '/account/update=/account/{id}',
                '--read-map', '/user/save=/user/{user_id}',
            ],
        )

    assert result.exit_code == 0
    config = scanner_cls.call_args.args[0]
    assert config['read_endpoint_map'] == {
        '/account/update': '/account/{id}',
        '/user/save': '/user/{user_id}',
    }


def test_read_map_defaults_to_none_when_absent(tmp_path):
    clean_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    with patch('cli.Scanner') as scanner_cls:
        scanner_cls.return_value.run.return_value = {'summary': clean_summary}
        result = CliRunner().invoke(
            main,
            ['--spec', 'sample_specs/fintech.yaml', '--tokens', _two_user_tokens(tmp_path)],
        )

    assert result.exit_code == 0
    assert scanner_cls.call_args.args[0]['read_endpoint_map'] is None


def test_read_map_rejects_entry_without_equals(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            '--spec', 'sample_specs/fintech.yaml',
            '--tokens', _two_user_tokens(tmp_path),
            '--read-map', '/account/update',   # missing =READ
        ],
    )

    assert result.exit_code == 2
    assert '--read-map entry must be WRITE=READ' in result.output
