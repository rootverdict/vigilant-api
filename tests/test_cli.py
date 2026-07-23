import os
import sys

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
