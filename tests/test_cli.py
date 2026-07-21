import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cli import _validate_oauth_config, _validate_user_entry


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
