"""
cli.py
------
Command-line interface for Vigilant-API v1.

Usage examples:
  # Full scan
  python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json

  # Skip SSRF and OAuth checks
  python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
                --skip ssrf --skip oauth

  # Custom resource IDs, output dir, rate-limit delay, and proxy
  python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
                --ids 1,2,3,10,99 --output my_reports --delay 0.5 \
                --proxy http://127.0.0.1:8080

  # Self-signed cert target + blind SSRF callback
  python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
                --insecure --callback https://your.burp-collaborator.net/

  # Verbose output (prints every request)
  python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
                --verbose
"""

import sys
import os
import json
import click

# Ensure src/ is on the path regardless of where cli.py is invoked from
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from scanner import Scanner


def _validate_user_entry(user: dict, index: int) -> str | None:
    """Return a token-file validation error, or None when usable."""
    if not user.get('name'):
        return f'Token entry {index} is missing required field "name".'

    scheme = str(user.get('scheme') or user.get('auth_type') or '').lower()
    if scheme in ('oauth2', 'oauth') or any(
        key in user for key in ('refresh_token', 'username', 'client_id', 'token_url')
    ):
        if user.get('token') or user.get('access_token'):
            return None
        has_client = bool(user.get('client_id'))
        can_refresh = has_client and bool(user.get('refresh_token'))
        can_use_password = has_client and bool(user.get('username')) and bool(user.get('password'))
        can_use_client_credentials = has_client and bool(user.get('client_secret'))
        if can_refresh or can_use_password or can_use_client_credentials:
            return None
        return (
            f'Token entry {index} has incomplete OAuth credentials. Provide an access token, '
            'refresh token, username/password, or client credentials.'
        )

    if scheme in ('apikey', 'api_key'):
        if user.get('key') or user.get('token') or (
            isinstance(user.get('api_keys'), dict) and user['api_keys']
        ):
            return None
        return (
            f'Token entry {index} needs "key", "token", or a non-empty "api_keys" '
            'mapping for API-key authentication.'
        )

    if user.get('token') or user.get('key') or user.get('access_token') or (
        isinstance(user.get('api_keys'), dict) and user['api_keys']
    ):
        return None
    return f'Token entry {index} needs authentication credentials.'


def _validate_oauth_config(config) -> str | None:
    """Return an OAuth config validation error, or None for a JSON object."""
    if not isinstance(config, dict):
        return 'OAuth config file must contain a JSON object.'
    return None


@click.command()
@click.version_option('1.0.0', '--version', '-V', prog_name='vigilant-api')
@click.option('--spec',     required=True,  help='Path to OpenAPI YAML/JSON spec file')
@click.option('--tokens',   required=True,  help='Path to JSON file with user tokens')
@click.option('--ids',      default='1,2,3,4,5', show_default=True,
              help='Comma-separated resource IDs to probe for BOLA')
@click.option('--output',   default='reports', show_default=True,
              help='Directory for output reports')
@click.option('--skip',     multiple=True,
              type=click.Choice(['bola', 'ssrf', 'oauth', 'jwt'], case_sensitive=False),
              help='Skip specific check types (can repeat: --skip bola --skip ssrf). '
                   'Use --skip jwt to suppress JWT algorithm checks independently of --skip oauth.')
@click.option('--callback', default=None,
              help='Callback URL for blind SSRF (e.g. Burp Collaborator). Omit to skip blind SSRF.')
@click.option('--oauth-config', 'oauth_config_file', default=None,
              help='Path to JSON file with OAuth server config (for OAuth flaw checks)')
@click.option('--delay',    default=0.0, show_default=True, type=float,
              help='Seconds to wait between requests (rate limiting / WAF evasion)')
@click.option('--insecure', is_flag=True, default=False,
              help='Disable TLS certificate verification (for self-signed certs)')
@click.option('--proxy',    default=None,
              help='HTTP proxy URL to route all requests through (e.g. http://127.0.0.1:8080)')
@click.option('--verbose',  is_flag=True, default=False,
              help='Print every request URL and payload to stdout')
@click.option('--active',   is_flag=True, default=False,
              help='Enable POST/PUT/PATCH/DELETE security probes. May modify target data.')
@click.option('--max-requests', default=1000, show_default=True,
              type=click.IntRange(min=1),
              help='Hard cap on HTTP requests sent during one scan')
def main(spec, tokens, ids, output, skip, callback, oauth_config_file,
         delay, insecure, proxy, verbose, active, max_requests):
    """
    \b
    Vigilant-API v1.0 — API Security Scanner
    Detects BOLA/IDOR, SSRF, and OAuth flaws via automated testing.
    """

    # ── Validate inputs ──────────────────────────────────────────────
    if not os.path.exists(spec):
        click.echo(f'[ERROR] Spec file not found: {spec}', err=True)
        sys.exit(2)

    if not os.path.exists(tokens):
        click.echo(f'[ERROR] Tokens file not found: {tokens}', err=True)
        sys.exit(2)

    # ── Load tokens ──────────────────────────────────────────────────
    try:
        with open(tokens, encoding='utf-8') as f:
            users = json.load(f)
    except json.JSONDecodeError as e:
        click.echo(f'[ERROR] Tokens file contains invalid JSON: {e}', err=True)
        sys.exit(2)
    if not isinstance(users, list) or not users:
        click.echo('[ERROR] Tokens file must be a non-empty JSON array.', err=True)
        sys.exit(2)
    for i, u in enumerate(users):
        if not isinstance(u, dict):
            click.echo(f'[ERROR] Token entry {i} must be a JSON object.', err=True)
            sys.exit(2)
        validation_error = _validate_user_entry(u, i)
        if validation_error:
            click.echo(f'[ERROR] {validation_error}', err=True)
            sys.exit(2)

    # ── Load optional OAuth config ────────────────────────────────────
    oauth_config = None
    if oauth_config_file:
        if not os.path.exists(oauth_config_file):
            click.echo(f'[ERROR] OAuth config file not found: {oauth_config_file}', err=True)
            sys.exit(2)
        try:
            with open(oauth_config_file, encoding='utf-8') as f:
                oauth_config = json.load(f)
        except json.JSONDecodeError as e:
            click.echo(f'[ERROR] OAuth config file contains invalid JSON: {e}', err=True)
            sys.exit(2)
        validation_error = _validate_oauth_config(oauth_config)
        if validation_error:
            click.echo(f'[ERROR] {validation_error}', err=True)
            sys.exit(2)

    # ── Parse resource IDs ────────────────────────────────────────────
    try:
        resource_ids = [int(i.strip()) for i in ids.split(',')]
    except ValueError:
        click.echo('[ERROR] --ids must be comma-separated integers, e.g. 1,2,3', err=True)
        sys.exit(2)

    # ── Build config and run ──────────────────────────────────────────
    config = {
        'spec_file':    spec,
        'users':        users,
        'resource_ids': resource_ids,
        'output_dir':   output,
        'skip':         list(skip),
        'callback_url': callback,
        'oauth_config': oauth_config,
        'delay':        delay,
        'insecure':     insecure,
        'proxy':        proxy,
        'verbose':      verbose,
        'active':       active,
        'max_requests': max_requests,
    }

    if active:
        click.echo(
            '[WARNING] Active mode can create or modify target data. '
            'Use it only on systems you are authorized to test.',
            err=True,
        )

    try:
        scanner = Scanner(config)
    except ValueError as e:
        click.echo(str(e), err=True)
        sys.exit(2)

    try:
        result = scanner.run()
    except (ValueError, OSError) as e:
        click.echo(f'[ERROR] Scan failed: {e}', err=True)
        sys.exit(2)

    # Exit with non-zero code if critical/high findings exist (CI gate)
    summary = result['summary']
    if summary['CRITICAL'] > 0 or summary['HIGH'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
