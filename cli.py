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


@click.command()
@click.version_option('1.0.0', '--version', '-V', prog_name='vigilant-api')
@click.option('--spec',     required=True,  help='Path to OpenAPI YAML/JSON spec file')
@click.option('--tokens',   required=True,  help='Path to JSON file with user tokens')
@click.option('--ids',      default='1,2,3,4,5', show_default=True,
              help='Comma-separated resource IDs to probe for BOLA')
@click.option('--output',   default='reports', show_default=True,
              help='Directory for output reports')
@click.option('--skip',     multiple=True,
              type=click.Choice(['bola', 'ssrf', 'oauth'], case_sensitive=False),
              help='Skip specific check types (can repeat: --skip bola --skip ssrf)')
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
def main(spec, tokens, ids, output, skip, callback, oauth_config_file,
         delay, insecure, proxy, verbose):
    """
    \b
    Vigilant-API v1.0 — API Security Scanner
    Detects BOLA/IDOR, SSRF, and OAuth flaws via automated testing.
    """

    # ── Validate inputs ──────────────────────────────────────────────
    if not os.path.exists(spec):
        click.echo(f'[ERROR] Spec file not found: {spec}', err=True)
        sys.exit(1)

    if not os.path.exists(tokens):
        click.echo(f'[ERROR] Tokens file not found: {tokens}', err=True)
        sys.exit(1)

    # ── Load tokens ──────────────────────────────────────────────────
    try:
        with open(tokens, encoding='utf-8') as f:
            users = json.load(f)
    except json.JSONDecodeError as e:
        click.echo(f'[ERROR] Tokens file contains invalid JSON: {e}', err=True)
        sys.exit(1)
    if not isinstance(users, list) or not users:
        click.echo('[ERROR] Tokens file must be a non-empty JSON array.', err=True)
        sys.exit(1)
    for i, u in enumerate(users):
        if not isinstance(u, dict):
            click.echo(f'[ERROR] Token entry {i} must be a JSON object.', err=True)
            sys.exit(1)
        for required_key in ('name', 'token'):
            if required_key not in u or not u[required_key]:
                click.echo(
                    f'[ERROR] Token entry {i} is missing required field "{required_key}".', err=True
                )
                sys.exit(1)

    # ── Load optional OAuth config ────────────────────────────────────
    oauth_config = None
    if oauth_config_file:
        if not os.path.exists(oauth_config_file):
            click.echo(f'[ERROR] OAuth config file not found: {oauth_config_file}', err=True)
            sys.exit(1)
        try:
            with open(oauth_config_file, encoding='utf-8') as f:
                oauth_config = json.load(f)
        except json.JSONDecodeError as e:
            click.echo(f'[ERROR] OAuth config file contains invalid JSON: {e}', err=True)
            sys.exit(1)

    # ── Parse resource IDs ────────────────────────────────────────────
    try:
        resource_ids = [int(i.strip()) for i in ids.split(',')]
    except ValueError:
        click.echo('[ERROR] --ids must be comma-separated integers, e.g. 1,2,3', err=True)
        sys.exit(1)

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
    }

    try:
        scanner = Scanner(config)
    except ValueError as e:
        click.echo(str(e), err=True)
        sys.exit(1)

    result  = scanner.run()

    # Exit with non-zero code if critical/high findings exist (CI gate)
    summary = result['summary']
    if summary['CRITICAL'] > 0 or summary['HIGH'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
