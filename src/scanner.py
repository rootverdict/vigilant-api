"""
scanner.py
----------
The main orchestrator for Vigilant-API v1.

Wires together:
  OpenAPIParser → AuthHandler → BOLADetector + SSRFDetector + OAuthFlawDetector
                              → ForensicLogger → ReportGenerator

The CLI (cli.py) calls Scanner.run() and that's all it needs to know.
"""

import os
import re as _re
from colorama import Fore, Style, init as colorama_init

from spec_parser    import OpenAPIParser
from auth           import AuthHandler
from bola_detector  import BOLADetector
from ssrf_detector  import SSRFDetector
from oauth_detector import OAuthFlawDetector
from logger         import ForensicLogger
from reporter       import ReportGenerator

colorama_init(autoreset=True)

# Keys that must be present in the oauth_config dict
_REQUIRED_OAUTH_KEYS = {'auth_url', 'token_url', 'client_id'}


class Scanner:

    def __init__(self, config: dict):
        """
        config keys:
          spec_file      : path to OpenAPI YAML/JSON
          users          : list of user dicts  [{'name':..,'token':..,'user_id':..}]
          resource_ids   : list of ints to probe for BOLA   (default [1,2,3,4,5])
          oauth_config   : dict with auth_url, token_url, client_id etc. (optional)
          output_dir     : where to write reports (default 'reports')
          callback_url   : blind SSRF callback — omit to skip blind SSRF check
          skip           : list of check names to skip (optional)
          delay          : seconds between requests for rate limiting (default 0)
          insecure       : if True, skip TLS certificate verification (default False)
          proxy          : HTTP proxy URL e.g. 'http://127.0.0.1:8080' (optional)
          verbose        : if True, print every request to stdout (default False)
        """
        self.config       = config
        self.parser       = OpenAPIParser(config['spec_file'])
        self.logger       = ForensicLogger(config.get('output_dir', 'reports'))
        self.reporter     = ReportGenerator(config.get('output_dir', 'reports'))
        self.resource_ids = config.get('resource_ids', [1, 2, 3, 4, 5])
        self.skip         = set(config.get('skip', []))
        self.verbose      = config.get('verbose', False)

        base_url = self.parser.get_base_url()
        users    = config['users']

        if not users:
            raise ValueError(
                '[ERROR] At least 1 user token is required for SSRF and OAuth checks. '
                'Add a token to your tokens file.'
            )

        if 'bola' not in self.skip and len(users) < 2:
            raise ValueError(
                '[ERROR] At least 2 users required for differential BOLA testing. '
                'Add a second user to your tokens file.'
            )

        # Common options forwarded to all detectors
        det_opts = dict(
            delay   = config.get('delay', 0.0),
            verify  = not config.get('insecure', False),
            proxy   = config.get('proxy'),
            verbose = self.verbose,
        )

        self.bola = BOLADetector(base_url, users, **det_opts) if len(users) >= 2 else None
        self.ssrf = SSRFDetector(config.get('callback_url'), **det_opts)

        # OAuth detector is optional (only if oauth_config provided)
        oa = config.get('oauth_config')
        if oa:
            # Validate required keys before instantiating — gives a clear error message
            missing = _REQUIRED_OAUTH_KEYS - set(oa.keys())
            if missing:
                raise ValueError(
                    f'[ERROR] --oauth-config is missing required keys: '
                    f'{", ".join(sorted(missing))}. '
                    f'Required: {", ".join(sorted(_REQUIRED_OAUTH_KEYS))}'
                )
            # Filter to only the keys OAuthFlawDetector accepts — extra keys in the
            # JSON (e.g. comments, descriptions) would cause unexpected-kwarg errors.
            _KNOWN_OAUTH_KEYS = {'auth_url', 'token_url', 'client_id', 'client_secret', 'redirect_uri'}
            filtered_oa = {k: v for k, v in oa.items() if k in _KNOWN_OAUTH_KEYS}
            self.oauth = OAuthFlawDetector(**filtered_oa, **det_opts)
        else:
            self.oauth = None

    # ------------------------------------------------------------------ #
    #  Main entry point                                                    #
    # ------------------------------------------------------------------ #

    def run(self) -> dict:
        """
        Execute full v1 scan.
        Returns a summary dict with file paths to the generated reports.
        """
        spec_file = self.config['spec_file']
        target    = self.parser.get_base_url()
        endpoints = self.parser.get_endpoints()

        self.logger.log_scan_start(spec_file, target)
        self._print_banner(target, len(endpoints))

        # ── Scan each endpoint ─────────────────────────────────────────
        for method, path, params, security in endpoints:
            self._print_endpoint(method, path)

            # --- BOLA / IDOR ---
            if 'bola' not in self.skip:
                if not self.bola:
                    raise ValueError(
                        '[ERROR] BOLA checks require at least 2 users. '
                        'Either add another token or skip BOLA with --skip bola.'
                    )
                # Run BOLA when any of these are true:
                #   1. Path has any {param}    → Simple IDOR, Indirect Reference
                #   2. Method accepts a body   → Body IDOR, Mass Assignment
                #   3. Query param contains id → Parameter Pollution
                any_path_params = [p for p in params if p['in'] == 'path']
                has_body        = method in ('POST', 'PUT', 'PATCH')
                has_query_id    = any('id' in p['name'].lower() for p in params if p['in'] == 'query')
                if any_path_params or has_body or has_query_id:
                    findings = self.bola.test_endpoint(method, path, self.resource_ids)
                    for f in findings:
                        fp = self.logger.log_finding(f)
                        self._print_finding(f, fp)

            # --- SSRF ---
            if 'ssrf' not in self.skip:
                url_params = self.parser.get_url_params(params)
                if url_params:
                    token = self.config['users'][0]['token']
                    # Replace any {path_param} placeholders with a default value
                    # so the URL resolves to a real endpoint (avoids 404s)
                    resolved_path = _re.sub(r'\{[^}]+\}', '1', path)
                    full_url = f'{target}{resolved_path}'
                    findings = self.ssrf.test_endpoint(method, full_url, url_params, token)
                    for f in findings:
                        fp = self.logger.log_finding(f)
                        self._print_finding(f, fp)

        # ── OAuth checks (endpoint-agnostic) ──────────────────────────
        if 'oauth' not in self.skip:
            # JWT algorithm weakness check for every user token
            for user in self.config['users']:
                token   = user.get('token', '')
                finding = AuthHandler.check_jwt_algorithm(token)
                if finding:
                    finding['endpoint'] = f'Token for user: {user["name"]}'
                    fp = self.logger.log_finding(finding)
                    self._print_finding(finding, fp)

            # Full OAuth server checks (only if oauth_config provided)
            if self.oauth:
                print(f'\n{Fore.CYAN}[*] Running OAuth flaw checks...{Style.RESET_ALL}')
                findings = self.oauth.run_all_checks()
                for f in findings:
                    fp = self.logger.log_finding(f)
                    self._print_finding(f, fp)

        # ── Generate reports ──────────────────────────────────────────
        meta = self.logger.log_scan_end()
        meta['endpoints_tested'] = len(endpoints)
        meta['target']           = target
        meta['spec_file']        = spec_file

        all_findings = self.logger.sorted_findings()
        summary      = self.logger.get_summary()

        json_path = self.reporter.generate_json(all_findings, meta)
        html_path = self.reporter.generate_html(all_findings, meta)

        self._print_summary(summary, json_path, html_path)

        return {
            'findings':    all_findings,
            'summary':     summary,
            'json_report': json_path,
            'html_report': html_path,
        }

    # ------------------------------------------------------------------ #
    #  Console output helpers                                              #
    # ------------------------------------------------------------------ #

    def _print_banner(self, target, endpoint_count):
        proxy   = self.config.get('proxy') or 'none'
        delay   = self.config.get('delay', 0.0)
        insecure = self.config.get('insecure', False)
        callback = self.config.get('callback_url') or 'none (blind SSRF skipped)'
        print(f'\n{Fore.CYAN}{"="*60}')
        print(f'  Vigilant-API v1.0 — API Security Scanner')
        print(f'  Target    : {target}')
        print(f'  Endpoints : {endpoint_count}')
        print(f'  Delay     : {delay}s  |  Verify TLS: {not insecure}')
        print(f'  Proxy     : {proxy}')
        print(f'  Callback  : {callback}')
        print(f'{"="*60}{Style.RESET_ALL}\n')

    def _print_endpoint(self, method, path):
        color = {'GET': Fore.GREEN, 'POST': Fore.YELLOW,
                 'PUT': Fore.BLUE, 'DELETE': Fore.RED}.get(method, Fore.WHITE)
        print(f'  {color}{method:<7}{Style.RESET_ALL} {path}')

    def _print_finding(self, finding, filepath):
        sev = finding.get('severity', finding.get('vulnerability', {}).get('severity', '?'))
        sev_color = {
            'CRITICAL': Fore.RED, 'HIGH': Fore.MAGENTA,
            'MEDIUM': Fore.YELLOW, 'LOW': Fore.GREEN,
        }.get(sev, Fore.WHITE)
        check = finding.get('check', '?')
        print(f'    {sev_color}[{sev}]{Style.RESET_ALL} {check}')
        print(f'           Evidence → {filepath}')

    def _print_summary(self, summary, json_path, html_path):
        total = sum(summary.values())
        print(f'\n{Fore.CYAN}{"="*60}')
        print(f'  Scan Complete — {total} finding(s)')
        print(f'  CRITICAL: {summary["CRITICAL"]}  HIGH: {summary["HIGH"]}  '
              f'MEDIUM: {summary["MEDIUM"]}  LOW: {summary["LOW"]}  INFO: {summary["INFO"]}')
        print(f'\n  JSON report : {json_path}')
        print(f'  HTML report : {html_path}')
        print(f'{"="*60}{Style.RESET_ALL}\n')
