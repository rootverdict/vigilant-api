"""
logger.py
---------
ForensicLogger: writes timestamped JSON evidence files for every finding.

Why forensic logging matters for AppSec:
  - Security findings without evidence are dismissed as false positives.
  - Forensic logs include the exact HTTP request, response, and verdict.
  - These files can be attached to a bug report or audit finding.

Each file is named:   evidence_YYYYMMDD_HHMMSS_<type>_<id>.json
All files are written to:  reports/evidence/
"""

import json
import uuid
import os
from datetime import datetime, timezone


class ForensicLogger:

    SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

    def __init__(self, output_dir: str = 'reports'):
        self.output_dir  = output_dir
        self.evidence_dir = os.path.join(output_dir, 'evidence')
        os.makedirs(self.evidence_dir, exist_ok=True)

        self.findings: list = []   # accumulated findings for this scan session
        self._meta: dict[str, object] = {}

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def log_finding(self, finding: dict) -> str:
        """
        Persist a single finding as a JSON evidence file.
        Attaches a unique finding_id and scan timestamp.
        Returns the file path.
        """
        finding_id   = str(uuid.uuid4())[:8].upper()
        timestamp    = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        vuln_type    = finding.get('type', 'UNKNOWN').replace('/', '_')
        filename     = f'evidence_{timestamp}_{vuln_type}_{finding_id}.json'
        filepath     = os.path.join(self.evidence_dir, filename)

        # Enrich the finding before saving.
        # Reconstruct a minimal request/response summary for forensic review:
        # the detectors forward what they captured in the `evidence` dict, so we
        # lift it into a dedicated `http` block so analysts can reproduce the test.
        raw_evidence = finding.get('evidence', {})
        http_block = self._build_http_block(finding, raw_evidence)

        enriched = {
            'metadata': {
                'finding_id':   finding_id,
                'timestamp':    datetime.now(timezone.utc).isoformat(),
                'tool_version': '1.0.0',
                'scanner':      'vigilant-api',
            },
            'vulnerability': {
                'type':       finding.get('type'),
                'check':      finding.get('check'),
                'severity':   finding.get('severity', 'MEDIUM'),
                'method':     finding.get('method'),
                'endpoint':   finding.get('endpoint'),
                'parameter':  finding.get('parameter'),
                'resource_id': finding.get('resource_id'),
                'owner': finding.get('owner'),
                'unauthorized_user': finding.get('unauthorized_user'),
            },
            'http':          http_block,
            'evidence':      raw_evidence,
            'description':   finding.get('description', ''),
            'remediation':   finding.get('remediation', ''),
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(enriched, f, indent=2, default=str)

        # Keep in memory for the final report
        enriched['_evidence_file'] = filepath
        self.findings.append(enriched)

        return filepath

    @staticmethod
    def _build_http_block(finding: dict, evidence: dict) -> dict:
        """
        Build a human-readable HTTP request/response summary from fields the
        detectors already collected.  This lets an analyst reproduce the test
        without re-running the scanner.

        Fields populated vary by detector type:
          SSRF   → endpoint, parameter, evidence.payload, evidence.status_code, evidence.body_preview
          BOLA   → endpoint, resource_id, unauthorized_user, evidence.payload / body_preview
          OAuth  → endpoint (or check name), evidence keys vary
        """
        endpoint  = finding.get('endpoint', '')
        method    = finding.get('method', '')
        param     = finding.get('parameter', '')
        payload   = evidence.get('payload', '')
        status    = evidence.get('status_code', '')
        preview   = evidence.get('body_preview', '')

        # Reconstruct a curl-style request line for quick reproduction
        if payload and param:
            request_hint = f'[param] {param} = {payload[:200]}'
        elif payload:
            request_hint = str(payload)[:200]
        else:
            request_hint = '(see evidence block for request details)'

        return {
            'request': {
                'endpoint':      endpoint,
                'method':        method or None,
                'injected_param': param or None,
                'injected_value': str(payload)[:200] if payload else None,
                'reproduction':  request_hint,
            },
            'response': {
                'status_code':  status or None,
                'body_preview': str(preview)[:500] if preview else None,
            },
        }

    def log_scan_start(self, spec_file: str, target: str):
        """Record scan metadata at the start."""
        self._meta = {
            'spec_file': spec_file,
            'target':    target,
            'start_time': datetime.now(timezone.utc).isoformat(),
        }

    def log_scan_end(self):
        """Record end time and return a summary dict."""
        self._meta['end_time'] = datetime.now(timezone.utc).isoformat()
        self._meta['total_findings'] = len(self.findings)
        return self._meta

    def get_findings(self) -> list:
        return self.findings

    def get_summary(self) -> dict:
        """Return a severity breakdown of all logged findings."""
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            sev = f.get('vulnerability', {}).get('severity', 'INFO')
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    def sorted_findings(self) -> list:
        """Return findings sorted by severity (CRITICAL first)."""
        return sorted(
            self.findings,
            key=lambda f: self.SEVERITY_ORDER.get(
                f.get('vulnerability', {}).get('severity', 'INFO'), 99
            )
        )
