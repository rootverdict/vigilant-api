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

        # Enrich the finding before saving
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
                'endpoint':   finding.get('endpoint'),
                'parameter':  finding.get('parameter'),
                'resource_id': finding.get('resource_id'),
            },
            'evidence':      finding.get('evidence', {}),
            'description':   finding.get('description', ''),
            'remediation':   finding.get('remediation', ''),
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(enriched, f, indent=2, default=str)

        # Keep in memory for the final report
        enriched['_evidence_file'] = filepath
        self.findings.append(enriched)

        return filepath

    def log_scan_start(self, spec_file: str, target: str):
        """Record scan metadata at the start."""
        self._meta = {
            'spec_file': spec_file,
            'target':    target,
            'start_time': datetime.now(timezone.utc).isoformat(),
        }

    def log_scan_end(self):
        """Record end time and return a summary dict."""
        if not hasattr(self, '_meta'):
            self._meta = {}
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
