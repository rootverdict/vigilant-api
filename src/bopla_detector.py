"""
bopla_detector.py
-----------------
Broken Object Property Level Authorization (BOPLA) & Excessive Data Exposure Detector.
Inspects response bodies for leaked sensitive attributes (passwords, tokens, internal
keys, PII, internal role/privilege flags) that should not be exposed.
"""

from __future__ import annotations

import re
from typing import Any

# Pattern matching sensitive property keys in JSON or query/form structures
_SENSITIVE_KEY_PATTERNS = [
    re.compile(r"^(password|passwd|pwd|pass_hash|password_hash)$", re.IGNORECASE),
    re.compile(r"^(secret|api_key|apikey|access_token|refresh_token|private_key)$", re.IGNORECASE),
    re.compile(r"^(ssn|social_security|credit_card|cvv|card_number)$", re.IGNORECASE),
    re.compile(r"^(is_admin|is_superuser|role_id|admin_role|internal_id)$", re.IGNORECASE),
]

_SENSITIVE_VALUE_PATTERNS = [
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS Access Key ID"),
    (re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"), "GitHub Personal Access Token"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Private Cryptographic Key"),
]


class BOPLADetector:
    """Inspects API responses for excessive data exposure and property-level authorization leaks."""

    def analyze_response(
        self,
        method: str,
        path: str,
        status_code: int,
        response_json: Any,
        raw_text: str = "",
    ) -> list[dict[str, Any]]:
        """Scan a response body for sensitive properties and leaked values."""
        findings: list[dict[str, Any]] = []

        if status_code not in (200, 201):
            return findings

        leaked_keys: list[str] = []
        if isinstance(response_json, (dict, list)):
            self._walk_and_find_keys(response_json, leaked_keys)

        if leaked_keys:
            findings.append({
                "check": "BOPLA Excessive Data Exposure",
                "vulnerability": {
                    "name": "Excessive Data Exposure / Sensitive Property Leak",
                    "type": "BOPLA",
                    "severity": "HIGH",
                    "endpoint": path,
                    "method": method,
                    "description": (
                        f"Endpoint {method} {path} returned sensitive properties in response: "
                        f"{', '.join(sorted(set(leaked_keys))[:5])}"
                    ),
                    "remediation": (
                        "Filter outgoing responses using Data Transfer Objects (DTOs) "
                        "or serialization allowlists."
                    ),
                },
                "endpoint": {"method": method, "path": path},
                "evidence": {
                    "status": status_code,
                    "leaked_properties": sorted(set(leaked_keys)),
                    "body_preview": (raw_text or str(response_json))[:300],
                },
            })

        # Check for known high-risk token/secret regex patterns in raw body
        if raw_text:
            for pattern, name in _SENSITIVE_VALUE_PATTERNS:
                if pattern.search(raw_text):
                    findings.append({
                        "check": "Hardcoded Secret Exposure",
                        "vulnerability": {
                            "name": f"Leaked {name} in API Response",
                            "type": "SECRET_LEAK",
                            "severity": "CRITICAL",
                            "endpoint": path,
                            "method": method,
                            "description": (
                                f"Endpoint {method} {path} leaks a live {name} in its response body."
                            ),
                            "remediation": (
                                "Immediately revoke and rotate the secret, and remove it from "
                                "response output."
                            ),
                        },
                        "endpoint": {"method": method, "path": path},
                        "evidence": {
                            "status": status_code,
                            "secret_type": name,
                            "body_preview": raw_text[:300],
                        },
                    })
                    break

        return findings

    def _walk_and_find_keys(self, obj: Any, found: list[str]) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_str = str(k)
                if any(pat.match(k_str) for pat in _SENSITIVE_KEY_PATTERNS):
                    found.append(k_str)
                self._walk_and_find_keys(v, found)
        elif isinstance(obj, list):
            for item in obj[:10]:  # Cap to first 10 items in large lists
                self._walk_and_find_keys(item, found)
