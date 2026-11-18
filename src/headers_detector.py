"""
headers_detector.py
--------------------
Security Headers and CORS Misconfiguration Detector for Vigilant-API.
Checks for missing protective headers and insecure CORS policies.
"""

from __future__ import annotations

from typing import Any
import requests
from request_utils import RequestBudget


class HeadersDetector:
    """Evaluates security headers and CORS policy configurations."""

    def __init__(
        self,
        base_url: str,
        budget: RequestBudget,
        timeout: float = 10.0,
        verify: bool = True,
        proxy: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.budget = budget
        self.timeout = timeout
        self.verify = verify
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def test_cors_and_headers(
        self,
        path: str,
        user_headers: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Probe for permissive CORS policies and missing fundamental security headers."""
        findings: list[dict[str, Any]] = []
        if not self.budget.consume():
            return findings

        url = f"{self.base_url}{path}"
        req_headers = dict(user_headers or {})
        req_headers["Origin"] = "https://evil-attacker.example.com"

        try:
            resp = requests.get(
                url,
                headers=req_headers,
                timeout=self.timeout,
                verify=self.verify,
                proxies=self.proxies,
            )
        except requests.RequestException:
            return findings

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        allow_origin = resp_headers.get("access-control-allow-origin", "")
        allow_creds = resp_headers.get("access-control-allow-credentials", "").lower() == "true"

        # 1. CORS Misconfiguration: Wildcard with credentials or reflected attacker origin
        if allow_origin == "*" and allow_creds:
            findings.append({
                "check": "Insecure CORS Policy",
                "vulnerability": {
                    "name": "CORS Misconfiguration: Wildcard with Credentials",
                    "type": "CORS",
                    "severity": "HIGH",
                    "endpoint": path,
                    "method": "GET",
                    "description": (
                        f"Endpoint {path} permits credentialed CORS requests with a wildcard origin (*)."
                    ),
                    "remediation": (
                        "Do not allow Access-Control-Allow-Origin: * when credentials are supported."
                    ),
                },
                "endpoint": {"method": "GET", "path": path},
                "evidence": {
                    "origin_sent": "https://evil-attacker.example.com",
                    "allow_origin": allow_origin,
                    "allow_credentials": "true",
                },
            })
        elif "evil-attacker.example.com" in allow_origin and allow_creds:
            findings.append({
                "check": "Insecure CORS Policy",
                "vulnerability": {
                    "name": "CORS Misconfiguration: Arbitrary Reflected Origin",
                    "type": "CORS",
                    "severity": "CRITICAL",
                    "endpoint": path,
                    "method": "GET",
                    "description": (
                        f"Endpoint {path} reflects arbitrary Origin headers with credentials allowed."
                    ),
                    "remediation": (
                        "Validate the Origin header against a strict allowlist of trusted origins."
                    ),
                },
                "endpoint": {"method": "GET", "path": path},
                "evidence": {
                    "origin_sent": "https://evil-attacker.example.com",
                    "allow_origin": allow_origin,
                    "allow_credentials": "true",
                },
            })

        # 2. Missing Critical Security Headers (checked on root or top-level endpoints)
        if (
            path in ("/", "/api", "/api/v1")
            and self.base_url.startswith("https://")
            and "strict-transport-security" not in resp_headers
        ):
            findings.append({
                "check": "Missing Security Header",
                "vulnerability": {
                    "name": "Missing Strict-Transport-Security (HSTS)",
                    "type": "SECURITY_HEADERS",
                    "severity": "LOW",
                    "endpoint": path,
                    "method": "GET",
                    "description": "API response lacks the Strict-Transport-Security (HSTS) header.",
                    "remediation": (
                        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
                    ),
                },
                "endpoint": {"method": "GET", "path": path},
                "evidence": {"missing_header": "Strict-Transport-Security"},
            })

        return findings
