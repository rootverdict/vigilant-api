"""
bfla_detector.py
----------------
Broken Function Level Authorization (BFLA) Detector for Vigilant-API.
Detects when sensitive or administrative endpoints (e.g. /admin, /manage,
/internal, or restricted operations) can be accessed by unprivileged users
or unauthenticated callers.
"""

from __future__ import annotations

import re
from typing import Any
import requests
from request_utils import RequestBudget

# Heuristic patterns identifying sensitive / administrative functions
_ADMIN_PATH_PATTERNS = [
    re.compile(r"/(admin|administrator|adm)/", re.IGNORECASE),
    re.compile(r"/(manage|management|manager)/", re.IGNORECASE),
    re.compile(r"/(internal|system|root|super)/", re.IGNORECASE),
    re.compile(r"/(users?|accounts?)/(create|delete|role|roles|permission|permissions)", re.IGNORECASE),
    re.compile(r"/(config|settings|audit|metrics|healthz|env|actuator)", re.IGNORECASE),
]


class BFLADetector:
    """Probes endpoints for Broken Function Level Authorization flaws."""

    def __init__(
        self,
        base_url: str,
        budget: RequestBudget,
        timeout: float = 10.0,
        verify: bool = True,
        proxy: str | None = None,
        delay: float = 0.0,
        active: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.budget = budget
        self.timeout = timeout
        self.verify = verify
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.delay = delay
        self.active = active

    def is_privileged_endpoint(self, path: str, summary: str = "", description: str = "") -> bool:
        """Check if path or operation metadata suggests a privileged function."""
        clean_path = path.lower()
        if any(pat.search(clean_path) for pat in _ADMIN_PATH_PATTERNS):
            return True
        meta = f"{summary} {description}".lower()
        return any(term in meta for term in ("admin only", "administrator", "requires role", "internal use"))

    def test_endpoint(
        self,
        method: str,
        path: str,
        users: list[dict[str, Any]],
        headers_builder: Any,
    ) -> list[dict[str, Any]]:
        """
        Probe endpoint with non-privileged user tokens and anonymous request.
        A finding is reported if a non-admin user or unauthenticated caller can
        access a privileged endpoint (200 OK or 201 Created).
        """
        findings: list[dict[str, Any]] = []

        # Only probe write methods (POST, PUT, DELETE) if active mode is enabled
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE") and not self.active:
            return findings

        # Filter unprivileged users (skip admin / owns_all)
        non_admins = [
            u for u in users
            if not u.get("owns_all")
            and str(u.get("role", "")).lower() not in ("admin", "administrator", "root")
        ]

        if not non_admins:
            return findings

        url = f"{self.base_url}{path}"
        # Substitute sample path parameters if any
        url = re.sub(r"\{[^\}]+\}", "1", url)

        # 1. Test Unauthenticated / Anonymous Access
        if self.budget.consume():
            try:
                resp = requests.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    verify=self.verify,
                    proxies=self.proxies,
                )
                if resp.status_code in (200, 201, 204):
                    findings.append({
                        "check": "BFLA Unauthenticated Access",
                        "vulnerability": {
                            "name": "Broken Function Level Authorization (Unauthenticated)",
                            "type": "BFLA",
                            "severity": "CRITICAL",
                            "endpoint": path,
                            "method": method,
                            "description": (
                                f"Administrative endpoint {method} {path} allows unauthenticated "
                                f"access (HTTP {resp.status_code})."
                            ),
                            "remediation": (
                                "Enforce strict role-based access control and require valid authentication."
                            ),
                        },
                        "endpoint": {"method": method, "path": path},
                        "evidence": {
                            "status": resp.status_code,
                            "user": "anonymous",
                            "url": url,
                            "body_preview": resp.text[:300],
                        },
                    })
            except requests.RequestException:
                pass

        # 2. Test with Standard / Non-privileged User
        for user in non_admins:
            if not self.budget.consume():
                break

            auth_headers = headers_builder(user)
            try:
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=auth_headers,
                    timeout=self.timeout,
                    verify=self.verify,
                    proxies=self.proxies,
                )
                if resp.status_code in (200, 201):
                    findings.append({
                        "check": "BFLA Privilege Escalation",
                        "vulnerability": {
                            "name": "Broken Function Level Authorization (Standard User)",
                            "type": "BFLA",
                            "severity": "HIGH",
                            "endpoint": path,
                            "method": method,
                            "description": (
                                f"Standard non-admin user '{user.get('name')}' successfully accessed "
                                f"privileged endpoint {method} {path} (HTTP {resp.status_code})."
                            ),
                            "remediation": (
                                "Validate user role and function-level permissions on every request."
                            ),
                        },
                        "endpoint": {"method": method, "path": path},
                        "evidence": {
                            "status": resp.status_code,
                            "user": user.get("name"),
                            "url": url,
                            "body_preview": resp.text[:300],
                        },
                    })
                    break  # One finding per endpoint is sufficient
            except requests.RequestException:
                pass

        return findings
