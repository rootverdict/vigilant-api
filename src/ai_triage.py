"""
ai_triage.py
------------
AI-powered vulnerability triage, false-positive elimination, and remediation
synthesis for Vigilant-API using Google Gemini.

Reads GEMINI_API_KEY from environment variables (checking both process-level
os.environ and Windows user-level registry if needed).

Features:
  1. False-Positive Analysis: Inspects HTTP evidence diffs and determines confidence.
  2. Business Impact: Translates raw technical findings into executive risk narratives.
  3. Remediation Code: Generates tailored code patches for the target stack.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def get_gemini_api_key() -> str | None:
    """Retrieve GEMINI_API_KEY from os.environ or Windows user environment."""
    key = os.environ.get("GEMINI_API_KEY")
    if key and key.strip():
        return key.strip()

    # Fallback for Windows where user-level env vars may not propagate to child shells
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as reg_key:
                val, _ = winreg.QueryValueEx(reg_key, "GEMINI_API_KEY")
                if val and str(val).strip():
                    return str(val).strip()
        except Exception:
            pass

    return None


class GeminiAITriage:
    """Performs intelligent triage on scanner findings via Google Gemini API."""

    DEFAULT_MODEL = "gemini-3.5-flash"
    FALLBACK_MODELS = ["gemini-3.5-flash-lite"]

    def __init__(self, api_key: str | None = None, model: str = DEFAULT_MODEL):
        if api_key is not None:
            self.api_key = api_key
        else:
            self.api_key = get_gemini_api_key() or ""
        self.model = model

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def analyze_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """
        Analyze an individual security finding using Gemini.
        Returns a dict containing:
          - is_valid: bool
          - confidence: 'HIGH' | 'MEDIUM' | 'LOW'
          - reasoning: str
          - executive_summary: str
          - suggested_code_fix: str
        """
        if not self.is_available:
            return {
                "is_valid": True,
                "confidence": "UNKNOWN",
                "reasoning": "AI triage skipped: GEMINI_API_KEY not configured.",
                "executive_summary": finding.get("vulnerability", {}).get("description", ""),
                "suggested_code_fix": finding.get("vulnerability", {}).get("remediation", ""),
            }

        prompt = self._build_prompt(finding)

        try:
            response_text = self._call_gemini(prompt)
            parsed = self._extract_json(response_text)
            if parsed:
                return parsed
        except Exception as e:
            return {
                "is_valid": True,
                "confidence": "ERROR",
                "reasoning": f"AI triage request failed: {e}",
                "executive_summary": finding.get("vulnerability", {}).get("description", ""),
                "suggested_code_fix": finding.get("vulnerability", {}).get("remediation", ""),
            }

        return {
            "is_valid": True,
            "confidence": "MEDIUM",
            "reasoning": "Unable to parse AI response.",
            "executive_summary": finding.get("vulnerability", {}).get("description", ""),
            "suggested_code_fix": finding.get("vulnerability", {}).get("remediation", ""),
        }

    def triage_findings(self, findings: list[dict[str, Any]], verbose: bool = False) -> list[dict[str, Any]]:
        """Run AI triage across all findings and attach the 'ai_analysis' field."""
        if not self.is_available:
            if verbose:
                print("  [AI] GEMINI_API_KEY not found. Skipping AI triage.")
            return findings

        if verbose:
            print(f"  [AI] Triaging {len(findings)} finding(s) with Gemini ({self.model})...")

        for finding in findings:
            analysis = self.analyze_finding(finding)
            finding["ai_analysis"] = analysis
            if verbose:
                valid_str = "VALID" if analysis.get("is_valid") else "FALSE_POSITIVE"
                conf = analysis.get("confidence")
                chk = (
                    finding.get("check")
                    or finding.get("vulnerability", {}).get("check")
                    or finding.get("vulnerability", {}).get("name")
                    or "Unknown Check"
                )
                reason = analysis.get("reasoning", "")[:70]
                print(f"    - [{valid_str} | {conf}] {chk}: {reason}...")

        return findings

    def _build_prompt(self, finding: dict[str, Any]) -> str:
        check = finding.get("check", "Unknown")
        vuln = finding.get("vulnerability", {})
        evidence = finding.get("evidence", {})
        endpoint = finding.get("endpoint", {})

        return f"""You are an elite AppSec Engineer analyzing an automated API scanner result.
Determine if this finding is a true positive vulnerability or a false positive
(e.g. error masked as 200, soft 404, honeypot, or standard public endpoint).

### Finding Details:
- Check Name: {check}
- Reported Vulnerability: {vuln.get('name')}
- Reported Severity: {vuln.get('severity')}
- Description: {vuln.get('description')}
- Endpoint: {endpoint.get('method', '')} {endpoint.get('path', '')}

### Evidence:
{json.dumps(evidence, indent=2, default=str)[:3000]}

### Task:
Respond ONLY with a valid JSON object with the following schema:
{{
  "is_valid": true or false,
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "reasoning": "Clear 2-3 sentence technical reason verifying or refuting based on evidence",
  "executive_summary": "1-2 sentence high-level business impact description for executives",
  "suggested_code_fix": "Concrete, production-ready code snippet fixing this root cause"
}}
"""

    def _call_gemini(self, prompt: str) -> str:
        models_to_try = [self.model] + [m for m in self.FALLBACK_MODELS if m != self.model]
        last_error = None

        for model_name in models_to_try:
            for _attempt in range(2):
                url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{model_name}:generateContent?key={self.api_key}"
                )
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.1,
                        "responseMimeType": "application/json",
                    },
                }

                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )

                try:
                    with urllib.request.urlopen(req, timeout=25) as resp:
                        resp_data = json.loads(resp.read().decode("utf-8"))
                        candidates = resp_data.get("candidates", [])
                        if candidates:
                            parts = candidates[0].get("content", {}).get("parts", [])
                            if parts:
                                return parts[0].get("text", "")
                        return ""
                except (urllib.error.HTTPError, TimeoutError, OSError) as e:
                    last_error = e
                    time.sleep(1.0)
                    continue

        if last_error:
            raise last_error
        return ""

    def _extract_json(self, text: str) -> dict[str, Any] | None:
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
        return None
