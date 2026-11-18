"""
test_ai_triage.py
------------------
Unit tests for Gemini AI triage and false-positive filtering module.
"""

from unittest.mock import MagicMock, patch
from src.ai_triage import GeminiAITriage


def test_ai_triage_not_available():
    triage = GeminiAITriage(api_key="")
    assert not triage.is_available
    res = triage.analyze_finding({"check": "BOLA"})
    assert res["is_valid"] is True
    assert res["confidence"] == "UNKNOWN"


@patch("src.ai_triage.urllib.request.urlopen")
def test_ai_triage_successful_analysis(mock_urlopen):
    mock_response = MagicMock()
    fake_json = (
        '{"is_valid": true, "confidence": "HIGH", "reasoning": "Real BOLA", '
        '"executive_summary": "Data breach risk", "suggested_code_fix": "check_user()"}'
    )
    mock_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": fake_json}]
                }
            }
        ]
    }
    import json
    mock_response.read.return_value = json.dumps(mock_payload).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    triage = GeminiAITriage(api_key="test_key")
    res = triage.analyze_finding({
        "check": "BOLA",
        "vulnerability": {"name": "BOLA", "severity": "HIGH", "description": "test"},
        "endpoint": {"method": "GET", "path": "/api/users/1"},
        "evidence": {"status": 200}
    })

    assert res["is_valid"] is True
    assert res["confidence"] == "HIGH"
    assert res["reasoning"] == "Real BOLA"
    assert res["suggested_code_fix"] == "check_user()"


@patch("src.ai_triage.urllib.request.urlopen")
def test_ai_triage_list_findings(mock_urlopen):
    mock_response = MagicMock()
    fake_json = (
        '{"is_valid": false, "confidence": "HIGH", "reasoning": "Error message in 200 response", '
        '"executive_summary": "Safe", "suggested_code_fix": ""}'
    )
    mock_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": fake_json}]
                }
            }
        ]
    }
    import json
    mock_response.read.return_value = json.dumps(mock_payload).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    triage = GeminiAITriage(api_key="test_key")
    findings = [{"check": "SSRF", "vulnerability": {}, "evidence": {}}]
    res = triage.triage_findings(findings)
    assert len(res) == 1
    assert "ai_analysis" in res[0]
    assert res[0]["ai_analysis"]["is_valid"] is False
