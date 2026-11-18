"""
test_new_detectors.py
---------------------
Tests for BFLA, BOPLA, and Security Headers detectors.
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from bfla_detector import BFLADetector
from bopla_detector import BOPLADetector
from headers_detector import HeadersDetector
from request_utils import RequestBudget


def test_bfla_is_privileged_endpoint():
    det = BFLADetector("http://localhost:5000", budget=RequestBudget(10))
    assert det.is_privileged_endpoint("/api/v1/admin/users") is True
    assert det.is_privileged_endpoint("/internal/metrics") is True
    assert det.is_privileged_endpoint("/public/products") is False


@patch("src.bfla_detector.requests.request")
def test_bfla_detection_unauthenticated(mock_req):
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "admin console"
    mock_req.return_value = resp

    det = BFLADetector("http://localhost:5000", budget=RequestBudget(10))
    findings = det.test_endpoint("GET", "/admin/settings", [{"name": "alice", "role": "user"}], lambda u: {})
    assert len(findings) >= 1
    assert findings[0]["vulnerability"]["type"] == "BFLA"
    assert findings[0]["vulnerability"]["severity"] == "CRITICAL"


def test_bopla_sensitive_properties_leak():
    det = BOPLADetector()
    res = det.analyze_response(
        "GET",
        "/api/users/1",
        200,
        {"id": 1, "username": "alice", "password_hash": "$2b$12$e...", "is_admin": False},
    )
    assert len(res) == 1
    assert res[0]["vulnerability"]["type"] == "BOPLA"
    assert "password_hash" in res[0]["evidence"]["leaked_properties"]


def test_bopla_secret_pattern_leak():
    det = BOPLADetector()
    raw = '{"key": "AKIAIOSFODNN7EXAMPLE"}'
    res = det.analyze_response("GET", "/api/config", 200, {"key": "AKIA..."}, raw_text=raw)
    assert len(res) >= 1
    types = [f["vulnerability"]["type"] for f in res]
    assert "SECRET_LEAK" in types


@patch("src.headers_detector.requests.get")
def test_cors_wildcard_with_credentials(mock_get):
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    mock_get.return_value = resp

    det = HeadersDetector("http://localhost:5000", budget=RequestBudget(10))
    findings = det.test_cors_and_headers("/api/data")
    assert len(findings) == 1
    assert findings[0]["vulnerability"]["name"] == "CORS Misconfiguration: Wildcard with Credentials"
    assert findings[0]["vulnerability"]["severity"] == "HIGH"
