import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from logger import ForensicLogger


def test_http_reproduction_stringifies_structured_payload():
    block = ForensicLogger._build_http_block(
        {'endpoint': '/transfer', 'method': 'POST', 'parameter': 'account'},
        {'payload': {'id': 7, 'role': 'admin'}, 'status_code': 200},
    )

    assert block['request']['reproduction'].startswith('[param] account = {')
    assert "'role': 'admin'" in block['request']['reproduction']


class TestEvidenceFilenames:
    """Evidence paths land in CI artifact directories, so they must be safe to
    glob. Finding types include 'BOLA/IDOR' and 'OAuth Flaw' — a separator and a
    space that both make the raw value awkward in a shell."""

    def test_slash_and_space_are_normalised(self, tmp_path):
        logger = ForensicLogger(str(tmp_path))
        path = logger.log_finding({'type': 'OAuth Flaw', 'check': 'x', 'severity': 'HIGH'})
        name = os.path.basename(path)
        assert ' ' not in name
        assert 'OAuth_Flaw' in name

    def test_slash_type_is_normalised(self, tmp_path):
        logger = ForensicLogger(str(tmp_path))
        path = logger.log_finding({'type': 'BOLA/IDOR', 'check': 'x', 'severity': 'HIGH'})
        assert 'BOLA_IDOR' in os.path.basename(path)

    def test_missing_type_falls_back(self, tmp_path):
        logger = ForensicLogger(str(tmp_path))
        path = logger.log_finding({'check': 'x', 'severity': 'HIGH'})
        assert 'UNKNOWN' in os.path.basename(path)

    def test_null_type_falls_back(self, tmp_path):
        """`.get('type', 'UNKNOWN')` returns None when the key exists as null."""
        logger = ForensicLogger(str(tmp_path))
        path = logger.log_finding({'type': None, 'check': 'x', 'severity': 'HIGH'})
        assert 'UNKNOWN' in os.path.basename(path)
