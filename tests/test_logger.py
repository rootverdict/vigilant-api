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
    glob. Finding types include 'BOLA/IDOR' and 'OAuth Flaw' - a separator and a
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


class TestFindingAccessors:
    """get_findings() returns findings in log order; sorted_findings() returns
    them severity-first. The scanner uses the sorted view for reports, so the
    insertion-order accessor needs its own test."""

    def _logger(self, tmp_path):
        logger = ForensicLogger(str(tmp_path))
        for severity in ('LOW', 'CRITICAL', 'MEDIUM'):
            logger.log_finding({'type': 'SSRF', 'check': severity, 'severity': severity})
        return logger

    def test_get_findings_preserves_log_order(self, tmp_path):
        logger = self._logger(tmp_path)
        order = [f['vulnerability']['severity'] for f in logger.get_findings()]
        assert order == ['LOW', 'CRITICAL', 'MEDIUM']

    def test_sorted_findings_orders_by_severity(self, tmp_path):
        logger = self._logger(tmp_path)
        order = [f['vulnerability']['severity'] for f in logger.sorted_findings()]
        assert order == ['CRITICAL', 'MEDIUM', 'LOW']

    def test_summary_counts_match_logged_findings(self, tmp_path):
        summary = self._logger(tmp_path).get_summary()
        assert summary['CRITICAL'] == 1 and summary['MEDIUM'] == 1 and summary['LOW'] == 1
        assert summary['HIGH'] == 0

    def test_unknown_severity_is_counted_not_dropped(self, tmp_path):
        logger = ForensicLogger(str(tmp_path))
        logger.log_finding({'type': 'SSRF', 'check': 'x', 'severity': 'WEIRD'})
        assert logger.get_summary()['WEIRD'] == 1
