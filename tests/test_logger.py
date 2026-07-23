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
