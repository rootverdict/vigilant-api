import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from request_utils import RequestBudget


def test_budget_stops_at_hard_limit():
    budget = RequestBudget(2)
    assert budget.consume()
    assert budget.consume()
    assert not budget.consume()
    assert budget.used == 2
    assert budget.exhausted is True


def test_budget_reports_remaining_requests():
    budget = RequestBudget(3)
    budget.consume()
    assert budget.remaining == 2


def test_budget_rejects_non_positive_limit():
    with pytest.raises(ValueError, match='at least 1'):
        RequestBudget(0)
