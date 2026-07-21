"""Shared request controls for scanner detectors."""


class RequestBudget:
    """A small shared counter that caps requests made by one scan."""

    def __init__(self, maximum: int = 1000):
        if maximum < 1:
            raise ValueError('max_requests must be at least 1')
        self.maximum = maximum
        self.used = 0
        self.exhausted = False

    def consume(self) -> bool:
        if self.used >= self.maximum:
            self.exhausted = True
            return False
        self.used += 1
        return True

    @property
    def remaining(self) -> int:
        return max(self.maximum - self.used, 0)
