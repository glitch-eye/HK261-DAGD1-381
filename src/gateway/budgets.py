"""Thread-safe request and rate budgets shared by gateway adapters."""
from __future__ import annotations
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

@dataclass(frozen=True)
class BudgetLimits:
    max_requests_per_run: int = 5000
    rate_per_second: int = 10

class BudgetTracker:
    """Tracks per-run request counts and per-operation rolling rate limits."""
    def __init__(self, limits: BudgetLimits | None = None, *, clock=time.monotonic) -> None:
        self.limits = limits or BudgetLimits()
        self._clock = clock
        self._counts: dict[str, int] = defaultdict(int)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def consume(self, run_id: str | None, operation_id: str, *,
                max_requests_per_run: int | None = None,
                rate_per_second: int | None = None) -> tuple[bool, str]:
        run_key = run_id or "__default__"
        count_limit = max_requests_per_run or self.limits.max_requests_per_run
        rate_limit = rate_per_second or self.limits.rate_per_second
        now = self._clock()
        with self._lock:
            if self._counts[run_key] >= count_limit:
                return False, "budget_exceeded"
            bucket = self._events[operation_id]
            while bucket and now - bucket[0] >= 1.0:
                bucket.popleft()
            if len(bucket) >= rate_limit:
                return False, "rate_limit_exceeded"
            self._counts[run_key] += 1
            bucket.append(now)
            return True, "within_budget"

    def count(self, run_id: str | None) -> int:
        with self._lock:
            return self._counts[run_id or "__default__"]

    def reset(self, run_id: str | None) -> None:
        with self._lock:
            self._counts.pop(run_id or "__default__", None)
