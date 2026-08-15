import time
from collections import defaultdict, deque


class SlidingWindowCounter:
    """Count keyed events inside a rolling time window.

    Events are counted per key (a source IP). Each observation carries its own
    timestamp; observations older than `window` seconds are dropped on every
    touch. Uses ingest time, set by the caller, not the log's own timestamp, so
    a stale or clock-skewed line cannot distort the window (day-1 decision).
    """

    def __init__(self, window_seconds, threshold):
        self.window = window_seconds
        self.threshold = threshold
        self._events = defaultdict(deque)   # key -> deque[timestamp]

    def _evict(self, key, now):
        dq = self._events[key]
        cutoff = now - self.window
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if not dq:
            del self._events[key]

    def add(self, key, ts=None):
        """Record one event for key. Returns the count in the window after
        adding. `ts` defaults to now; pass a fixed value in tests."""
        now = time.time() if ts is None else ts
        self._events[key].append(now)
        self._evict(key, now)
        return len(self._events.get(key, ()))

    def count(self, key, now=None):
        now = time.time() if now is None else now
        if key not in self._events:
            return 0
        self._evict(key, now)
        return len(self._events.get(key, ()))

    def over_threshold(self, key, now=None):
        return self.count(key, now) >= self.threshold

    def reset(self, key):
        """Clear a key's window, e.g. after firing so one burst alerts once."""
        self._events.pop(key, None)
