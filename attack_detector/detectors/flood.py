import time
from collections import deque


class AggregateFloodDetector:
    """Detect a volumetric / distributed flood by counting ALL requests in a
    window, ignoring the source IP.

    This is the shape a per-IP rule cannot catch: a distributed flood spreads
    across many source IPs, so no single IP crosses a per-IP threshold, but the
    total volume is far above normal. This detector watches the total.

    It also reports the top source IPs in the window, so an alert can say who is
    contributing most, even though the fire decision is on the aggregate.
    """

    def __init__(self, window_seconds=10, threshold=2000, cooldown=30):
        self.window = window_seconds
        self.threshold = threshold
        self.cooldown = cooldown          # seconds to wait before firing again
        self._events = deque()             # (ts, source_ip)
        self._last_fired = 0.0

    def _evict(self, now):
        cutoff = now - self.window
        while self._events and self._events[0][0] <= cutoff:
            self._events.popleft()

    def observe(self, event):
        """Feed one request Event. Returns an alert tuple
        (count, top_sources) when the aggregate crosses the threshold and the
        cooldown has passed, otherwise None."""
        now = event.ingest_ts or time.time()
        self._events.append((now, event.source_ip))
        self._evict(now)
        count = len(self._events)
        if count >= self.threshold and (now - self._last_fired) >= self.cooldown:
            self._last_fired = now
            return (count, self._top_sources())
        return None

    def count(self, now=None):
        now = time.time() if now is None else now
        self._evict(now)
        return len(self._events)

    def _top_sources(self, k=5):
        tally = {}
        for _ts, ip in self._events:
            tally[ip] = tally.get(ip, 0) + 1
        ranked = sorted(tally.items(), key=lambda kv: kv[1], reverse=True)
        return ranked[:k]
