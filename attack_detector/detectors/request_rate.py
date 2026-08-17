import time

from .window_counter import SlidingWindowCounter


class PerIPRequestDetector:
    """Count http requests per source IP in a window; fire when one IP crosses
    the threshold. This is the single-source high-rate flood rule.

    It sits alongside the aggregate flood detector to make the contrast visible:
    a distributed flood trips the aggregate but NOT this per-IP rule, because no
    single IP is individually busy. A single-source flood trips both.
    """

    def __init__(self, window_seconds=5, threshold=100, cooldown=30):
        self.counter = SlidingWindowCounter(window_seconds, threshold)
        self.cooldown = cooldown
        self._last_fired = {}   # ip -> ts

    def observe(self, event):
        """Feed one request Event. Returns (ip, count) if this IP crossed the
        threshold and its cooldown passed, else None."""
        now = event.ingest_ts or time.time()
        count = self.counter.add(event.source_ip, ts=now)
        if count >= self.counter.threshold:
            last = self._last_fired.get(event.source_ip, 0)
            if now - last >= self.cooldown:
                self._last_fired[event.source_ip] = now
                return (event.source_ip, count)
        return None

    def count(self, ip, now=None):
        return self.counter.count(ip, now)
