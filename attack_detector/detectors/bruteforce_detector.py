"""STALE SCAFFOLD -- rewritten on day 2. Do not import.

Consumes dict-shaped events that no collector produces any more, counts only
failed logins, and has no per-connection dedupe. The real per-IP sliding-window
engine replaces this file wholesale.
"""

import time
from collections import defaultdict, deque


class BruteForceDetector:
    def __init__(self, responder, threshold: int = 5, window: int = 60):
        self.responder = responder
        self.threshold = threshold
        self.window = window
        self._counters = defaultdict(lambda: deque())

    def handle_event(self, event: dict):
        if event.get("type") != "ssh_failed":
            return
        ip = event.get("src_ip") or "unknown"
        now = time.time()
        dq = self._counters[ip]
        dq.append(now)
        # drop older than window
        while dq and dq[0] < now - self.window:
            dq.popleft()
        if len(dq) >= self.threshold:
            # fire alert
            self.responder.alert(
                rule="brute_force",
                src_ip=ip,
                detail={"count": len(dq), "window": self.window},
            )
            dq.clear()
