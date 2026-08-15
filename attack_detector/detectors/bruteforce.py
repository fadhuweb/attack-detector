import time

from ..events import SSH_FAILED_LOGIN, SSH_INVALID_USER
from .window_counter import SlidingWindowCounter


class BruteForceDetector:
    """Count failed SSH auth per source IP in a sliding window; fire above a
    threshold.

    Counting rule (confirmed against real sshd output):
      - every ssh_failed_login counts as one guess. A single connection that
        trips MaxAuthTries emits several of these on one port; each is a real
        guess and each counts.
      - an ssh_invalid_user counts only when no ssh_failed_login with the same
        (ip, port) follows within a short grace period. sshd emits both lines
        for a nonexistent user, so counting both would double-count; counting
        only failed_login would miss a probe that never attempts a password.

    Implementation: ssh_failed_login is counted immediately. ssh_invalid_user is
    held for `pair_grace` seconds keyed on (ip, port); if a failed_login on the
    same key arrives in that time, the held invalid_user is dropped (the pair is
    one attempt). If the grace passes with no failed_login, the invalid_user is
    counted (a bare probe).
    """

    def __init__(self, window_seconds=60, threshold=5, pair_grace=3.0):
        self.counter = SlidingWindowCounter(window_seconds, threshold)
        self.pair_grace = pair_grace
        self._pending = {}   # (ip, port) -> ts of a held invalid_user

    def _flush_pending(self, now):
        """Count any held invalid_user whose grace has elapsed with no pairing
        failed_login. Returns a list of (ip, count) that crossed threshold."""
        fired = []
        expired = [k for k, ts in self._pending.items()
                   if now - ts >= self.pair_grace]
        for key in expired:
            ip, _port = key
            ts = self._pending.pop(key)
            count = self.counter.add(ip, ts=now)
            if count >= self.counter.threshold:
                fired.append((ip, count))
                self.counter.reset(ip)
        return fired

    def observe(self, event):
        """Feed one Event. Returns a list of alerts (ip, count, reason) that
        fired as a result. Most calls return an empty list."""
        now = event.ingest_ts or time.time()
        alerts = []

        # first, retire any held probes whose grace has passed
        for ip, count in self._flush_pending(now):
            alerts.append((ip, count, "failed SSH logins"))

        if event.etype == SSH_FAILED_LOGIN:
            key = (event.source_ip, event.port)
            # this failed_login pairs with a held invalid_user on the same
            # (ip, port): drop the held probe, it was the same attempt
            self._pending.pop(key, None)
            count = self.counter.add(event.source_ip, ts=now)
            if count >= self.counter.threshold:
                alerts.append((event.source_ip, count, "failed SSH logins"))
                self.counter.reset(event.source_ip)

        elif event.etype == SSH_INVALID_USER:
            # hold it; a paired failed_login may arrive shortly
            self._pending[(event.source_ip, event.port)] = now

        return alerts

    def tick(self, now=None):
        """Call periodically so held probes still retire when no new events
        arrive. Returns any alerts that fired."""
        now = time.time() if now is None else now
        return [(ip, count, "failed SSH logins")
                for ip, count in self._flush_pending(now)]
