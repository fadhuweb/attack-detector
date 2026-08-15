import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.events import (
    Event, SSH_FAILED_LOGIN, SSH_INVALID_USER, SSH_ACCEPTED_LOGIN,
)
from attack_detector.detectors.window_counter import SlidingWindowCounter
from attack_detector.detectors.bruteforce import BruteForceDetector

_fail = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _fail.append(name)


def ev(etype, ip, port, ts, user="baduser"):
    e = Event(etype, ip, user=user, port=port)
    e.ingest_ts = ts
    return e


# ---- counter unit checks ----
c = SlidingWindowCounter(window_seconds=60, threshold=5)
t = 1000.0
for i in range(4):
    c.add("1.1.1.1", ts=t + i)
check("counter below threshold not over", not c.over_threshold("1.1.1.1", now=t + 4))
c.add("1.1.1.1", ts=t + 4)
check("counter at threshold is over", c.over_threshold("1.1.1.1", now=t + 4))

c2 = SlidingWindowCounter(window_seconds=10, threshold=3)
c2.add("2.2.2.2", ts=t)
c2.add("2.2.2.2", ts=t + 1)
check("counter evicts stale events", c2.count("2.2.2.2", now=t + 100) == 0)

# ---- MaxAuthTries: 3 failed_login on one port count as 3, not 1 ----
d = BruteForceDetector(window_seconds=60, threshold=5, pair_grace=3.0)
alerts = []
alerts += d.observe(ev(SSH_INVALID_USER, "9.9.9.9", 43200, 100.0))
alerts += d.observe(ev(SSH_FAILED_LOGIN, "9.9.9.9", 43200, 100.5))
alerts += d.observe(ev(SSH_FAILED_LOGIN, "9.9.9.9", 43200, 101.0))
alerts += d.observe(ev(SSH_FAILED_LOGIN, "9.9.9.9", 43200, 101.5))
# 3 failed on one port; the invalid_user paired with the first, so count is 3
check("MaxAuthTries counts each guess (3), invalid_user paired away",
      d.counter.count("9.9.9.9", now=101.5) == 3 and alerts == [])

# ---- spray: 5 connections, each an invalid_user+failed_login pair, counts 5 and fires ----
d2 = BruteForceDetector(window_seconds=60, threshold=5, pair_grace=3.0)
fired = []
base = 200.0
for i in range(5):
    port = 50000 + i
    d2.observe(ev(SSH_INVALID_USER, "8.8.8.8", port, base + i))
    fired += d2.observe(ev(SSH_FAILED_LOGIN, "8.8.8.8", port, base + i + 0.1))
check("spray of 5 pairs counts 5 and fires once",
      len(fired) == 1 and fired[0][0] == "8.8.8.8" and fired[0][1] == 5)

# ---- bare probes: invalid_user with no paired failed_login count after grace ----
# all 5 arrive at the same instant so none retire mid-loop; then one tick past
# the grace retires all 5 together and fires.
d3 = BruteForceDetector(window_seconds=60, threshold=5, pair_grace=3.0)
fired = []
base = 300.0
for i in range(5):
    d3.observe(ev(SSH_INVALID_USER, "7.7.7.7", 60000 + i, base))
mid = d3.counter.count("7.7.7.7", now=base)          # still held, nothing counted
fired += d3.tick(now=base + 4)                        # 4s > 3s grace: all retire
check("bare probes held then counted after grace",
      mid == 0 and len(fired) == 1 and fired[0][1] == 5)

# ---- a real failed_login does NOT get dropped by an unrelated invalid_user ----
d4 = BruteForceDetector(window_seconds=60, threshold=5, pair_grace=3.0)
d4.observe(ev(SSH_INVALID_USER, "6.6.6.6", 111, 400.0))       # held on port 111
d4.observe(ev(SSH_FAILED_LOGIN, "6.6.6.6", 222, 400.2))       # different port, counts
check("failed_login on a different port still counts",
      d4.counter.count("6.6.6.6", now=400.2) == 1)

# ---- accepted logins are ignored ----
d5 = BruteForceDetector()
a = d5.observe(ev(SSH_ACCEPTED_LOGIN, "5.5.5.5", 22, 500.0, user="fadhl"))
check("accepted login ignored", a == [] and d5.counter.count("5.5.5.5", now=500.0) == 0)

# ---- window expiry: 4 old + 1 new does not fire ----
d6 = BruteForceDetector(window_seconds=60, threshold=5, pair_grace=3.0)
for i in range(4):
    d6.observe(ev(SSH_FAILED_LOGIN, "4.4.4.4", 1000 + i, 600.0 + i))
fired = d6.observe(ev(SSH_FAILED_LOGIN, "4.4.4.4", 1010, 700.0))  # 100s later, old evicted
check("stale failures expire out of the window",
      fired == [] and d6.counter.count("4.4.4.4", now=700.0) == 1)

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
