import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.events import Event
from attack_detector.collectors.access_collector import parse_line, HTTP_REQUEST
from attack_detector.detectors.flood import AggregateFloodDetector
from attack_detector.detectors.window_counter import SlidingWindowCounter

_fail = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _fail.append(name)


def req(ip, ts):
    e = Event(HTTP_REQUEST, ip)
    e.ingest_ts = ts
    return e


# ---- access-log parser ----
line = ('192.168.50.11 - - [14/Aug/2026:22:10:01 +0000] '
        '"GET /index.html HTTP/1.1" 200 612 "-" "curl/8.0"')
e = parse_line(line)
check("parses nginx combined line",
      e and e.etype == HTTP_REQUEST and e.source_ip == "192.168.50.11"
      and e.method == "GET")

e = parse_line('malformed nonsense line')
check("ignores malformed line", e is None)

e = parse_line('10.0.0.5 - - [14/Aug/2026:22:10:02 +0000] "POST /login HTTP/1.1" 403 0 "-" "-"')
check("parses POST with 403", e and e.method == "POST" and e.source_ip == "10.0.0.5")

# ---- aggregate fires on total volume from ONE source ----
d = AggregateFloodDetector(window_seconds=10, threshold=100, cooldown=30)
fired = None
t = 1000.0
for i in range(100):
    fired = d.observe(req("192.168.50.11", t + i * 0.01)) or fired
check("aggregate fires on single-source flood past threshold",
      fired is not None and fired[0] >= 100)

# ---- the key case: DISTRIBUTED flood that no per-IP rule would catch ----
# 500 requests spread across 250 IPs = 2 requests each. A per-IP threshold of
# even 5 never trips. The aggregate must still fire.
agg = AggregateFloodDetector(window_seconds=10, threshold=400, cooldown=30)
perip = SlidingWindowCounter(window_seconds=10, threshold=5)
t = 2000.0
agg_fired = None
perip_ever_over = False
n = 0
for round_i in range(2):                 # 2 requests per IP
    for ip_i in range(250):              # 250 distinct IPs
        ip = f"10.{ip_i // 256}.{ip_i % 256}.1"
        ts = t + n * 0.001
        n += 1
        agg_fired = agg.observe(req(ip, ts)) or agg_fired
        perip.add(ip, ts=ts)
        if perip.over_threshold(ip, now=ts):
            perip_ever_over = True
check("distributed flood: per-IP rule NEVER fires", not perip_ever_over)
check("distributed flood: aggregate rule DOES fire",
      agg_fired is not None and agg_fired[0] >= 400)

# ---- normal traffic below the ceiling does not fire ----
quiet = AggregateFloodDetector(window_seconds=10, threshold=2000, cooldown=30)
t = 3000.0
q_fired = None
for i in range(50):                      # only 50 requests, ceiling is 2000
    q_fired = quiet.observe(req("192.168.50.20", t + i * 0.1)) or q_fired
check("normal traffic does not fire", q_fired is None)

# ---- stale requests fall out of the window ----
w = AggregateFloodDetector(window_seconds=10, threshold=5, cooldown=0)
for i in range(4):
    w.observe(req("1.1.1.1", 4000.0 + i))
check("old requests evicted from window", w.count(now=4100.0) == 0)

# ---- cooldown prevents alert spam ----
cd = AggregateFloodDetector(window_seconds=10, threshold=10, cooldown=30)
t = 5000.0
fires = 0
for i in range(40):                      # keep flooding past threshold
    if cd.observe(req("2.2.2.2", t + i * 0.1)):
        fires += 1
check("cooldown fires once, not per request", fires == 1)

# ---- top sources reported ----
ts_det = AggregateFloodDetector(window_seconds=10, threshold=5, cooldown=0)
t = 6000.0
res = None
for ip, times in [("9.9.9.9", 4), ("8.8.8.8", 2), ("7.7.7.7", 1)]:
    for _ in range(times):
        res = ts_det.observe(req(ip, t)) or res
        t += 0.001
check("alert reports the heaviest source first",
      res is not None and res[1][0][0] == "9.9.9.9")

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
