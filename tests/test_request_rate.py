import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.events import Event
from attack_detector.collectors.access_collector import HTTP_REQUEST
from attack_detector.detectors.request_rate import PerIPRequestDetector
from attack_detector.detectors.flood import AggregateFloodDetector

_fail = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _fail.append(name)


def req(ip, ts):
    e = Event(HTTP_REQUEST, ip)
    e.ingest_ts = ts
    return e


# ---- single-source flood trips the per-IP rule ----
d = PerIPRequestDetector(window_seconds=5, threshold=100, cooldown=30)
fired = None
t = 1000.0
for i in range(100):
    fired = d.observe(req("192.168.50.11", t + i * 0.01)) or fired
check("per-IP rule fires on single-source flood",
      fired is not None and fired[0] == "192.168.50.11")

# ---- THE contrast: distributed flood trips aggregate, NOT per-IP ----
perip = PerIPRequestDetector(window_seconds=10, threshold=50, cooldown=30)
agg = AggregateFloodDetector(window_seconds=10, threshold=400, cooldown=30)
t = 2000.0
perip_fired = None
agg_fired = None
n = 0
for r in range(4):                       # 4 requests per IP
    for ip_i in range(200):              # 200 IPs -> 800 total
        ip = f"198.51.{ip_i // 256}.{ip_i % 256}"
        ts = t + n * 0.001
        n += 1
        perip_fired = perip.observe(req(ip, ts)) or perip_fired
        agg_fired = agg.observe(req(ip, ts)) or agg_fired
check("distributed flood does NOT trip per-IP rule", perip_fired is None)
check("distributed flood DOES trip aggregate rule",
      agg_fired is not None and agg_fired[0] >= 400)

# ---- single-source flood trips BOTH ----
perip2 = PerIPRequestDetector(window_seconds=10, threshold=50, cooldown=30)
agg2 = AggregateFloodDetector(window_seconds=10, threshold=400, cooldown=30)
t = 3000.0
pf = None
af = None
for i in range(500):
    ts = t + i * 0.001
    pf = perip2.observe(req("203.0.113.9", ts)) or pf
    af = agg2.observe(req("203.0.113.9", ts)) or af
check("single-source flood trips per-IP rule", pf is not None and pf[0] == "203.0.113.9")
check("single-source flood trips aggregate rule too", af is not None)

# ---- cooldown on per-IP ----
cd = PerIPRequestDetector(window_seconds=5, threshold=10, cooldown=30)
t = 4000.0
fires = 0
for i in range(60):
    if cd.observe(req("7.7.7.7", t + i * 0.01)):
        fires += 1
check("per-IP cooldown fires once per burst", fires == 1)

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
