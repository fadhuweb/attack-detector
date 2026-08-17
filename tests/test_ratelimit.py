import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.responder import Responder, MemoryBackend, NftablesBackend

_fail = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _fail.append(name)


# ---- mode gating ----
r = Responder("off", allowlist=["10.0.2.2"], backend=MemoryBackend(),
              log_path="/tmp/rl_test.log")
check("off does nothing", r.handle_flood("1.2.3.4", 200, "flood", 20) == "noop-off")

r = Responder("monitor", allowlist=["10.0.2.2"], backend=MemoryBackend(),
              log_path="/tmp/rl_test.log")
check("monitor never limits",
      r.handle_flood("1.2.3.4", 200, "flood", 20) == "skipped-monitor"
      and r.limited_ips() == [])

# ---- enforce rate-limits an offender ----
b = MemoryBackend()
r = Responder("enforce", allowlist=["10.0.2.2"], backend=b, log_path="/tmp/rl_test.log")
res = r.handle_flood("192.168.50.11", 200, "flood", 20)
check("enforce rate-limits offender",
      res == "limited" and b.list_limited() == [("192.168.50.11", 20)])

# ---- allowlist lock: never limit the admin path ----
b = MemoryBackend()
r = Responder("enforce", allowlist=["10.0.2.2"], backend=b, log_path="/tmp/rl_test.log")
res = r.handle_flood("10.0.2.2", 999, "flood", 20)
check("enforce SKIPS allowlisted admin IP",
      res == "skipped-allowlist" and b.list_limited() == [])

# ---- idempotent ----
b = MemoryBackend()
r = Responder("enforce", allowlist=[], backend=b, log_path="/tmp/rl_test.log")
first = r.handle_flood("5.5.5.5", 200, "flood", 20)
second = r.handle_flood("5.5.5.5", 400, "flood", 20)
check("second limit of same IP is a no-op",
      first == "limited" and second == "already-limited"
      and b.list_limited() == [("5.5.5.5", 20)])

# ---- unlimit removes it ----
r.unlimit("5.5.5.5")
check("unlimit removes the IP", b.list_limited() == [])

# ---- nftables backend emits a `limit rate over N/second drop` rule ----
class FakeRes:
    stdout = ""
    stderr = ""
    returncode = 0


calls = []


def fake_runner(args):
    calls.append(args)
    return FakeRes()


nb = NftablesBackend(runner=fake_runner)
nb.rate_limit("192.168.50.11", 25)
limit_rule = None
for a in calls:
    if a[:3] == ["add", "rule", "inet"] and "ratelimit" in a:
        limit_rule = a
check("nft adds a ratelimit rule for the ip",
      limit_rule is not None and "192.168.50.11" in limit_rule)
check("rule limits rate over 25/second and drops",
      limit_rule is not None and "over" in limit_rule
      and "25/second" in limit_rule and "drop" in limit_rule)
check("rule carries an adlimit comment tag for later removal",
      any("adlimit:192.168.50.11" in str(x) for x in limit_rule))

# ---- ratelimit chain is separate from the block chain ----
calls.clear()
nb2 = NftablesBackend(runner=fake_runner)
nb2.rate_limit("3.3.3.3", 10)
script = next((a[1] for a in calls if a and a[0] == "-f"), "")
check("table defines a separate ratelimit chain",
      "chain inet attack_detector ratelimit" in script)

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
