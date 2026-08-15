import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.responder import (
    Responder, MemoryBackend, NftablesBackend,
)

_fail = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _fail.append(name)


# ---- mode gating ----
r = Responder("off", allowlist=["10.0.2.2"], backend=MemoryBackend(),
              log_path="/tmp/resp_test.log")
check("off does nothing", r.handle_alert("1.2.3.4", 5, "bf") == "noop-off")

r = Responder("monitor", allowlist=["10.0.2.2"], backend=MemoryBackend(),
              log_path="/tmp/resp_test.log")
check("monitor never blocks", r.handle_alert("1.2.3.4", 5, "bf") == "skipped-monitor"
      and r.blocked_ips() == [])

# ---- enforce blocks a normal IP ----
b = MemoryBackend()
r = Responder("enforce", allowlist=["10.0.2.2"], backend=b, log_path="/tmp/resp_test.log")
check("enforce blocks offender",
      r.handle_alert("192.168.50.11", 5, "bf") == "blocked"
      and b.list_blocked() == ["192.168.50.11"])

# ---- the allowlist lock: never block the admin path ----
b = MemoryBackend()
r = Responder("enforce", allowlist=["10.0.2.2"], backend=b, log_path="/tmp/resp_test.log")
check("enforce SKIPS allowlisted admin IP",
      r.handle_alert("10.0.2.2", 99, "bf") == "skipped-allowlist"
      and b.list_blocked() == [])

# ---- idempotent: blocking same IP twice does not double-apply ----
b = MemoryBackend()
r = Responder("enforce", allowlist=[], backend=b, log_path="/tmp/resp_test.log")
first = r.handle_alert("5.5.5.5", 5, "bf")
second = r.handle_alert("5.5.5.5", 8, "bf")
check("second block of same IP is a no-op",
      first == "blocked" and second == "already-blocked"
      and b.list_blocked() == ["5.5.5.5"])

# ---- unblock removes it ----
r.unblock("5.5.5.5")
check("unblock removes the IP", b.list_blocked() == [])

# ---- nftables backend emits the right commands (fake runner, no root) ----
class FakeRes:
    stdout = ""
    stderr = ""
    returncode = 0


calls = []


def fake_runner(args):
    calls.append(args)
    return FakeRes()


nb = NftablesBackend(runner=fake_runner)
nb.block("192.168.50.11")
# first call must create the table ruleset; a later call adds the element
made_table = any(a and a[0] == "-f" and "add table inet attack_detector" in a[1]
                 for a in calls)
added_elem = any(a[:3] == ["add", "element", "inet"]
                 and "blocked4" in a and "{192.168.50.11}" in a for a in calls)
check("nft creates its own table", made_table)
check("nft adds ipv4 element to blocked4 set", added_elem)

# ipv6 goes to blocked6
calls.clear()
nb2 = NftablesBackend(runner=fake_runner)
nb2.block("2001:db8::1")
added6 = any(a[:3] == ["add", "element", "inet"] and "blocked6" in a for a in calls)
check("nft routes ipv6 to blocked6 set", added6)

# unblock deletes the element
calls.clear()
nb2.unblock("2001:db8::1")
deleted = any(a[:3] == ["delete", "element", "inet"] and "blocked6" in a for a in calls)
check("nft unblock deletes the element", deleted)

# table uses priority -100 and its own name, so it can't clobber other rules
calls.clear()
nb3 = NftablesBackend(runner=fake_runner)
nb3.block("3.3.3.3")
script = next(a[1] for a in calls if a and a[0] == "-f")
check("table is named attack_detector and hooks input at priority -100",
      "table inet attack_detector" in script and "priority -100" in script
      and "saddr @blocked4 drop" in script)

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
