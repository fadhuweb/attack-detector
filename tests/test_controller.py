import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.responder import Responder, MemoryBackend
from attack_detector.detectors.bruteforce import BruteForceDetector
from attack_detector.alerting import Alerter
from attack_detector.controller import Controller

_fail = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _fail.append(name)


def make(mode, allowlist):
    d = tempfile.mkdtemp()
    backend = MemoryBackend()
    responder = Responder(mode, allowlist, backend,
                          log_path=os.path.join(d, "resp.log"))
    detector = BruteForceDetector(window_seconds=60, threshold=5)
    alerter = Alerter(path=os.path.join(d, "alerts.log"))
    ctl = Controller(responder, detector, alerter,
                     state_path=os.path.join(d, "control.json"),
                     command_path=os.path.join(d, "commands.jsonl"),
                     status_path=os.path.join(d, "status.json"),
                     poll_interval=0.05)
    ctl._log_path = os.path.join(d, "controller.log")
    return d, responder, detector, ctl


# ---- hot mode change monitor -> enforce (allowlist set) ----
d, responder, detector, ctl = make("monitor", ["10.0.2.2"])
ok, msg = ctl.set_mode("enforce")
check("monitor -> enforce with allowlist succeeds",
      ok and responder.mode == "enforce")

# ---- enforce -> off ----
ok, msg = ctl.set_mode("off")
check("enforce -> off succeeds", ok and responder.mode == "off")

# ---- the runtime guard: cannot arm enforce with empty allowlist ----
d, responder, detector, ctl = make("monitor", [])
ok, msg = ctl.set_mode("enforce")
check("enforce refused at runtime when allowlist empty",
      not ok and responder.mode == "monitor")

# ---- invalid mode rejected ----
ok, msg = ctl.set_mode("banana")
check("invalid mode rejected", not ok and responder.mode == "monitor")

# ---- hot reload via the state file ----
d, responder, detector, ctl = make("monitor", ["10.0.2.2"])
with open(ctl.state_path, "w") as f:
    json.dump({"mode": "enforce"}, f)
ctl.poll_once()
check("poll picks up mode change from state file", responder.mode == "enforce")

# ---- unblock command via the command file ----
d, responder, detector, ctl = make("enforce", ["10.0.2.2"])
responder.handle_alert("192.168.50.11", 5, "bf")            # block it first
before = responder.blocked_ips()
with open(ctl.command_path, "w") as f:
    f.write(json.dumps({"action": "unblock", "ip": "192.168.50.11"}) + "\n")
ctl.poll_once()
after = responder.blocked_ips()
check("unblock command releases the IP",
      before == ["192.168.50.11"] and after == [])

# ---- manual block command respects the allowlist ----
d, responder, detector, ctl = make("enforce", ["10.0.2.2"])
ok, msg = ctl.run_command({"action": "block", "ip": "10.0.2.2"})
check("manual block refuses an allowlisted IP",
      not ok and responder.blocked_ips() == [])

# ---- manual block of a normal IP works ----
ok, msg = ctl.run_command({"action": "block", "ip": "8.8.8.8"})
check("manual block of a normal IP works",
      ok and responder.blocked_ips() == ["8.8.8.8"])

# ---- command file is cleared after draining (no double-run) ----
d, responder, detector, ctl = make("enforce", ["10.0.2.2"])
with open(ctl.command_path, "w") as f:
    f.write(json.dumps({"action": "block", "ip": "9.9.9.9"}) + "\n")
ctl.poll_once()
first = responder.blocked_ips()
responder.unblock("9.9.9.9")            # remove it
ctl.poll_once()                          # poll again: stale command must NOT re-block
second = responder.blocked_ips()
check("drained command does not run twice",
      first == ["9.9.9.9"] and second == [])

# ---- status file is written and well-formed ----
d, responder, detector, ctl = make("monitor", ["10.0.2.2"])
status = ctl.write_status()
with open(ctl.status_path) as f:
    ondisk = json.load(f)
check("status file has mode, blocked, allowlist, threshold",
      ondisk["mode"] == "monitor" and ondisk["allowlist"] == ["10.0.2.2"]
      and ondisk["threshold"] == 5 and "blocked" in ondisk)

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
