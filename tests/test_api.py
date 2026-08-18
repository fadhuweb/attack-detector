import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.api.server import create_app

_fail = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _fail.append(name)


d = tempfile.mkdtemp()
status_path = os.path.join(d, "status.json")
state_path = os.path.join(d, "control.json")
cmd_path = os.path.join(d, "commands.jsonl")
alert_path = os.path.join(d, "alerts.log")

# seed status + alerts
with open(status_path, "w") as f:
    json.dump({"mode": "monitor", "blocked": ["1.2.3.4"], "limited": [],
               "allowlist": ["10.0.2.2"], "threshold": 5}, f)
with open(alert_path, "w") as f:
    f.write("2026-01-01 00:00:00 ALERT rule=bruteforce src=9.9.9.9 count=6\n")

app = create_app(status_path, state_path, cmd_path, alert_path, token="secret")
c = app.test_client()

# ---- health needs no token ----
r = c.get("/api/health")
check("health ok without token", r.status_code == 200 and r.get_json()["ok"])

# ---- status requires token ----
r = c.get("/api/status")
check("status without token is 401", r.status_code == 401)

r = c.get("/api/status", headers={"X-Auth-Token": "secret"})
check("status with token returns the status",
      r.status_code == 200 and r.get_json()["mode"] == "monitor"
      and r.get_json()["blocked"] == ["1.2.3.4"])

# ---- wrong token rejected ----
r = c.get("/api/status", headers={"X-Auth-Token": "wrong"})
check("wrong token rejected", r.status_code == 401)

# ---- alerts endpoint ----
r = c.get("/api/alerts?n=10", headers={"X-Auth-Token": "secret"})
check("alerts returns recent lines",
      r.status_code == 200 and len(r.get_json()["alerts"]) == 1
      and "bruteforce" in r.get_json()["alerts"][0])

# ---- set mode writes the control file ----
r = c.post("/api/mode", json={"mode": "enforce"}, headers={"X-Auth-Token": "secret"})
check("set mode returns ok", r.status_code == 200 and r.get_json()["ok"])
with open(state_path) as f:
    check("mode written to control.json", json.load(f)["mode"] == "enforce")

# ---- invalid mode rejected ----
r = c.post("/api/mode", json={"mode": "banana"}, headers={"X-Auth-Token": "secret"})
check("invalid mode is 400", r.status_code == 400)

# ---- unblock queues a command ----
r = c.post("/api/unblock", json={"ip": "1.2.3.4"}, headers={"X-Auth-Token": "secret"})
check("unblock returns ok", r.status_code == 200)
with open(cmd_path) as f:
    lines = [json.loads(x) for x in f if x.strip()]
check("unblock command queued",
      any(c["action"] == "unblock" and c["ip"] == "1.2.3.4" for c in lines))

# ---- unlimit queues a command ----
r = c.post("/api/unlimit", json={"ip": "5.5.5.5"}, headers={"X-Auth-Token": "secret"})
with open(cmd_path) as f:
    lines = [json.loads(x) for x in f if x.strip()]
check("unlimit command queued",
      any(c["action"] == "unlimit" and c["ip"] == "5.5.5.5" for c in lines))

# ---- unblock without ip is 400 ----
r = c.post("/api/unblock", json={}, headers={"X-Auth-Token": "secret"})
check("unblock without ip is 400", r.status_code == 400)

# ---- missing status file returns 503, not a crash ----
d2 = tempfile.mkdtemp()
app2 = create_app(os.path.join(d2, "nope.json"),
                  os.path.join(d2, "c.json"),
                  os.path.join(d2, "cmd.jsonl"),
                  os.path.join(d2, "a.log"), token=None)
r = app2.test_client().get("/api/status")
check("missing status returns 503", r.status_code == 503)

# ---- no token configured: endpoints open (localhost-only deployment) ----
r = app2.test_client().get("/api/alerts")
check("no-token mode allows access", r.status_code == 200)

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
