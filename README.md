# attack-detector

A lightweight intrusion detection and response system for a single Linux server.
It watches authentication logs, the web-server access log, and the live TCP
connection table, detects five common attack patterns, and responds, either by
alerting only (monitor) or by blocking offenders in the firewall (enforce).

It ships with a self-contained demo: a fake logistics company ("Northwind
Freight") whose shipment-tracking site is taken down by a real attack and kept
online by the detector, controllable from a phone.

---

## What it does

The engine runs as a systemd service and reads three live sources:

- **`/var/log/auth.log`** for SSH authentication (brute-force detection).
- **the nginx access log** for HTTP request volume (flood detection).
- **the kernel connection table via `ss`** for connection-level attacks
  (SYN flood and Slowloris), which never touch an application log.

When a rule fires it writes an alert. In enforce mode it also acts: a full
firewall block for connection-holding and brute-force attackers, a rate-limit
for high-volume single-source floods so a shared address is slowed rather than
cut off. Your own admin path is on an allowlist and is never blocked.

### The five detectors

| Rule | Source | Fires when | Enforce action |
|------|--------|-----------|----------------|
| Brute force | auth log | > 5 failed logins from one IP in 60s | block IP |
| Aggregate flood | nginx log | > 2000 total requests in 10s (distributed) | alert |
| Per-IP request flood | nginx log | > 100 requests from one IP in 5s | rate-limit IP |
| SYN flood | `ss` | > 100 half-open (SYN-RECV) connections | alert |
| Connection hold (Slowloris) | `ss` | > N held connections from one IP | block IP + kill its connections |

All thresholds are configurable in `config.yaml`.

### Three modes

- **off** — do nothing.
- **monitor** — detect and alert, never block. Safe default.
- **enforce** — detect, alert, and block or rate-limit offenders via nftables.

Mode changes live without a restart (the engine polls a control file), so you can
flip monitor to enforce mid-attack.

---

## Architecture

```
attack_detector/
  engine.py            main loop: wires collectors -> detectors -> responder
  events.py            the Event type passed between stages
  config.py            config loading + defaults
  controller.py        live control: reads control.json, drains commands.jsonl,
                       writes status.json
  ctl.py               command-line control (set mode, block, unblock, status)

  collectors/
    tailer.py          follows a log file across rotation
    auth_collector.py  parses sshd auth lines into events
    access_collector.py parses nginx access lines into events

  detectors/
    window_counter.py  shared sliding-window counter
    bruteforce.py      failed-login-per-IP rule
    flood.py           aggregate volumetric rule
    request_rate.py    per-IP request-rate rule
    connstate.py       SYN-flood + Slowloris rule (samples ss)

  alerting.py          formats and writes alerts
  responder.py         MemoryBackend (dry run) and NftablesBackend (real blocking)
  api/
    server.py          Flask API + operator dashboard
```

**Runtime data** lives in `/var/lib/attack-detector/`: `control.json` (desired
mode), `commands.jsonl` (queued block/unblock), `status.json` (current state),
`alerts.log`, `responder.log`.

**The firewall** uses a dedicated nftables table, `inet attack_detector`, so it
never interferes with your other rules. Blocking an IP also kills its existing
connections, so a held attack is released immediately instead of lingering until
TCP timeout.

---

## Requirements

- Linux (tested on Ubuntu Server 24.04) with `nftables` and `ss` (iproute2).
- Python 3.11+.
- `PyYAML` and `Flask` (see `requirements.txt`).
- Root, for the engine to read logs and manage nftables.

Install Flask and PyYAML on Ubuntu (externally-managed Python):

```bash
sudo apt install -y python3-flask python3-yaml
# or: pip install -r requirements.txt --break-system-packages
```

---

## Install

From the repository root on the server:

```bash
sudo bash deploy/install.sh
```

This copies the package to `/opt/attack-detector`, installs the config to
`/etc/attack-detector/config.yaml`, creates `/var/lib/attack-detector/`, and
installs and starts two systemd services:

- `attack-detector` — the detection/response engine.
- `attack-detector-api` — the API and dashboard.

Both are enabled, so they survive a reboot. See `deploy/INSTALL.md` for details.

To remove everything:

```bash
sudo bash deploy/uninstall.sh
```

### Important: services run from `/opt`, not your home directory

The systemd services run the copy in `/opt/attack-detector`. Editing files in
your home clone does nothing until you copy them into `/opt` and restart:

```bash
sudo cp -r attack_detector/* /opt/attack-detector/attack_detector/
sudo systemctl restart attack-detector
```

The engine caches code in memory, so **always restart after deploying a change.**

---

## Configuration

Edit `/etc/attack-detector/config.yaml`. Key settings:

```yaml
mode: monitor                    # off | monitor | enforce
admin_allowlist: ["10.0.2.2"]    # never blocked - YOUR admin path
responder_backend: nftables      # nftables (real) | memory (dry run)

bf_threshold: 5                  # failed logins per IP / 60s
flood_threshold: 2000            # total requests / 10s
req_threshold: 100               # requests per IP / 5s
req_rate_limit: 20               # rate-limit a flooding IP to N req/s (enforce)
syn_threshold: 100               # half-open connections -> syn flood
conn_threshold: 50               # held connections per IP -> slowloris
connstate_interval: 5            # seconds between ss samples
```

**`admin_allowlist` is a safety rail.** Enforce refuses to start with an empty
allowlist, so you cannot lock yourself out. Put your admin source IP here and
never put an attacker's IP here.

---

## Operating it

Control the running engine with `ctl.py` (or the dashboard):

```bash
python3 -m attack_detector.ctl status              # current mode + blocked IPs
python3 -m attack_detector.ctl mode enforce        # switch mode live
python3 -m attack_detector.ctl unblock 1.2.3.4     # release an IP
```

The **dashboard** is served by the API service. Browse to the host on the API
port (default 8787). It needs the API token from `/etc/attack-detector/api.env`,
sent as the `X-Auth-Token` header.

Handy resets:

```bash
# force monitor mode
echo '{"mode":"monitor"}' | sudo tee /var/lib/attack-detector/control.json

# clear all firewall blocks
sudo nft flush table inet attack_detector
```

---

## Tests

Ten test suites cover the parsers, detectors, responder, controller, and API.
Run them from the repository root:

```bash
for t in tests/test_*.py; do python3 "$t"; done
```

All should print `all checks passed`.

---

## The demo

The `demo/` folder is a complete, self-contained demonstration: a shipment-
tracking site that a real connection-exhaustion attack makes unusable, and that
the detector keeps online in enforce mode. It is designed to be driven from a
phone while the audience watches the site on a PC.

See **`demo/README_demo.md`** for the full runbook and **`demo/PHONE_SETUP.md`**
for phone/network setup. In short:

- `demo/app/fragile_server.py` — the Northwind tracking app. A fixed worker pool;
  each request needs a worker. Under a connection-exhaustion attack the pool
  fills and real visitors' requests hang, the authentic experience of an
  overwhelmed server.
- `demo/site/index.html` — the tracking page (enter a number, get shipment
  status). Hangs and shows a timeout message when the server is saturated.
- `demo/slowloris_hold.py` — a hold-open connection attack that exhausts the pool.
- `demo/launcher.py` — a token-gated launcher that fires attacks on command.
- `demo/display.html` — full-screen site view for the PC (the audience screen).
- `demo/remote.html` — the phone remote: big mode indicator, attack buttons, and
  a Reset that clears the firewall block between rounds.

### The story it tells

1. A visitor tracks a shipment on the live site. It works.
2. Attack launched, detector in **monitor**: the site hangs. Real customers can't
   use it. The detector sees the attack but only watches.
3. Detector switched to **enforce**: the same attack is launched, the detector
   blocks the attacker within seconds and kills its connections, and the site
   stays usable throughout.

Same real attack, opposite outcomes. Nothing is faked, real connections, real
detection, a real firewall block, real recovery.

---


---

## License

Private project. All rights reserved.
