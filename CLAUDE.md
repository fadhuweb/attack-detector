# CLAUDE.md — server intrusion detection app

This file is the project brief. Claude Code reads it on launch. It carries the
full plan and every design decision from the planning conversation so no context
is lost.

## What we are building

A small intrusion detection and response app that installs on a single Linux
server. It reads events, detects a set of attacks, responds, and gives the
operator a web dashboard to watch it and control it. Others can install it in one
command. It is for testing and demos against machines we own, not a production
security product.

Two halves:
1. The engine. A background service that detects and responds.
2. The app. A dashboard, an API, and a one-command install so others can use it.

Stack: Python. Flask for the API and to serve one dashboard page. Parse logs with
string handling or regex. Hold counters in dicts of timestamps. Shell out to
`nft` or `iptables` for blocking and rate-limiting. Read connection state from
`ss`. Ship as a systemd service with an install script.

## Architecture: six parts

Engine:
1. Collector. Tails a source and parses each new line into a structured record
   (timestamp, source IP, event type). Sources: SSH auth log
   (`/var/log/auth.log`), web access log, connection table.
2. Detector. Runs rules over a sliding time window. Each rule counts events and
   fires when a threshold is crossed. Three counter shapes: per-IP, aggregate,
   and connection-state.
3. Responder. Acts when a rule fires. Alert (log, print, webhook), block
   (firewall drop rule for one IP), and rate-limit (cap requests per IP per
   second, drop the excess).
4. Controller. Holds the mode (off/monitor/enforce) in a config value. Reloads
   without a restart so the dashboard buttons take effect live.

App:
5. API. A thin Flask layer over the controller: read status, read alerts, read
   blocked and rate-limited IPs, set mode, get and set thresholds.
6. Dashboard. One HTML page talking to the API. Shows current mode, live alerts,
   blocked and rate-limited IPs, and three buttons for off/monitor/enforce.

## The toggle: three modes

- `off`: engine idle.
- `monitor`: detect and alert, never block or rate-limit. Test here first.
- `enforce`: detect, alert, and block or rate-limit.

Always exempt the admin IP with an allowlist so a rule can never fence us out.
Test every enforcing rule in `monitor` first, then `enforce` with the allowlist
in place.

## Detection rules: three counter shapes

Per-IP rules (count events per source IP in a window). One engine, three
instances:
- Port scan. Count distinct destination ports per IP in 10s. Fire above ~15.
  Simulate: `nmap -sT <target>`.
- Login brute force. Count failed logins per IP in 60s. Fire above ~5. Parse
  "Failed password" lines from the auth log. Simulate: a loop of SSH attempts
  with a wrong password, or `hydra` against our own box.
- Request flood (single-source). Count requests per IP in 5s. Fire above ~100.
  Read the web access log. Simulate: `ab -n 500 -c 50 http://<target>/`.

Aggregate rule (count across all IPs, ignore source):
- DDoS / volumetric. Count total requests across all sources in 10s. Fire above a
  ceiling normal traffic never reaches (example: 2000 when baseline is 200).
  Catches distributed traffic no per-IP rule sees. Simulate:
  `hping3 --rand-source -p 80 --flood <target>`, or many parallel `ab`/`curl`
  workers. The test: per-IP rules stay quiet, the aggregate rule fires.

Connection-state rule (sample the connection table, not log lines):
- SYN flood and Slowloris. Count half-open or idle connections from
  `ss -tan state syn-recv` and idle-connection counts. Fire above a threshold. A
  rate counter misses Slowloris because its request volume stays low. Simulate:
  `hping3 -S --flood -p 80 <target>` (SYN, confirm with `ss`),
  `slowhttptest -c 200 -H -u http://<target>/` (Slowloris, confirm idle open
  connections with `ss`).

## Responses and their limits

- Single-source attacks: block the one IP. Fixes it.
- Floods: rate-limit per IP and shed load above a ceiling rather than hard-block.
- DDoS limit to remember: the app cannot stop a flood large enough to fill the
  uplink, because the traffic saturates the link before the software acts. That
  is handled upstream by the host or a service in front of the server. Build
  detection and alert; treat blocking and rate-limiting as best-effort.

## The app layer

API endpoints (Flask):
- `GET /status` — mode, uptime, counts.
- `GET /alerts` — recent alerts from the alert log.
- `GET /blocked` — currently blocked and rate-limited IPs.
- `POST /mode` — set off/monitor/enforce. Writes the controller config.
- `GET /config`, `POST /config` — read and set thresholds.

Dashboard: one static HTML page plus a little JavaScript. Polls `/status` and
`/alerts`, renders the mode, the alert feed, and the blocked and rate-limited
lists, and posts to `/mode` from three buttons.

Security default: bind the dashboard and API to localhost only. The admin reaches
it over an SSH tunnel. It must never sit open on the internet, because it edits
the firewall and blocks IPs. Add a shared-token check on the API as a second
layer.

## Deploy: usable by others

Primary path: systemd service plus `install.sh`.
- `install.sh` installs Python dependencies, copies the app into place, writes a
  config file, drops a systemd unit, and starts the service.
- The unit runs the engine and the Flask app together, restarts on failure.
- A short README tells the installer what to set: which logs to read, the admin
  IP for the allowlist, the web server type, and the alert webhook if any.

Optional path: Docker, as a demo target only. Note the caveats in the README:
the container needs host network access, the `NET_ADMIN` capability, and mounted
host log files to read logs and edit the firewall. Systemd on the host is
cleaner for this tool, so Docker stays optional.

## Test lab and safety

Two machines we own: an attacker box and a target box, isolated. Never point any
attack at shared infrastructure or a cloud provider without checking their
policy. A real flood can get an account suspended. Keep SYN-flood bursts short.

## Three-week day-by-day

Days 7, 14, and 21 are buffers for slippage. After any day the app should still
run. Must-ship minimum by day 21 is a one-command install running all five
attack detections behind the dashboard.

### Week 1: the engine and the toggle

- Day 1. Stand up two VMs (attacker, target). Init repo and Python env. Write the
  collector that tails the auth log and parses failed-login lines. Print them.
- Day 2. Build the per-IP sliding-window counter. Wire the brute-force rule to
  fire an alert. Run in `monitor`. Simulate with the SSH loop.
- Day 3. Build the responder: firewall block via `nft`/`iptables`. Add the admin
  allowlist. Add the config file. Test `enforce` with the allowlist so we do not
  lock ourselves out.
- Day 4. Build the controller: off/monitor/enforce with hot reload, no restart.
  Wrap the pieces into one loop.
- Day 5. Add the web-access-log and connection-log collectors. Add the port-scan
  rule as a second per-IP instance reusing the engine.
- Day 6. Add the single-source request-flood rule. Simulate with `ab`. Test all
  three per-IP rules end to end.
- Day 7. Buffer and test. Fix bugs. Save the simulation commands as scripts in
  the repo.

### Week 2: DoS and DDoS

- Day 8. Build the aggregate counter (total across all IPs). Add the
  DDoS/volumetric alert. Run in `monitor`.
- Day 9. Simulate distributed traffic. Confirm the per-IP rules stay quiet while
  the aggregate rule fires.
- Day 10. Build rate-limiting as the flood response: cap requests per IP per
  second, drop the excess. Add load shedding above a ceiling.
- Day 11. Build the connection-state rule. Simulate SYN flood and Slowloris.
  Confirm the flood rule alone misses Slowloris.
- Day 12. Integrate all five rule shapes under the one toggle. Tune thresholds
  against baseline traffic. Make sure the allowlist covers rate-limiting too.
- Day 13. Test all five attacks end to end in `monitor`, then `enforce`.
- Day 14. Buffer. Fix bugs.

### Week 3: the app and deploy

- Day 15. Build the Flask API: `/status`, `/alerts`, `/blocked`. Read from the
  engine's alert log and state.
- Day 16. Add `/mode` and `/config`. Confirm posting a mode change flips the
  controller live through the hot reload.
- Day 17. Build the dashboard page: mode display, alert feed, blocked and
  rate-limited lists, three buttons. Poll the API. Bind to localhost, add the
  shared-token check.
- Day 18. Write `install.sh` and the systemd unit. Install onto a clean VM from
  scratch and confirm it starts and runs.
- Day 19. Full integration on the clean install: run all five attacks, watch them
  land on the dashboard, flip modes from the buttons, confirm block, rate-limit,
  and allowlist.
- Day 20. Write the README and a runbook. Add the alert webhook. Record a demo of
  each attack seen on the dashboard.
- Day 21. Buffer. Full rehearsal on a fresh VM: install, flip off to monitor to
  enforce, run every attack, confirm detect and respond. Fix leftovers.

## Build order rule

Build in the order above. After any day the app should still run. Start with
brute force in `monitor` because it is the easiest to parse and the safest to
test. Add blocking only after alerting works. Add DoS/DDoS only after the three
per-IP rules work. Build the API only after the engine works. Build deploy only
after the dashboard works.

## Open decisions to confirm with the user

- Target OS. The plan assumes Linux with `nft`/`iptables` and `ss`.
- Web server for the access-log source (nginx, apache, other).
- Where alerts go (webhook URL, or log only for now).
- Deploy target for the demo: systemd on a VM (recommended) or Docker.
