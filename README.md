# attack-detector

Intrusion detection and response for a single Linux server. Detects five attack
shapes, responds with blocking or rate-limiting, and exposes a dashboard to
watch and control it. Built for an isolated test lab, not production.

The full plan lives in [CLAUDE.md](CLAUDE.md).

## Lab

| Role     | Address        | Notes                                            |
| -------- | -------------- | ------------------------------------------------ |
| Target   | 192.168.50.10  | Ubuntu Server 24.04, nginx, nftables, python3    |
| Attacker | 192.168.50.11  | nmap, hping3, ab, slowhttptest, hydra            |

Code is edited on the Windows workstation and copied to the target to run.

## Progress

- [~] **Day 1** — repo scaffold, auth-log collector, prints parsed events.
      Code complete and green on Windows; **not closed until
      `./scripts/verify_day1.sh` passes on the target** (see below).
- [ ] Day 2 — per-IP sliding window, brute-force rule, alerts
- [ ] Day 3 — firewall block via nftables, admin allowlist
- [ ] Day 4 — off/monitor/enforce controller with hot reload

## Running it

On the workstation, push the code to the target:

```powershell
.\scripts\sync.ps1
```

On the target, once:

```bash
cd ~/attack-detector
./scripts/setup_target.sh
```

`setup_target.sh` builds the venv and checks the auth log. **The run user must
be in the `adm` group to read `/var/log/auth.log`** — the script adds you and
tells you to log back out and in, since group membership only applies to a new
login session.

Then:

```bash
./scripts/run.sh
```

It follows `/var/log/auth.log` and prints an event per recognised sshd line.
To see it work, from the attacker box:

```bash
ssh baduser@192.168.50.10    # enter a wrong password a few times
```

Each failure should appear on the target as an `ssh_failed_login` line.

## Auth log source

The lab target has rsyslog, so the source is the file `/var/log/auth.log`.
Ubuntu 24.04 is journald-first and some images ship without rsyslog, leaving no
such file. For those hosts, switch the source in `config.yaml`:

```yaml
sources:
  auth:
    type: journald    # instead of "file"
    unit: ssh
```

The same parser handles both; `journalctl` emits identical sshd message text.

## Tests

These run on Windows or Linux, no lab required:

```bash
python -m tests.test_auth_parser
python -m tests.test_tailer_rotation
```

`test_tailer_rotation` skips its rename-rotation case on Windows, which cannot
rename a file while a handle is open. Logrotate's default *is* rename-style, so
that path has no real coverage until the suite runs on Linux.

## Closing a day

Run on the target:

```bash
./scripts/verify_day1.sh          # checks + admin address discovery
./scripts/verify_day1.sh --live   # watch for real failed-password lines
```

The first form checks the auth log is readable, runs both suites (including the
rename-rotation case that only works here), and prints the address the target
observes your admin session on. The second watches for 60s while you SSH from
the attacker with a wrong password, and passes only if real events arrive.

## Config

See [config.yaml](config.yaml). `admin_allowlist` starts **empty**, and the
engine refuses to start in `enforce` mode while it is — blocking cannot go live
before the value is set.

Do not guess that value. SSH from Windows arrives through the NAT port-forward,
so the target sees the NAT gateway (`10.0.2.x`), not your Windows address.
`verify_day1.sh` prints what it actually observes. The attacker VM
(`192.168.50.11`) must never be listed.
