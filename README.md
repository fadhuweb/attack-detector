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

- [x] **Day 1** — repo scaffold, auth-log collector, prints parsed events
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
rename an open file. **Run that suite on the target too** — logrotate's default
is rename-style, so that path only gets real coverage on Linux.

## Config

See [config.yaml](config.yaml). Before day 3 adds blocking, set
`admin_allowlist` to include the address you administer the target from, or an
enforcing rule can lock you out. The attacker VM must *not* be listed there.
