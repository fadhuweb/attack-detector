# attack-detector

Server intrusion detection and response for a single Linux host. See CLAUDE.md
for the full three-week plan. This is through day 3.

## What works now (days 1-3)

Collector, brute-force detection, and blocking. Tails the SSH auth log, counts
failed logins per source IP in a sliding window, alerts on the threshold, and in
enforce mode blocks the offender with nftables. The admin allowlist is never
blocked.

- events.py - the Event record
- collectors/tailer.py - tail -F: survives rotation and truncate
- collectors/auth_collector.py - sshd parser, file + journald
- detectors/window_counter.py - per-key sliding-window counter
- detectors/bruteforce.py - brute-force rule with invalid-user pairing
- alerting.py - alerts to stdout and alerts.log
- responder.py - nftables blocking, allowlist + mode gated
- config.py - defaults, config.yaml, and the enforce safety guard
- engine.py - runs collector, detector, alerter, responder

## The three modes

- off: nothing runs.
- monitor: detect and alert, never block. Safe default. Test here first.
- enforce: detect, alert, and block offenders. Refuses to start if the allowlist
  is empty.

## Safety design (read before enforce)

1. The allowlist is checked on every block. An alert for an allowlisted IP is
   logged and skipped, never blocked. This stops the tool blocking the address
   you administer the host from.
2. enforce with an empty allowlist refuses to start (exit 2). Blocking cannot go
   live unconfigured.
3. Blocking uses a dedicated nftables table `attack_detector` with its own sets.
   It never touches your other firewall rules. Remove all blocks with:
       sudo nft flush table inet attack_detector
   or delete the whole table with:
       sudo nft delete table inet attack_detector

## Run it (on the target VM)

    cd ~/attack-detector
    chmod +x scripts/*.sh
    ./scripts/run.sh                 # monitor mode from config.yaml

Blocking needs root (nft edits the firewall). To test enforce:

    sudo python3 -m attack_detector.engine -c config.yaml --mode enforce

Confirm the allowlist has your admin IP (10.0.2.2) first, or it will refuse.

## Tests (run by file path from the repo root)

    python3 tests/test_auth_parser.py
    python3 tests/test_tailer_rotation.py
    python3 tests/test_bruteforce.py
    python3 tests/test_responder.py

The responder test uses a fake nft runner, so it needs no root. Verify real
blocking on the target (see below).

## Verify real blocking on the target

1. Set admin_allowlist to your admin IP (10.0.2.2) in config.yaml.
2. Run enforce as root:  sudo ./scripts/run.sh --mode enforce  (or the python line above)
3. From the ATTACKER VM (192.168.50.11), brute-force the target:
       for i in $(seq 1 8); do sshpass -p wrong ssh -o PreferredAuthentications=password \
         -o PubkeyAuthentication=no -o StrictHostKeyChecking=no bad@192.168.50.10; done
4. Watch for BLOCK src=192.168.50.11. Then confirm the attacker can no longer
   reach the target:  from the attacker,  ssh bad@192.168.50.10  should now hang/fail.
5. Confirm YOUR admin SSH from Windows still works (10.0.2.2 is allowlisted).
6. Clean up:  sudo nft flush table inet attack_detector

## Connection-state rule: SYN flood and Slowloris (day 11)

These attacks carry almost no request volume, so every log-based rule misses
them. This rule samples the TCP connection table with `ss` on a timer instead of
reading a log.

- SYN flood: many half-open connections (state SYN-RECV). Fires syn_flood when
  the count passes syn_threshold. SYN sources are often spoofed, so this alerts
  rather than blocks.
- Slowloris: one IP holds many established connections open with almost no
  traffic. Fires conn_hold when one IP's established count passes conn_threshold.
  That IP is real, so it is blocked in enforce mode (allowlist still applies).

Simulate from the attacker VM:

    # SYN flood (short bursts), confirm with ss on the target:
    sudo hping3 -S --flood -p 80 192.168.50.10
    #   on target:  watch -n1 'ss -tan state syn-recv | wc -l'

    # Slowloris:
    sudo apt install -y slowhttptest
    slowhttptest -c 300 -H -u http://192.168.50.10/ -i 10 -r 200
    #   on target:  ss -tan state established | grep <attacker-ip> | wc -l

Tune syn_threshold and conn_threshold above your normal connection counts.

## Rate-limiting as the flood response (day 10)

In enforce mode, a single-source request flood is RATE-LIMITED, not hard-blocked:
nftables caps the offending IP to req_rate_limit requests/second and drops the
excess. This is gentler than a full block, so legitimate traffic from a shared
address (many users behind one NAT) still gets through while the flood is
throttled.

- gated by mode and allowlist, exactly like blocking. The admin IP is never
  rate-limited.
- reversible live:  python3 -m attack_detector.ctl unlimit <ip>
- a distributed flood has no single IP to limit, so it still only alerts.
- rate-limits live in a separate nftables chain; remove all with the same
  table flush:  sudo nft flush table inet attack_detector

## Distributed vs single-source floods (day 9)

Two request-rate rules run on the access log:
- aggregate (day 8): total requests across all IPs -> catches distributed floods.
- per-IP (day 9): requests from one IP -> catches single-source floods.

The point of running both is the contrast:
- a DISTRIBUTED flood trips the aggregate rule but NOT the per-IP rule, because
  no single IP is individually busy.
- a SINGLE-SOURCE flood trips both.

Simulate each with the included tool (writes to the access log the engine tails):

    # distributed: many IPs, few requests each -> aggregate fires, per-IP quiet
    sudo python3 scripts/simulate_flood.py --distributed --requests 3000 --ips 500 \
        --log /var/log/nginx/access.log

    # single-source: one IP, all requests -> both fire
    sudo python3 scripts/simulate_flood.py --single --requests 3000 \
        --ip 192.168.50.11 --log /var/log/nginx/access.log

For a real network-level single-source flood, ab from the attacker VM also works:
    ab -n 5000 -c 200 http://192.168.50.10/
Spoofing many real source IPs over the lab network is unreliable through NAT, so
the simulator is the deterministic way to exercise the distributed case.

## Aggregate flood detection (day 8)

A second detector counts TOTAL http requests across all source IPs in a short
window and fires above a ceiling. This catches a distributed flood that per-IP
rules miss: when a flood is spread across thousands of IPs, no single IP crosses
a per-IP threshold, but the total volume is far above normal.

- reads the nginx access log (access_log in config.yaml)
- fires on flood_threshold total requests in flood_window seconds
- reports the heaviest source IPs in the alert, though the fire decision is the
  aggregate total, not any one IP
- a distributed flood has no single IP to block, so day 8 alerts only.
  Rate-limiting as the flood response is day 10.

Simulate a distributed flood from the attacker (many parallel workers):

    ab -n 5000 -c 200 http://192.168.50.10/        # apache bench, one host many requests
    # or spread across fake sources with parallel curl loops

Tune flood_threshold above your normal peak traffic, or it will false-fire.

## Live control without restart (day 4)

The engine watches control files while it runs. Change mode or release an IP with
no restart, using the ctl helper:

    python3 -m attack_detector.ctl status              # show mode, blocked IPs, uptime
    python3 -m attack_detector.ctl mode enforce        # flip to enforce live
    python3 -m attack_detector.ctl mode monitor        # back to alert-only
    python3 -m attack_detector.ctl mode off            # stop acting
    python3 -m attack_detector.ctl unblock 192.168.50.11   # release a blocked IP
    python3 -m attack_detector.ctl block 203.0.113.7       # block manually (allowlist still applies)

Switching to enforce with an empty allowlist is refused at runtime, the same
guard as startup. The status file (status.json) is what the week-3 dashboard
reads.

## Sync from Windows

    scp -P 2222 -r C:\Users\fadhl\Desktop\attack-detector target@localhost:~/
