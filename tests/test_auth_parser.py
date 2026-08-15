import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.collectors.auth_collector import parse_line
from attack_detector.events import (
    SSH_FAILED_LOGIN,
    SSH_INVALID_USER,
    SSH_AUTH_ABORT,
    SSH_ACCEPTED_LOGIN,
)

_fail = []


def check(name, cond):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}")
        _fail.append(name)


P = "target sshd[1]: "

# 1. failed password, valid user
e = parse_line("Aug 14 20:39:22 " + P + "Failed password for fadhl from 192.168.50.11 port 43112 ssh2")
check("failed password valid user",
      e and e.etype == SSH_FAILED_LOGIN and e.source_ip == "192.168.50.11"
      and e.user == "fadhl" and e.port == 43112)

# 2. failed password, invalid user -> typed failed, port captured
e = parse_line("Aug 14 20:39:23 " + P + "Failed password for invalid user admin from 192.168.50.11 port 43120 ssh2")
check("failed password invalid user types as failed",
      e and e.etype == SSH_FAILED_LOGIN and e.user == "admin" and e.port == 43120)

# 3. bare Invalid user -> typed invalid, port captured
e = parse_line("Aug 14 20:39:23 " + P + "Invalid user admin from 192.168.50.11 port 43120")
check("bare invalid user carries port",
      e and e.etype == SSH_INVALID_USER and e.user == "admin" and e.port == 43120)

# 4. the invalid-user pair shares one dedupe key
inv = parse_line("Aug 14 20:39:23 " + P + "Invalid user admin from 192.168.50.11 port 43120")
fail = parse_line("Aug 14 20:39:23 " + P + "Failed password for invalid user admin from 192.168.50.11 port 43120 ssh2")
check("invalid-user pair shares one dedupe key",
      inv.dedupe_key() == fail.dedupe_key())

# 5. accepted publickey
e = parse_line("Aug 14 20:39:20 " + P + "Accepted publickey for fadhl from 192.168.50.1 port 51000 ssh2: RSA SHA256:x")
check("accepted publickey",
      e and e.etype == SSH_ACCEPTED_LOGIN and e.method == "publickey" and e.user == "fadhl")

# 6. accepted password
e = parse_line("Aug 14 20:39:20 " + P + "Accepted password for fadhl from 192.168.50.1 port 51002 ssh2")
check("accepted password",
      e and e.etype == SSH_ACCEPTED_LOGIN and e.method == "password")

# 7. max auth attempts -> abort
e = parse_line("Aug 14 20:39:25 " + P + "error: maximum authentication attempts exceeded for fadhl from 192.168.50.11 port 43130 ssh2 [preauth]")
check("max auth exceeded types as abort",
      e and e.etype == SSH_AUTH_ABORT and e.port == 43130)

# 8. non-ssh line ignored
e = parse_line("Aug 14 20:39:26 target systemd[1]: Started Session 5 of user fadhl.")
check("non-ssh line ignored", e is None)

# 9. ISO timestamp line parses and captures log_ts
e = parse_line("2026-08-14T20:39:27.123456+00:00 " + P + "Failed password for root from 192.168.50.11 port 43140 ssh2")
check("iso timestamp line parses",
      e and e.etype == SSH_FAILED_LOGIN and e.log_ts and e.log_ts.startswith("2026-08-14T"))

# 10. classic timestamp captured for display
e = parse_line("Aug 14 20:39:22 " + P + "Failed password for fadhl from 192.168.50.11 port 43112 ssh2")
check("classic timestamp captured", e and e.log_ts == "Aug 14 20:39:22")

# 11. Dec->Jan rollover lines both parse (windows use ingest time, so no year math needed)
d = parse_line("Dec 31 23:59:59 " + P + "Failed password for fadhl from 192.168.50.11 port 44000 ssh2")
j = parse_line("Jan  1 00:00:01 " + P + "Failed password for fadhl from 192.168.50.11 port 44001 ssh2")
check("year rollover lines both parse",
      d and j and d.etype == SSH_FAILED_LOGIN and j.etype == SSH_FAILED_LOGIN)

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
