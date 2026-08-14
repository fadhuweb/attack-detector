"""Parser checks that run anywhere, so the regexes are proven before scp.

Run from the repo root:  python -m tests.test_auth_parser
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attack_detector.collectors.auth_collector import parse_line, parse_timestamp

FAILURES: list[str] = []


def check(name: str, got, want) -> None:
    if got == want:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}\n         got:  {got!r}\n         want: {want!r}")
        FAILURES.append(name)


def test_failed_password() -> None:
    line = "Aug 14 11:21:04 target sshd[1312]: Failed password for root from 192.168.50.11 port 43118 ssh2"
    event = parse_line(line)
    check("failed password type", event.event_type, "ssh_failed_login")
    check("failed password ip", event.src_ip, "192.168.50.11")
    check("failed password user", event.extra["user"], "root")


def test_failed_password_invalid_user() -> None:
    line = "Aug 14 11:21:02 target sshd[1310]: Failed password for invalid user admin from 192.168.50.11 port 43112 ssh2"
    event = parse_line(line)
    check("invalid-user failure type", event.event_type, "ssh_failed_login")
    check("invalid-user failure ip", event.src_ip, "192.168.50.11")
    check("invalid-user failure user", event.extra["user"], "admin")


def test_accepted_login() -> None:
    line = "Aug 14 11:22:00 target sshd[1450]: Accepted password for fadhl from 192.168.50.1 port 51044 ssh2"
    event = parse_line(line)
    check("accepted type", event.event_type, "ssh_accepted_login")
    check("accepted ip", event.src_ip, "192.168.50.1")


def test_invalid_user_line() -> None:
    line = "Aug 14 11:21:02 target sshd[1310]: Invalid user admin from 192.168.50.11 port 43112"
    event = parse_line(line)
    check("invalid user type", event.event_type, "ssh_invalid_user")
    check("invalid user ip", event.src_ip, "192.168.50.11")


def test_max_attempts() -> None:
    line = "Aug 14 11:21:08 target sshd[1320]: error: maximum authentication attempts exceeded for root from 192.168.50.11 port 43142 ssh2 [preauth]"
    event = parse_line(line)
    check("max attempts type", event.event_type, "ssh_failed_login")
    check("max attempts ip", event.src_ip, "192.168.50.11")


def test_non_ssh_line_ignored() -> None:
    line = "Aug 14 11:21:30 target CRON[1400]: pam_unix(cron:session): session opened for user root(uid=0)"
    check("cron line ignored", parse_line(line), None)


def test_iso_timestamp_line() -> None:
    line = "2026-08-14T11:23:11.482913+00:00 target sshd[1502]: Failed password for backup from 192.168.50.11 port 44002 ssh2"
    event = parse_line(line)
    check("iso line type", event.event_type, "ssh_failed_login")
    check("iso line ip", event.src_ip, "192.168.50.11")
    check("iso timestamp parsed", event.log_ts is not None, True)


def test_syslog_timestamp_year_rollover() -> None:
    # Reading a 31 Dec line on 1 Jan must land in the previous year, not the
    # current one, or the event looks like it is from the future.
    jan_first = time.mktime((2026, 1, 1, 0, 30, 0, 0, 1, -1))
    parsed = parse_timestamp("Dec 31 23:59:00 target sshd[1]: x", now=jan_first)
    check("year rollover", time.localtime(parsed).tm_year, 2025)


def main() -> int:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(name)
            fn()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed: {', '.join(FAILURES)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
