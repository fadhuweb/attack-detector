"""Read the SSH auth log and turn sshd lines into :class:`Event` records.

Source on the lab target is the file ``/var/log/auth.log`` (rsyslog is
installed). The process needs to be in the ``adm`` group to read it.

On a host where rsyslog is absent -- Ubuntu 24.04 is journald-first, so a
minimal or cloud image often has no auth.log -- point ``source`` at journald
instead and the same parser runs over ``journalctl`` output, which uses the
identical sshd message text.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from datetime import datetime
from typing import Callable, Optional

from ..events import Event
from .tailer import FileTailer

SOURCE_NAME = "auth"

# rsyslog on Ubuntu 24.04 may write either the traditional "Aug 14 11:20:33"
# stamp or an RFC3339 one, depending on the template in effect. Accept both.
_TS_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)")
_TS_SYSLOG = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"

# Ordered: first match wins, so the more specific "invalid user" variant of a
# failed password has to be tried before the general one.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ssh_failed_login",
        re.compile(rf"Failed password for invalid user (?P<user>\S+) from {_IP} port (?P<port>\d+)"),
    ),
    (
        "ssh_failed_login",
        re.compile(rf"Failed password for (?P<user>\S+) from {_IP} port (?P<port>\d+)"),
    ),
    (
        "ssh_failed_login",
        re.compile(rf"maximum authentication attempts exceeded for (?P<user>\S+) from {_IP}"),
    ),
    (
        "ssh_invalid_user",
        re.compile(rf"Invalid user (?P<user>\S+) from {_IP}(?: port (?P<port>\d+))?"),
    ),
    (
        "ssh_auth_abort",
        re.compile(rf"Connection closed by authenticating user (?P<user>\S+) {_IP}(?: port (?P<port>\d+))?"),
    ),
    (
        "ssh_accepted_login",
        re.compile(rf"Accepted (?P<method>\S+) for (?P<user>\S+) from {_IP} port (?P<port>\d+)"),
    ),
]


def parse_timestamp(line: str, now: Optional[float] = None) -> Optional[float]:
    """Pull the syslog timestamp off the front of a line as an epoch float."""
    match = _TS_ISO.match(line)
    if match:
        try:
            return datetime.fromisoformat(match.group(1).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None

    match = _TS_SYSLOG.match(line)
    if not match:
        return None

    # The traditional format carries no year, so we supply the current one and
    # correct for the case where we read a December line early in January.
    now = time.time() if now is None else now
    reference = datetime.fromtimestamp(now)
    try:
        stamp = datetime.strptime(match.group(1), "%b %d %H:%M:%S")
    except ValueError:
        return None
    dated = stamp.replace(year=reference.year)
    if (dated - reference).total_seconds() > 86400:
        dated = dated.replace(year=reference.year - 1)
    return dated.timestamp()


def parse_line(line: str, now: Optional[float] = None) -> Optional[Event]:
    """Return an :class:`Event` for an sshd line we care about, else ``None``."""
    if "sshd" not in line:
        return None

    for event_type, pattern in _PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        extra = {k: v for k, v in match.groupdict().items() if v is not None}
        return Event(
            event_type=event_type,
            src_ip=_extract_ip(match),
            source=SOURCE_NAME,
            log_ts=parse_timestamp(line, now=now),
            raw=line,
            extra=extra,
        )
    return None


def _extract_ip(match: re.Match[str]) -> Optional[str]:
    """The IP is the one unnamed group in every pattern above."""
    named = set(match.groupdict().values())
    for group in match.groups():
        if group is not None and group not in named and re.fullmatch(_IP, group):
            return group
    return None


class AuthCollector:
    """Tail the auth log and hand each recognised line to ``on_event``."""

    def __init__(
        self,
        path: str,
        on_event: Callable[[Event], None],
        from_start: bool = False,
    ):
        self.on_event = on_event
        self._tailer = FileTailer(path, self._handle_line, from_start=from_start)

    def start(self) -> None:
        self._tailer.start()

    def stop(self) -> None:
        self._tailer.stop()

    def join(self, timeout: Optional[float] = None) -> None:
        self._tailer.join(timeout)

    def _handle_line(self, line: str) -> None:
        event = parse_line(line)
        if event is not None:
            self.on_event(event)


class JournaldAuthCollector:
    """Same parser, fed by ``journalctl -u ssh -f`` instead of a file.

    The alternate source for hosts with no ``/var/log/auth.log``. Not used in
    the lab, which has rsyslog.
    """

    def __init__(self, on_event: Callable[[Event], None], unit: str = "ssh"):
        self.on_event = on_event
        self.unit = unit
        self._stop = threading.Event()
        self._proc: Optional[subprocess.Popen[str]] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def run(self) -> None:
        self._proc = subprocess.Popen(
            ["journalctl", "-u", self.unit, "-f", "-n", "0", "-o", "short"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            if self._stop.is_set():
                break
            event = parse_line(line.rstrip("\n"))
            if event is not None:
                self.on_event(event)
