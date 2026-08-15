import re
import subprocess

from ..events import (
    Event,
    SSH_FAILED_LOGIN,
    SSH_INVALID_USER,
    SSH_AUTH_ABORT,
    SSH_ACCEPTED_LOGIN,
)

_PREFIX = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s[\d:]+|\d{4}-\d{2}-\d{2}T[\d:.+\-]+)"
)
_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_MAXAUTH = re.compile(
    r"maximum authentication attempts exceeded for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)


def _log_ts(line):
    m = _PREFIX.match(line)
    return m.group("ts") if m else None


def parse_line(line):
    """Return an Event for an sshd auth line, or None. Order matters:
    maxauth and failed are checked before invalid so a 'Failed password for
    invalid user' line types as a failed attempt, not a bare probe."""
    ts = _log_ts(line)

    m = _MAXAUTH.search(line)
    if m:
        return Event(SSH_AUTH_ABORT, m.group("ip"), log_ts=ts,
                     user=m.group("user"), port=int(m.group("port")), raw=line)

    m = _FAILED.search(line)
    if m:
        return Event(SSH_FAILED_LOGIN, m.group("ip"), log_ts=ts,
                     user=m.group("user"), port=int(m.group("port")), raw=line)

    m = _ACCEPTED.search(line)
    if m:
        return Event(SSH_ACCEPTED_LOGIN, m.group("ip"), log_ts=ts,
                     user=m.group("user"), port=int(m.group("port")),
                     method=m.group("method"), raw=line)

    m = _INVALID.search(line)
    if m:
        port = m.group("port")
        return Event(SSH_INVALID_USER, m.group("ip"), log_ts=ts,
                     user=m.group("user"),
                     port=int(port) if port else None, raw=line)

    return None


class AuthCollector:
    def __init__(self, source="file", path="/var/log/auth.log",
                 unit="ssh", from_start=False):
        self.source = source
        self.path = path
        self.unit = unit
        self.from_start = from_start

    def _lines(self):
        if self.source == "journald":
            cmd = ["journalctl", "-u", self.unit, "-f", "-n", "0", "-o", "short-iso"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            try:
                for line in proc.stdout:
                    yield line.rstrip("\n")
            finally:
                proc.terminate()
        else:
            from .tailer import Tailer
            yield from Tailer(self.path).follow(from_start=self.from_start)

    def events(self):
        for line in self._lines():
            ev = parse_line(line)
            if ev is not None:
                yield ev
