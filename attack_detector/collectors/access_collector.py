import re

from ..events import Event

HTTP_REQUEST = "http_request"

# nginx default "combined" log format:
#   $remote_addr - $remote_user [$time_local] "$request" $status $bytes "$ref" "$ua"
# example:
#   192.168.50.11 - - [14/Aug/2026:22:10:01 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.0"
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<bytes>\S+)'
)


def parse_line(line):
    """Parse one nginx combined-format access line into an http_request Event.
    Returns None on a line that does not match (malformed, or a different
    format)."""
    m = _COMBINED.search(line)
    if not m:
        return None
    return Event(
        HTTP_REQUEST,
        m.group("ip"),
        log_ts=m.group("ts"),
        method=m.group("method"),
        raw=line,
    )


class AccessCollector:
    """Tails an nginx access log and yields http_request events. Uses the same
    Tailer as the auth collector, so it survives log rotation and truncation."""

    def __init__(self, path="/var/log/nginx/access.log", from_start=False):
        self.path = path
        self.from_start = from_start

    def events(self):
        from .tailer import Tailer
        for line in Tailer(self.path).follow(from_start=self.from_start):
            ev = parse_line(line)
            if ev is not None:
                yield ev
