import subprocess
import time
from collections import Counter


def _run_ss(args):
    return subprocess.run(["ss"] + args, capture_output=True, text=True)


class ConnStateDetector:
    """Detect SYN floods and connection-holding attacks (Slowloris) by sampling
    the TCP connection table, not by reading a log. These attacks carry almost
    no request volume, so the log-based rules never see them.

    Two signals per sample:
      - syn_recv:   count of half-open connections (state SYN-RECV). A SYN flood
                    drives this up: many handshakes started, none finished.
      - per_ip_est: established connections grouped by source IP. Slowloris shows
                    up as one IP holding an unusually high number of open
                    connections.

    fire conditions:
      - total SYN-RECV over syn_threshold  -> "syn_flood"
      - any single IP with established connections over conn_threshold
                                            -> "conn_hold" (Slowloris shape)
    """

    def __init__(self, syn_threshold=100, conn_threshold=50, runner=None,
                 cooldown=30):
        self.syn_threshold = syn_threshold
        self.conn_threshold = conn_threshold
        self._run = runner or _run_ss
        self.cooldown = cooldown
        self._last_fired = {}   # key -> monotonic ts of last alert

    def _sample_syn_recv(self):
        # ss -tan state syn-recv : one line per half-open connection
        res = self._run(["-tan", "state", "syn-recv"])
        text = getattr(res, "stdout", "") or ""
        lines = [ln for ln in text.splitlines() if ln.strip()]
        # ss prints a header line for -tan; drop it if present
        if lines and lines[0].lower().startswith(("state", "recv-q")):
            lines = lines[1:]
        return len(lines)

    def _sample_established_by_ip(self):
        # ss -tan state established : count per remote (peer) address
        res = self._run(["-tan", "state", "established"])
        text = getattr(res, "stdout", "") or ""
        counts = Counter()
        for ln in text.splitlines():
            parts = ln.split()
            if len(parts) < 5:
                continue
            peer = parts[4]                       # peer address:port column
            if peer.lower().startswith(("peer", "address")):
                continue
            ip = peer.rsplit(":", 1)[0].strip("[]")   # strip port, ipv6 brackets
            if ip and ip not in ("Local", "Address"):
                counts[ip] += 1
        return counts

    def sample(self):
        """Take one sample of the connection table. Returns a list of alerts,
        each a tuple (kind, key, count). Empty when nothing crosses a
        threshold."""
        alerts = []

        now = time.monotonic()

        syn = self._sample_syn_recv()
        if syn >= self.syn_threshold and self._ready("syn_flood:aggregate", now):
            alerts.append(("syn_flood", "aggregate", syn))

        by_ip = self._sample_established_by_ip()
        for ip, n in by_ip.items():
            if n >= self.conn_threshold and self._ready(f"conn_hold:{ip}", now):
                alerts.append(("conn_hold", ip, n))

        return alerts

    def _ready(self, key, now):
        """True if this alert key is outside its cooldown; records the fire."""
        last = self._last_fired.get(key, -1e9)
        if now - last >= self.cooldown:
            self._last_fired[key] = now
            return True
        return False
