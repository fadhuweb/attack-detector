import ipaddress
import shutil
import subprocess
from datetime import datetime


class BlockBackend:
    """Interface for applying and removing blocks. Two implementations:
    NftablesBackend (real, Linux) and MemoryBackend (tests, no privileges)."""

    def block(self, ip):
        raise NotImplementedError

    def unblock(self, ip):
        raise NotImplementedError

    def list_blocked(self):
        raise NotImplementedError


class MemoryBackend(BlockBackend):
    """In-memory backend for tests and dry runs. Records blocks, applies none."""

    def __init__(self):
        self._blocked = set()

    def block(self, ip):
        self._blocked.add(ip)

    def unblock(self, ip):
        self._blocked.discard(ip)

    def list_blocked(self):
        return sorted(self._blocked)


class NftablesBackend(BlockBackend):
    """Real backend. Owns a dedicated nftables table so nothing here can touch
    the operator's other firewall rules. Adds one drop rule per source IP.

    Table layout (created on first use):
      table inet attack_detector {
        set blocked4 { type ipv4_addr; }
        set blocked6 { type ipv6_addr; }
        chain input {
          type filter hook input priority -100; policy accept;
          ip  saddr @blocked4 drop
          ip6 saddr @blocked6 drop
        }
      }

    Blocking adds the IP to the set; unblocking removes it. Using sets keeps it
    idempotent (adding an existing element is a no-op with `add ... ; ` guarded)
    and means the drop rules themselves are written once, not per IP.
    """

    TABLE = "attack_detector"

    def __init__(self, runner=None):
        # runner lets tests inject a fake subprocess; defaults to real nft
        self._run = runner or self._run_nft
        self._ensured = False

    def _run_nft(self, args):
        # args is a list of nft arguments. When the first arg is "-f", the
        # second element is the ruleset script piped to nft on stdin.
        if args and args[0] == "-f":
            script = args[1]
            return subprocess.run(["nft", "-f", "-"], input=script,
                                  capture_output=True, text=True)
        return subprocess.run(["nft"] + args, capture_output=True, text=True)

    def _ensure_table(self):
        if self._ensured:
            return
        script = f"""
add table inet {self.TABLE}
add set inet {self.TABLE} blocked4 {{ type ipv4_addr; flags interval; }}
add set inet {self.TABLE} blocked6 {{ type ipv6_addr; flags interval; }}
add chain inet {self.TABLE} input {{ type filter hook input priority -100; policy accept; }}
flush chain inet {self.TABLE} input
add rule inet {self.TABLE} input ip saddr @blocked4 drop
add rule inet {self.TABLE} input ip6 saddr @blocked6 drop
"""
        # apply as a single ruleset so partial failure can't leave a half table
        res = self._run(["-f", script])
        self._ensured = True
        return res

    def _family(self, ip):
        return 6 if ipaddress.ip_address(ip).version == 6 else 4

    def block(self, ip):
        self._ensure_table()
        setname = "blocked6" if self._family(ip) == 6 else "blocked4"
        # `add element` is idempotent: re-adding an existing element is a no-op
        self._run(["add", "element", "inet", self.TABLE, setname, "{" + ip + "}"])

    def unblock(self, ip):
        setname = "blocked6" if self._family(ip) == 6 else "blocked4"
        self._run(["delete", "element", "inet", self.TABLE, setname, "{" + ip + "}"])

    def list_blocked(self):
        out = []
        for setname in ("blocked4", "blocked6"):
            res = self._run(["list", "set", "inet", self.TABLE, setname])
            text = getattr(res, "stdout", "") or ""
            # elements appear inside `elements = { a, b, c }`
            if "elements" in text:
                inside = text.split("elements", 1)[1]
                inside = inside[inside.find("{") + 1: inside.find("}")]
                for part in inside.split(","):
                    ip = part.strip()
                    if ip:
                        out.append(ip)
        return sorted(out)


def make_backend(kind):
    if kind == "nftables":
        if shutil.which("nft") is None:
            raise RuntimeError("nft not found; install nftables or set responder_backend: memory")
        return NftablesBackend()
    if kind == "memory":
        return MemoryBackend()
    raise ValueError(f"unknown responder backend: {kind}")


class Responder:
    """Turns an alert into an action, gated by mode and the allowlist.

    - off:     do nothing.
    - monitor: never block. (alerting happens elsewhere.)
    - enforce: block the offending IP, unless it is on the allowlist.

    The allowlist check is the lock that stops the tool blocking the address the
    operator administers the host from. It is checked on every block request,
    not just at startup.
    """

    def __init__(self, mode, allowlist, backend, log_path="responder.log"):
        self.mode = mode
        self.allowlist = set(allowlist or [])
        self.backend = backend
        self.log_path = log_path
        self._blocked = {}   # ip -> reason, what this process blocked

    def _log(self, msg):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} {msg}"
        print(line, flush=True)
        try:
            with open(self.log_path, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def is_allowlisted(self, ip):
        return ip in self.allowlist

    def handle_alert(self, ip, count, reason):
        """Called when a detector fires. Returns one of:
        'blocked', 'skipped-allowlist', 'skipped-monitor', 'noop-off',
        'already-blocked'."""
        if self.mode == "off":
            return "noop-off"
        if self.mode == "monitor":
            return "skipped-monitor"
        # enforce
        if self.is_allowlisted(ip):
            self._log(f"SKIP block src={ip} reason=allowlisted "
                      f"(would have blocked for {reason}, count={count})")
            return "skipped-allowlist"
        if ip in self._blocked:
            return "already-blocked"
        self.backend.block(ip)
        self._blocked[ip] = reason
        self._log(f"BLOCK src={ip} reason={reason} count={count}")
        return "blocked"

    def unblock(self, ip):
        self.backend.unblock(ip)
        self._blocked.pop(ip, None)
        self._log(f"UNBLOCK src={ip}")

    def blocked_ips(self):
        return sorted(self._blocked.keys())
