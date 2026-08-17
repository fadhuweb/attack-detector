import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.detectors.connstate import ConnStateDetector

_fail = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _fail.append(name)


class FakeRes:
    def __init__(self, stdout):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


def make_runner(syn_recv_lines, established_lines):
    """Return an ss runner that responds based on the requested state."""
    def runner(args):
        if "syn-recv" in args:
            header = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            return FakeRes(header + "\n".join(syn_recv_lines) + ("\n" if syn_recv_lines else ""))
        if "established" in args:
            header = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            return FakeRes(header + "\n".join(established_lines) + ("\n" if established_lines else ""))
        return FakeRes("")
    return runner


def syn_line():
    return "SYN-RECV 0 0 192.168.50.10:80 198.51.100.9:44321"


def est_line(peer_ip, port):
    return f"ESTAB 0 0 192.168.50.10:80 {peer_ip}:{port}"


# ---- SYN flood: many half-open connections ----
syns = [syn_line() for _ in range(120)]
d = ConnStateDetector(syn_threshold=100, conn_threshold=50,
                      runner=make_runner(syns, []))
alerts = d.sample()
check("syn flood fires when SYN-RECV over threshold",
      any(a[0] == "syn_flood" and a[2] == 120 for a in alerts))

# ---- below SYN threshold: no alert ----
d = ConnStateDetector(syn_threshold=100, conn_threshold=50,
                      runner=make_runner([syn_line() for _ in range(30)], []))
check("no syn alert below threshold",
      not any(a[0] == "syn_flood" for a in d.sample()))

# ---- Slowloris: one IP holding many established connections ----
est = [est_line("203.0.113.7", 40000 + i) for i in range(60)]        # 60 from one IP
est += [est_line("10.0.0.5", 22)]                                     # a normal one
d = ConnStateDetector(syn_threshold=1000, conn_threshold=50,
                      runner=make_runner([], est))
alerts = d.sample()
check("conn-hold fires for an IP over the connection threshold",
      any(a[0] == "conn_hold" and a[1] == "203.0.113.7" and a[2] == 60 for a in alerts))

# ---- normal spread of connections: no conn-hold alert ----
est = [est_line(f"10.0.0.{i}", 22) for i in range(40)]               # 40 different IPs
d = ConnStateDetector(syn_threshold=1000, conn_threshold=50,
                      runner=make_runner([], est))
check("no conn-hold alert for spread-out connections",
      not any(a[0] == "conn_hold" for a in d.sample()))

# ---- both at once: SYN flood and a slowloris IP ----
syns = [syn_line() for _ in range(150)]
est = [est_line("203.0.113.7", 40000 + i) for i in range(70)]
d = ConnStateDetector(syn_threshold=100, conn_threshold=50,
                      runner=make_runner(syns, est))
alerts = d.sample()
check("detects syn flood and conn-hold together",
      any(a[0] == "syn_flood" for a in alerts)
      and any(a[0] == "conn_hold" and a[1] == "203.0.113.7" for a in alerts))

# ---- empty tables: no alerts, no crash ----
d = ConnStateDetector(runner=make_runner([], []))
check("empty connection table is quiet", d.sample() == [])

# ---- ipv6 peer parsing ----
est = [f"ESTAB 0 0 [::1]:80 [2001:db8::5]:40000" for _ in range(55)]
d = ConnStateDetector(syn_threshold=1000, conn_threshold=50,
                      runner=make_runner([], est))
alerts = d.sample()
check("ipv6 peer grouped correctly",
      any(a[0] == "conn_hold" and a[1] == "2001:db8::5" for a in alerts))

# ---- cooldown: a sustained flood alerts once, not every sample ----
syns = [syn_line() for _ in range(120)]
d = ConnStateDetector(syn_threshold=100, conn_threshold=50,
                      runner=make_runner(syns, []), cooldown=1000)
first = d.sample()
second = d.sample()      # immediately again: still flooding
check("sustained syn flood alerts once within cooldown",
      any(a[0] == "syn_flood" for a in first)
      and not any(a[0] == "syn_flood" for a in second))

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
