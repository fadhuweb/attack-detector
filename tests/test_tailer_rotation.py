import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_detector.collectors.tailer import Tailer

_fail = []


def check(name, cond):
    print(f"  {'ok  ' if cond else 'FAIL'} {name}")
    if not cond:
        _fail.append(name)


class Harness:
    """Run Tailer.follow in a background thread and let the test wait for lines
    to actually arrive, instead of sleeping a fixed guess. This makes the test
    deterministic on a slow VM: each step blocks until the expected line shows
    up or a generous timeout expires."""

    def __init__(self, path, from_start=False, poll=0.05):
        self.out = []
        self._lock = threading.Lock()
        gen = Tailer(path, poll_interval=poll).follow(from_start=from_start)

        def run():
            try:
                for line in gen:
                    with self._lock:
                        self.out.append(line)
            except Exception:
                pass

        self._th = threading.Thread(target=run, daemon=True)
        self._th.start()
        time.sleep(0.4)   # let follow open and seek before the test acts

    def lines(self):
        with self._lock:
            return list(self.out)

    def wait_for(self, substr, timeout=6.0):
        """Block until a line containing substr has arrived, or timeout."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if any(substr in ln for ln in self.lines()):
                return True
            time.sleep(0.05)
        return False

    def wait_absent(self, substr, settle=0.8):
        """Give time to pass, then confirm no line contains substr (used to
        prove backlog was skipped)."""
        time.sleep(settle)
        return not any(substr in ln for ln in self.lines())


def tmp():
    d = tempfile.mkdtemp()
    return os.path.join(d, "auth.log")


# A. follows appends on a pre-existing file
p = tmp()
open(p, "w").close()
h = Harness(p)
with open(p, "a") as f:
    f.write("line1\n"); f.flush()
    f.write("line2\n"); f.flush()
check("follows appends", h.wait_for("line1") and h.wait_for("line2"))

# B. skips backlog on a file that existed at start
p = tmp()
with open(p, "w") as f:
    f.write("old1\nold2\n")
h = Harness(p)
with open(p, "a") as f:
    f.write("new1\n"); f.flush()
check("skips pre-existing backlog",
      h.wait_for("new1") and "old1" not in " ".join(h.lines()))

# C. picks up a file created after start, from the beginning
p = tmp()
h = Harness(p)
with open(p, "w") as f:
    f.write("first\nsecond\n"); f.flush()
check("late-created file read from start",
      h.wait_for("first") and h.wait_for("second"))

# D. copytruncate: file truncated in place, tailing continues
p = tmp()
open(p, "w").close()
h = Harness(p)
with open(p, "a") as f:
    f.write("a\n"); f.flush()
h.wait_for("a")                       # wait until 'a' is seen before truncating
with open(p, "r+") as f:
    f.truncate(0)
time.sleep(0.3)                       # let the tailer notice the shrink
with open(p, "a") as f:
    f.write("b\n"); f.flush()
check("copytruncate keeps following", h.wait_for("a") and h.wait_for("b"))

# E. rename rotation: file renamed away, new file at same path (Linux)
p = tmp()
open(p, "w").close()
h = Harness(p)
with open(p, "a") as f:
    f.write("before\n"); f.flush()
h.wait_for("before")                  # wait until 'before' is seen before rotating
os.rename(p, p + ".1")                # rotate old file away
time.sleep(0.3)                       # let the tailer notice the missing/renamed file
with open(p, "w") as f:               # new file appears at the same path
    f.write("after\n"); f.flush()
check("survives rename rotation", h.wait_for("before") and h.wait_for("after"))

print()
if _fail:
    print(f"{len(_fail)} check(s) failed")
    sys.exit(1)
print("all checks passed")
