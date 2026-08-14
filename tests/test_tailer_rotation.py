"""Prove the tailer survives both rotation styles. Runs on Windows or Linux.

Run from the repo root:  python -m tests.test_tailer_rotation
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attack_detector.collectors.tailer import FileTailer

FAILURES: list[str] = []


def check(name: str, got, want) -> None:
    if got == want:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}\n         got:  {got!r}\n         want: {want!r}")
        FAILURES.append(name)


def append(path: Path, text: str) -> None:
    with open(path, "a") as handle:
        handle.write(text + "\n")
        handle.flush()


def collect(path: Path, actions, settle: float = 1.5) -> list[str]:
    """Run the tailer over ``path`` while ``actions`` writes to it."""
    seen: list[str] = []
    lock = threading.Lock()

    def on_line(line: str) -> None:
        with lock:
            seen.append(line)

    tailer = FileTailer(str(path), on_line, poll_interval=0.05)
    tailer.start()
    time.sleep(0.4)  # let it open and seek to the end
    actions()
    time.sleep(settle)
    tailer.stop()
    tailer.join(timeout=2.0)
    with lock:
        return list(seen)


def test_follows_appends() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "auth.log"
        append(path, "line one")  # written before start, must be skipped

        def actions() -> None:
            append(path, "line two")
            time.sleep(0.2)
            append(path, "line three")

        seen = collect(path, actions)
        check("skips pre-existing content", "line one" in seen, False)
        check("follows appends", seen, ["line two", "line three"])


def test_rename_rotation() -> None:
    # Windows refuses to rename a file while a handle is open, so this case is
    # only exercisable on the target. The code path it covers is the default
    # logrotate behaviour, so run this suite on the VM too.
    if sys.platform == "win32":
        print("  skip rename rotation (not possible on Windows; verify on the target)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "auth.log"
        path.touch()

        def actions() -> None:
            append(path, "before rotate")
            time.sleep(0.4)
            os.replace(path, Path(tmp) / "auth.log.1")  # logrotate default
            append(path, "after rotate")

        seen = collect(path, actions, settle=2.5)
        check("reads across rename rotation", seen, ["before rotate", "after rotate"])


def test_copytruncate_rotation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "auth.log"
        path.touch()

        def actions() -> None:
            append(path, "before truncate")
            time.sleep(0.4)
            with open(path, "w"):  # same inode, emptied in place
                pass
            time.sleep(0.3)
            append(path, "after truncate")

        seen = collect(path, actions, settle=2.5)
        check("reads across copytruncate", seen, ["before truncate", "after truncate"])


def test_waits_for_missing_file() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "not-yet.log"

        def actions() -> None:
            time.sleep(0.5)
            append(path, "appeared late")

        seen = collect(path, actions, settle=2.5)
        check("picks up a file created after start", seen, ["appeared late"])


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
