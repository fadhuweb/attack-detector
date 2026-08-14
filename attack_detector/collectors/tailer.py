"""Follow a growing log file the way ``tail -F`` does.

A log tailer that only calls ``readline`` in a loop stops working the first
time logrotate runs, which on a real target is nightly. This one notices both
rotation styles: a rename (the path now points at a different inode) and
copytruncate (same inode, size dropped below where we were reading).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Callable, Optional


class FileTailer:
    def __init__(
        self,
        path: str,
        on_line: Callable[[str], None],
        poll_interval: float = 0.2,
        from_start: bool = False,
    ):
        self.path = Path(path)
        self.on_line = on_line
        self.poll_interval = poll_interval
        self.from_start = from_start
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._file_id: Optional[tuple[int, int]] = None
        self._buf = ""
        self._opened_once = False
        self._saw_missing = False

    def start(self) -> None:
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def run(self) -> None:
        """Block, reading lines until :meth:`stop` is called."""
        handle = None
        try:
            while not self._stop.is_set():
                if handle is None:
                    handle = self._open()
                    if handle is None:
                        # File not there yet. It may appear later (fresh VM,
                        # rotation gap), so wait rather than give up.
                        self._stop.wait(self.poll_interval * 5)
                        continue

                chunk = handle.readline()
                if chunk:
                    self._buf += chunk
                    if self._buf.endswith("\n"):
                        line, self._buf = self._buf.rstrip("\n"), ""
                        if line:
                            self.on_line(line)
                    continue

                # Nothing to read. Check whether the file moved out from under us.
                if self._rotated(handle):
                    handle.close()
                    handle = None
                    self._buf = ""
                    continue

                self._stop.wait(self.poll_interval)
        finally:
            if handle:
                handle.close()

    def _open(self):
        try:
            handle = open(self.path, "r", errors="replace")
        except OSError:
            self._saw_missing = True
            return None
        # Skip to the end only when we are attaching to a log that was already
        # there when we started -- its backlog is history we must not alert on.
        # Every other case (rotation, or a file that appeared after we began
        # watching) is entirely new content, so it gets read from the top.
        attaching_to_existing = not self._opened_once and not self._saw_missing
        if not self.from_start and attaching_to_existing:
            handle.seek(0, os.SEEK_END)
        self._opened_once = True
        st = os.fstat(handle.fileno())
        self._file_id = (st.st_dev, st.st_ino)
        return handle

    def _rotated(self, handle) -> bool:
        try:
            st = os.stat(self.path)
        except OSError:
            return True  # Renamed away and no replacement yet.

        if (st.st_dev, st.st_ino) != self._file_id:
            return True  # Rename-style rotation: the path is a new file now.

        if st.st_size < handle.tell():
            # copytruncate: same file, emptied in place. Keep the handle and
            # start over from the top.
            handle.seek(0)

        return False
