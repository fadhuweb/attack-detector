import os
import time


class Tailer:
    """Follow a file like `tail -F`. Survives rename-rotation and copytruncate,
    and picks up a file that appears after start.

    A file that already exists at start has its backlog skipped (unless
    from_start). A file that does not exist yet is read from the beginning once
    it appears, because on a fresh host the first lines are the first events.
    """

    def __init__(self, path, poll_interval=0.5):
        self.path = path
        self.poll_interval = poll_interval

    def _open(self):
        try:
            return open(self.path, "r")
        except FileNotFoundError:
            return None

    def follow(self, from_start=False):
        f = self._open()
        if f is not None:
            if not from_start:
                f.seek(0, os.SEEK_END)
            inode = os.fstat(f.fileno()).st_ino
        else:
            inode = None
        buf = ""

        while True:
            if f is None:
                f = self._open()
                if f is None:
                    time.sleep(self.poll_interval)
                    continue
                inode = os.fstat(f.fileno()).st_ino
                buf = ""

            chunk = f.readline()
            if chunk:
                buf += chunk
                if buf.endswith("\n"):
                    line = buf.rstrip("\n")
                    buf = ""
                    yield line
                continue

            time.sleep(self.poll_interval)
            try:
                st = os.stat(self.path)
            except FileNotFoundError:
                f.close()
                f = None
                inode = None
                buf = ""
                continue

            if st.st_ino != inode:            # rename rotation: new file at same path
                f.close()
                f = self._open()
                if f is not None:
                    inode = os.fstat(f.fileno()).st_ino
                buf = ""
                continue

            if st.st_size < f.tell():          # copytruncate: file shrank
                f.seek(0)
                buf = ""
                continue
