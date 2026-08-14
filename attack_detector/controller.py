import threading
import time
import yaml
from pathlib import Path


class Controller:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self._lock = threading.Lock()
        self.mode = "monitor"
        self.admin_allowlist = set(["127.0.0.1"])
        self._last_mtime = 0
        self._load()

    def _load(self):
        if not self.config_path.exists():
            return
        mtime = self.config_path.stat().st_mtime
        if mtime == self._last_mtime:
            return
        with self._lock:
            with open(self.config_path, "r") as f:
                cfg = yaml.safe_load(f) or {}
            self.mode = cfg.get("mode", self.mode)
            allow = cfg.get("admin_allowlist", [])
            self.admin_allowlist = set(allow)
            self._last_mtime = mtime

    def start_reload_loop(self, interval: float = 2.0):
        def loop():
            while True:
                try:
                    self._load()
                except Exception:
                    pass
                time.sleep(interval)

        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def is_enforce(self) -> bool:
        return self.mode == "enforce"

    def is_monitor(self) -> bool:
        return self.mode == "monitor"

    def is_off(self) -> bool:
        return self.mode == "off"
