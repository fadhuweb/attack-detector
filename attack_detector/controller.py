import json
import os
import threading
import time
from datetime import datetime


VALID_MODES = ("off", "monitor", "enforce")


class Controller:
    """Live control surface for a running engine.

    Reads two files so an operator (or later, the dashboard API) can change the
    engine without restarting it:

      state_path   (control.json)   - {"mode": "..."} the desired mode
      command_path (commands.jsonl) - one JSON command per line, consumed FIFO

    A background thread polls both once a second. Mode changes are applied to the
    live responder; commands (currently `unblock` and `block`) run immediately.
    The controller also writes a status file the dashboard reads.

    Safety: switching to enforce at runtime re-checks the allowlist guard, the
    same rule as startup, so enforcement cannot be armed with an empty allowlist.
    """

    def __init__(self, responder, detector, alerter,
                 state_path="control.json",
                 command_path="commands.jsonl",
                 status_path="status.json",
                 poll_interval=1.0,
                 on_mode_change=None):
        self.responder = responder
        self.detector = detector
        self.alerter = alerter
        self.state_path = state_path
        self.command_path = command_path
        self.status_path = status_path
        self.poll_interval = poll_interval
        self.on_mode_change = on_mode_change
        self._stop = threading.Event()
        self._thread = None
        self._started_at = time.time()
        self._log_path = "controller.log"

    # ---- logging ----
    def _log(self, msg):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} {msg}"
        print(line, flush=True)
        try:
            with open(self._log_path, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass

    # ---- mode changes ----
    def set_mode(self, mode):
        """Apply a mode to the live responder. Returns (ok, message). Refuses to
        arm enforce with an empty allowlist, matching the startup guard."""
        if mode not in VALID_MODES:
            return False, f"invalid mode '{mode}'"
        if mode == self.responder.mode:
            return True, f"mode already {mode}"
        if mode == "enforce" and not self.responder.allowlist:
            msg = ("refused: enforce with empty allowlist would risk locking you "
                   "out. set admin_allowlist first.")
            self._log(f"MODE change refused off->enforce: empty allowlist")
            return False, msg
        old = self.responder.mode
        self.responder.mode = mode
        self._log(f"MODE {old} -> {mode}")
        if self.on_mode_change:
            self.on_mode_change(old, mode)
        return True, f"mode {old} -> {mode}"

    # ---- commands ----
    def run_command(self, cmd):
        """Execute one command dict. Returns (ok, message)."""
        action = cmd.get("action")
        if action == "set_mode":
            return self.set_mode(cmd.get("mode"))
        if action == "unblock":
            ip = cmd.get("ip")
            if not ip:
                return False, "unblock requires an ip"
            self.responder.unblock(ip)
            self._log(f"COMMAND unblock {ip}")
            return True, f"unblocked {ip}"
        if action == "block":
            ip = cmd.get("ip")
            if not ip:
                return False, "block requires an ip"
            # manual block still respects the allowlist
            if self.responder.is_allowlisted(ip):
                return False, f"{ip} is allowlisted; not blocking"
            self.responder.backend.block(ip)
            self.responder._blocked[ip] = "manual"
            self._log(f"COMMAND block {ip} (manual)")
            return True, f"blocked {ip}"
        return False, f"unknown action '{action}'"

    # ---- file polling ----
    def _read_desired_mode(self):
        try:
            with open(self.state_path) as f:
                data = json.load(f)
            return data.get("mode")
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def _drain_commands(self):
        """Read and clear the command file, running each line."""
        if not os.path.exists(self.command_path):
            return
        try:
            with open(self.command_path) as f:
                lines = f.readlines()
        except OSError:
            return
        # clear first so a slow command can't be run twice on the next poll
        try:
            open(self.command_path, "w").close()
        except OSError:
            pass
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except json.JSONDecodeError:
                self._log(f"bad command line ignored: {line[:80]}")
                continue
            ok, msg = self.run_command(cmd)
            self._log(f"cmd result: {msg}" if ok else f"cmd FAILED: {msg}")

    def write_status(self):
        status = {
            "mode": self.responder.mode,
            "uptime_seconds": round(time.time() - self._started_at, 1),
            "blocked": self.responder.blocked_ips(),
            "allowlist": sorted(self.responder.allowlist),
            "threshold": self.detector.counter.threshold,
            "window_seconds": self.detector.counter.window,
            "updated": datetime.now().isoformat(timespec="seconds"),
        }
        try:
            tmp = self.status_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(status, f, indent=2)
            os.replace(tmp, self.status_path)   # atomic
        except OSError:
            pass
        return status

    def poll_once(self):
        desired = self._read_desired_mode()
        if desired and desired != self.responder.mode:
            self.set_mode(desired)
        self._drain_commands()
        self.write_status()

    # ---- background loop ----
    def start(self):
        # seed the state file with the current mode if absent
        if not os.path.exists(self.state_path):
            try:
                with open(self.state_path, "w") as f:
                    json.dump({"mode": self.responder.mode}, f)
            except OSError:
                pass
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.wait(self.poll_interval):
            try:
                self.poll_once()
            except Exception as e:   # a bad file must not kill the engine
                self._log(f"controller poll error: {e}")

    def stop(self):
        self._stop.set()
