#!/usr/bin/env python3
"""Health probe for the demo target site.

Hits the target's health URL once per interval, records whether it responded and
how long it took, and serves a rolling window of readings as JSON. The demo page
polls that JSON to draw the site's health. This is the objective 'is the site up'
signal: measured, not asserted.

Run on the ATTACKER vm (so it measures the site across the network, the same path
an attack degrades):
    python3 demo/probe.py --target http://192.168.50.10/health.html --port 8080
"""
import argparse
import json
import threading
import time
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Probe:
    def __init__(self, url, interval=1.0, window=60, timeout=2.0):
        self.url = url
        self.interval = interval
        self.timeout = timeout
        self.readings = deque(maxlen=window)   # dicts: t, up, ms
        self._stop = threading.Event()

    def _measure(self):
        start = time.time()
        try:
            with urllib.request.urlopen(self.url, timeout=self.timeout) as r:
                r.read(64)
                ms = (time.time() - start) * 1000.0
                return {"t": time.time(), "up": True, "ms": round(ms, 1)}
        except Exception:
            ms = (time.time() - start) * 1000.0
            return {"t": time.time(), "up": False, "ms": round(ms, 1)}

    def loop(self):
        while not self._stop.wait(self.interval):
            self.readings.append(self._measure())

    def start(self):
        threading.Thread(target=self.loop, daemon=True).start()

    def summary(self):
        rs = list(self.readings)
        recent = rs[-10:]
        up_recent = sum(1 for r in recent if r["up"])
        last = rs[-1] if rs else None
        # health verdict from the last 10 readings
        if not recent:
            verdict = "unknown"
        elif up_recent >= 9:
            verdict = "operational"
        elif up_recent >= 5:
            verdict = "degraded"
        else:
            verdict = "down"
        avg_ms = round(sum(r["ms"] for r in recent) / len(recent), 1) if recent else None
        return {
            "verdict": verdict,
            "up_last10": up_recent,
            "avg_ms": avg_ms,
            "last": last,
            "series": rs,
        }


def make_handler(probe):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # quiet
        def do_GET(self):
            if self.path.startswith("/health"):
                body = json.dumps(probe.summary()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()
    return H


def main():
    p = argparse.ArgumentParser(description="demo site health probe")
    p.add_argument("--target", default="http://192.168.50.10/health.html")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--interval", type=float, default=1.0)
    args = p.parse_args()

    probe = Probe(args.target, interval=args.interval)
    probe.start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(probe))
    print(f"probe measuring {args.target} every {args.interval}s; "
          f"readings at http://127.0.0.1:{args.port}/health", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
