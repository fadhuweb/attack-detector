#!/usr/bin/env python3
"""A deliberately fragile 'Northwind app' server for the demo.

Unlike nginx, this is easy to overwhelm: a small thread pool and a shallow
listen backlog. Under a connection-exhaustion (Slowloris) or traffic flood it
runs out of workers and stops answering new requests -- it goes DOWN for real,
no artificial cap needed. When the attacker is blocked (enforce mode), the held
connections die, workers free up, and it answers again.

It also exposes /appstate so the demo page can show 'online' vs 'not responding'
without a chart.

Run on the TARGET (behind nothing; it IS the victim app):
    python3 demo/app/fragile_server.py --port 8000 --workers 8
"""
import argparse
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, TCPServer

PORTAL_HTML = None  # loaded from file at start


class BoundedThreadingServer(ThreadingMixIn, TCPServer):
    """A server with a HARD cap on concurrent worker threads and a shallow
    backlog, so it can actually be exhausted. Standard ThreadingHTTPServer
    spawns unlimited threads and is very hard to take down; this one won't."""
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 5          # shallow listen backlog

    def __init__(self, addr, handler, max_workers=8):
        super().__init__(addr, handler)
        self._sem = threading.BoundedSemaphore(max_workers)
        self._active = 0
        self._active_lock = threading.Lock()
        self.max_workers = max_workers

    def process_request(self, request, client_address):
        # if no worker slot is free, DO NOT spawn; refuse by closing. This is
        # what makes the app "go down" under load instead of scaling forever.
        got = self._sem.acquire(blocking=False)
        if not got:
            try:
                request.close()
            except Exception:
                pass
            return
        with self._active_lock:
            self._active += 1
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active -= 1
            self._sem.release()

    def free_workers(self):
        return self.max_workers - self._active


class Handler(BaseHTTPRequestHandler):
    timeout = 20                 # a held connection occupies a worker up to 20s

    def setup(self):
        super().setup()
        # give each connection a read timeout; slow clients hold the worker until
        # this fires, which is what lets a slowloris exhaust the pool.
        try:
            self.connection.settimeout(self.timeout)
        except Exception:
            pass

    def handle_one_request(self):
        # BaseHTTPRequestHandler reads the request line + headers here. A slow
        # client sending headers a byte at a time keeps this worker busy the
        # whole time, exactly the Slowloris effect. We just let it block.
        try:
            super().handle_one_request()
        except Exception:
            self.close_connection = True

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/appstate"):
            free = self.server.free_workers()
            body = ('{"app":"northwind","workers_total":%d,"workers_free":%d,'
                    '"healthy":%s}' % (self.server.max_workers, free,
                                       "true" if free > 0 else "false")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return
        # normal page render
        time.sleep(0.02)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(PORTAL_HTML)


def main():
    global PORTAL_HTML
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--html", default=None)
    args = p.parse_args()

    if args.html:
        with open(args.html, "rb") as f:
            PORTAL_HTML = f.read()
    else:
        PORTAL_HTML = b"<!doctype html><h1>Northwind App</h1><p>online</p>"

    srv = BoundedThreadingServer(("0.0.0.0", args.port), Handler,
                                 max_workers=args.workers)
    print(f"fragile app on 0.0.0.0:{args.port} with {args.workers} workers "
          f"(backlog {srv.request_queue_size}); /appstate for health", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
