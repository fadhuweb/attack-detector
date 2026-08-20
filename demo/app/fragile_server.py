#!/usr/bin/env python3
"""Deliberately fragile 'Northwind app' server for the demo.

Design goal: a held-open connection DETERMINISTICALLY occupies one worker. The
server has a fixed worker pool. Each worker, once it accepts a connection, reads
the HTTP request until the blank line that ends the headers. A Slowloris client
that sends partial headers and never sends that blank line keeps its worker
blocked until the socket read times out. So:

    connections held  ==  workers busy

which makes the crash predictable: N slow connections against N workers saturates
the pool, and /appstate reports unhealthy (or the app stops answering).

/appstate is answered on a FAST path that does not consume a pool worker, so the
health check still works right up until saturation and reports it honestly.
"""
import argparse
import socket
import threading
import time

PORTAL_HTML = b"<!doctype html><h1>Northwind App</h1><p>online</p>"
STATE_LOCK = threading.Lock()
BUSY = 0
TOTAL = 8
READ_TIMEOUT = 20     # a held connection occupies its worker up to this long


def handle_conn(conn):
    """A worker: read the full request (headers up to blank line), then respond.
    A slowloris never sends the blank line, so this blocks until timeout, holding
    the worker the whole time. That is the point."""
    global BUSY
    with STATE_LOCK:
        BUSY += 1
    try:
        conn.settimeout(READ_TIMEOUT)
        data = b""
        # fast path: health check. peek the first line; if it's /appstate, answer
        # immediately without waiting for full headers.
        try:
            first = conn.recv(1024)
        except Exception:
            return
        data += first
        if b"/appstate" in first.split(b"\r\n", 1)[0]:
            with STATE_LOCK:
                free = TOTAL - BUSY
                healthy = free > 0
            body = ('{"app":"northwind","workers_total":%d,"workers_free":%d,'
                    '"healthy":%s}' % (TOTAL, free, "true" if healthy else "false")).encode()
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                         b"Access-Control-Allow-Origin: *\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\n\r\n%s"
                         % (len(body), body))
            return
        # normal path: read until end-of-headers blank line. A slowloris that
        # never sends it will block here until READ_TIMEOUT, holding this worker.
        while b"\r\n\r\n" not in data:
            try:
                chunk = conn.recv(1024)
            except Exception:
                return          # timed out waiting: worker was held, now freed
            if not chunk:
                return
            data += chunk
        # got a full request: serve the page
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                     b"Access-Control-Allow-Origin: *\r\n"
                     b"Content-Length: %d\r\nConnection: close\r\n\r\n%s"
                     % (len(PORTAL_HTML), PORTAL_HTML))
    finally:
        with STATE_LOCK:
            BUSY -= 1
        try:
            conn.close()
        except Exception:
            pass


def health_path_server(host, port):
    """A separate always-responsive listener JUST for /appstate on port+1 is not
    needed; /appstate is handled inline on the fast path above."""
    pass


def main():
    global TOTAL, PORTAL_HTML
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--html", default=None)
    args = p.parse_args()
    TOTAL = args.workers
    if args.html:
        with open(args.html, "rb") as f:
            PORTAL_HTML = f.read()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(64)   # accept backlog; workers is the real limit
    print(f"fragile app on 0.0.0.0:{args.port} with {TOTAL} deterministic workers; "
          f"/appstate for health", flush=True)

    sem = threading.BoundedSemaphore(TOTAL)

    def worker(conn):
        try:
            handle_conn(conn)
        finally:
            sem.release()

    while True:
        conn, _ = srv.accept()
        got = sem.acquire(blocking=False)
        if not got:
            # pool exhausted: refuse immediately (this is the app "down" for new
            # visitors). Close without serving.
            try:
                conn.close()
            except Exception:
                pass
            continue
        threading.Thread(target=worker, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
