#!/usr/bin/env python3
"""Northwind shipment-tracking app on a deliberately fragile server.

The server has a fixed worker pool. Real visitor actions (loading the page,
tracking a shipment) consume a worker for the duration of the request. A
connection-exhaustion attack holds workers open, so when the pool is full a real
visitor's /track request cannot get a worker and HANGS - the site is genuinely
unusable, which is exactly what an overwhelmed real server does.

Endpoints:
  GET /            -> the tracking page (HTML)
  GET /track?id=X  -> shipment status JSON (does a little "work", needs a worker)
  GET /appstate    -> health (fast path, does not consume a pool worker)

A Slowloris that sends partial headers and never finishes holds its worker until
READ_TIMEOUT, so N held connections == N workers busy.
"""
import argparse
import json
import random
import socket
import threading
import time

TOTAL = 8
BUSY = 0
LOCK = threading.Lock()
READ_TIMEOUT = 20
PAGE = b""   # set in main

STATUSES = [
    ("In transit", "Chicago, IL", "Denver, CO"),
    ("Out for delivery", "Denver, CO", "Denver, CO"),
    ("At sorting facility", "Memphis, TN", "Dallas, TX"),
    ("Departed origin", "Newark, NJ", "Atlanta, GA"),
    ("Customs clearance", "Los Angeles, CA", "Phoenix, AZ"),
]


def track_result(tid):
    # deterministic-ish result from the id so the same number gives the same status
    random.seed(hash(tid) & 0xffff)
    st, origin, dest = random.choice(STATUSES)
    eta_days = random.randint(1, 5)
    steps = ["Label created", "Picked up", "Departed origin",
             "In transit", "At facility", "Out for delivery"]
    done = random.randint(2, 5)
    return {
        "id": tid, "status": st, "origin": origin, "destination": dest,
        "eta": "%d day(s)" % eta_days,
        "steps": [{"name": s, "done": i < done} for i, s in enumerate(steps)],
    }


def handle(conn):
    global BUSY
    with LOCK:
        BUSY += 1
    try:
        conn.settimeout(READ_TIMEOUT)
        data = b""
        try:
            data = conn.recv(2048)
        except Exception:
            return
        if not data:
            return
        line = data.split(b"\r\n", 1)[0]
        path = line.split(b" ")[1] if len(line.split(b" ")) > 1 else b"/"
        pstr = path.decode("latin1")

        # health: fast path
        if pstr.startswith("/appstate"):
            with LOCK:
                free = TOTAL - BUSY
            body = json.dumps({"app": "northwind", "workers_total": TOTAL,
                               "workers_free": free, "healthy": free > 0}).encode()
            _send(conn, "application/json", body)
            return

        # tracking: real work that needs this worker for a moment
        if pstr.startswith("/track"):
            tid = "NW000000"
            if "id=" in pstr:
                tid = pstr.split("id=", 1)[1].split("&")[0] or tid
            time.sleep(0.4)   # simulate a DB/backend lookup: holds the worker
            body = json.dumps(track_result(tid)).encode()
            _send(conn, "application/json", body)
            return

        # any normal page: finish reading headers (so a slowloris partial request
        # blocks here holding the worker), then serve the tracking page.
        while b"\r\n\r\n" not in data:
            try:
                chunk = conn.recv(1024)
            except Exception:
                return
            if not chunk:
                return
            data += chunk
        _send(conn, "text/html", PAGE)
    finally:
        with LOCK:
            BUSY -= 1
        try:
            conn.close()
        except Exception:
            pass


def _send(conn, ctype, body):
    try:
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
                     b"Access-Control-Allow-Origin: *\r\nContent-Length: %d\r\n"
                     b"Connection: close\r\n\r\n%s"
                     % (ctype.encode(), len(body), body))
    except Exception:
        pass


def main():
    global TOTAL, PAGE
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--html", default=None)
    args = p.parse_args()
    TOTAL = args.workers
    if args.html:
        with open(args.html, "rb") as f:
            PAGE = f.read()
    else:
        PAGE = b"<h1>Northwind</h1>"

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(64)
    print("Northwind tracking app on 0.0.0.0:%d with %d workers; /track, /appstate"
          % (args.port, TOTAL), flush=True)
    sem = threading.BoundedSemaphore(TOTAL)

    def worker(c):
        try:
            handle(c)
        finally:
            sem.release()

    while True:
        conn, _ = srv.accept()
        # try to get a worker, but WAIT up to a few seconds if the pool is full.
        # during an attack every worker is held, so a real visitor's request waits
        # here (their browser shows a spinner) and then gives up - the realistic
        # "the site is hanging / not responding" experience.
        got = sem.acquire(timeout=8)
        if not got:
            try:
                conn.close()
            except Exception:
                pass
            continue
        threading.Thread(target=worker, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
