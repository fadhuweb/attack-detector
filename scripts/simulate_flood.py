#!/usr/bin/env python3
"""Simulate flood traffic by appending nginx-format lines to an access log.

Two shapes:
  --distributed  many source IPs, few requests each (the DDoS shape a per-IP
                 rule cannot catch)
  --single       one source IP, all the requests (a single-source flood)

This writes directly to the access log the engine tails, so it exercises the
real detector path without needing to spoof network packets. For a real
network-level test, use ab/curl from the attacker VM (see README day 9).

Usage:
  sudo python3 scripts/simulate_flood.py --distributed --requests 3000 --ips 500 \
       --log /var/log/nginx/access.log
  sudo python3 scripts/simulate_flood.py --single --requests 3000 \
       --ip 192.168.50.11 --log /var/log/nginx/access.log
"""
import argparse
import random
import time
from datetime import datetime, timezone


def line(ip, path="/"):
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (f'{ip} - - [{ts}] "GET {path} HTTP/1.1" 200 100 "-" "flood-sim/1.0"')


def distributed(n, num_ips):
    # spread n requests across num_ips distinct source addresses
    ips = [f"198.51.{i // 256}.{i % 256 + 1}" for i in range(num_ips)]
    out = []
    for i in range(n):
        out.append(line(random.choice(ips)))
    return out


def single(n, ip):
    return [line(ip) for _ in range(n)]


def main():
    p = argparse.ArgumentParser(description="append simulated flood traffic to an access log")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--distributed", action="store_true",
                   help="many IPs, few requests each (DDoS shape)")
    g.add_argument("--single", action="store_true",
                   help="one IP, all requests")
    p.add_argument("--requests", type=int, default=3000)
    p.add_argument("--ips", type=int, default=500, help="distinct IPs for --distributed")
    p.add_argument("--ip", default="192.168.50.11", help="source IP for --single")
    p.add_argument("--log", default="/var/log/nginx/access.log")
    p.add_argument("--burst", type=int, default=0,
                   help="if set, write this many lines then sleep 0.1s, repeat, "
                        "to spread the flood over time instead of all at once")
    args = p.parse_args()

    if args.distributed:
        lines = distributed(args.requests, args.ips)
        shape = f"{args.requests} requests across {args.ips} IPs"
    else:
        lines = single(args.requests, args.ip)
        shape = f"{args.requests} requests from {args.ip}"

    random.shuffle(lines)
    with open(args.log, "a") as f:
        if args.burst:
            for i in range(0, len(lines), args.burst):
                f.write("\n".join(lines[i:i + args.burst]) + "\n")
                f.flush()
                time.sleep(0.1)
        else:
            f.write("\n".join(lines) + "\n")
    print(f"wrote {shape} to {args.log}")


if __name__ == "__main__":
    main()
