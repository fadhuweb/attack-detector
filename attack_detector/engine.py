import argparse
import signal
import sys
import threading
from datetime import datetime

from .config import load_config, ConfigError
from .collectors.auth_collector import AuthCollector
from .collectors.access_collector import AccessCollector
from .detectors.bruteforce import BruteForceDetector
from .detectors.flood import AggregateFloodDetector
from .alerting import Alerter
from .responder import Responder, make_backend
from .controller import Controller


def _handle(signum, frame):
    raise KeyboardInterrupt


def _log(msg):
    print(f"{datetime.now():%H:%M:%S} {msg}", flush=True)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="attack-detector (day 8: brute-force + aggregate flood detection)"
    )
    p.add_argument("-c", "--config")
    p.add_argument("--auth-source", choices=["file", "journald"])
    p.add_argument("--auth-log")
    p.add_argument("--access-log")
    p.add_argument("--mode", choices=["off", "monitor", "enforce"])
    p.add_argument("--from-start", action="store_true", default=None)
    p.add_argument("--print-events", action="store_true")
    args = p.parse_args(argv)

    try:
        cfg = load_config(args.config, overrides={
            "auth_source": args.auth_source,
            "auth_log": args.auth_log,
            "access_log": args.access_log,
            "mode": args.mode,
            "from_start": args.from_start,
        })
    except ConfigError as e:
        _log(f"ERROR config: {e}")
        return 2

    signal.signal(signal.SIGTERM, _handle)

    bf = BruteForceDetector(cfg.bf_window, cfg.bf_threshold, cfg.bf_pair_grace)
    flood = AggregateFloodDetector(cfg.flood_window, cfg.flood_threshold,
                                   cfg.flood_cooldown)
    alerter = Alerter(path=cfg.alert_log)

    try:
        backend = make_backend(cfg.responder_backend)
    except RuntimeError as e:
        _log(f"ERROR responder: {e}")
        return 2
    responder = Responder(cfg.mode, cfg.admin_allowlist, backend,
                          log_path=cfg.responder_log)

    controller = Controller(
        responder, bf, alerter,
        state_path=cfg.control_state,
        command_path=cfg.control_commands,
        status_path=cfg.control_status,
        on_mode_change=lambda o, n: _log(f"mode changed live: {o} -> {n}"),
    )

    if cfg.auth_source == "journald":
        _log(f"auth source: journald unit={cfg.journald_unit}")
    else:
        _log(f"auth source: file {cfg.auth_log}")
    _log(f"brute-force rule: >{cfg.bf_threshold} failed logins per IP in {cfg.bf_window}s")
    if cfg.flood_enabled:
        _log(f"flood rule: >{cfg.flood_threshold} total requests in {cfg.flood_window}s "
             f"(reads {cfg.access_log})")
    _log(f"mode={cfg.mode}  responder={cfg.responder_backend}  allowlist={cfg.admin_allowlist}")

    controller.start()

    def on_bruteforce(ip, count, reason):
        alerter.fire("bruteforce", ip, count, reason, responder.mode)
        result = responder.handle_alert(ip, count, reason)
        if result == "skipped-allowlist":
            _log(f"note: {ip} is allowlisted; alerted but not blocked")

    def on_flood(count, top_sources):
        top = ", ".join(f"{ip}({n})" for ip, n in top_sources)
        alerter.fire("flood", "aggregate", count,
                     f"volumetric flood; top: {top}", responder.mode)
        _log(f"FLOOD alert: {count} requests in window; top sources: {top}")
        # a distributed flood has no single IP to block; the aggregate alert is
        # the action for now. rate-limiting is day 10.

    stop = threading.Event()

    def ticker():
        while not stop.wait(1.0):
            for ip, count, reason in bf.tick():
                on_bruteforce(ip, count, reason)

    threading.Thread(target=ticker, daemon=True).start()

    # access-log collector runs in its own thread feeding the flood detector
    def access_loop():
        collector = AccessCollector(path=cfg.access_log, from_start=cfg.from_start)
        try:
            for ev in collector.events():
                if stop.is_set():
                    break
                res = flood.observe(ev)
                if res:
                    on_flood(res[0], res[1])
        except Exception as e:
            _log(f"access collector stopped: {e}")

    if cfg.flood_enabled:
        threading.Thread(target=access_loop, daemon=True).start()

    auth = AuthCollector(
        source=cfg.auth_source, path=cfg.auth_log,
        unit=cfg.journald_unit, from_start=cfg.from_start,
    )
    try:
        for ev in auth.events():
            if args.print_events:
                print(f"{ev.log_ts or '-'} [auth] {ev}", flush=True)
            for ip, count, reason in bf.observe(ev):
                on_bruteforce(ip, count, reason)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        controller.stop()

    if responder.blocked_ips():
        _log(f"blocked this session: {responder.blocked_ips()}")
        _log("remove all with: sudo nft flush table inet attack_detector")
    _log("collector stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
