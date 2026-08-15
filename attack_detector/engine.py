import argparse
import signal
import sys
import threading
from datetime import datetime

from .config import load_config, ConfigError
from .collectors.auth_collector import AuthCollector
from .detectors.bruteforce import BruteForceDetector
from .alerting import Alerter
from .responder import Responder, make_backend
from .controller import Controller


def _handle(signum, frame):
    raise KeyboardInterrupt


def _log(msg):
    print(f"{datetime.now():%H:%M:%S} {msg}", flush=True)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="attack-detector (day 4: live control without restart)"
    )
    p.add_argument("-c", "--config")
    p.add_argument("--auth-source", choices=["file", "journald"])
    p.add_argument("--auth-log")
    p.add_argument("--mode", choices=["off", "monitor", "enforce"])
    p.add_argument("--from-start", action="store_true", default=None)
    p.add_argument("--print-events", action="store_true")
    args = p.parse_args(argv)

    try:
        cfg = load_config(args.config, overrides={
            "auth_source": args.auth_source,
            "auth_log": args.auth_log,
            "mode": args.mode,
            "from_start": args.from_start,
        })
    except ConfigError as e:
        _log(f"ERROR config: {e}")
        return 2

    signal.signal(signal.SIGTERM, _handle)

    detector = BruteForceDetector(
        window_seconds=cfg.bf_window,
        threshold=cfg.bf_threshold,
        pair_grace=cfg.bf_pair_grace,
    )
    alerter = Alerter(path=cfg.alert_log)

    try:
        backend = make_backend(cfg.responder_backend)
    except RuntimeError as e:
        _log(f"ERROR responder: {e}")
        return 2
    responder = Responder(cfg.mode, cfg.admin_allowlist, backend,
                          log_path=cfg.responder_log)

    def on_mode_change(old, new):
        _log(f"mode changed live: {old} -> {new}")

    controller = Controller(
        responder, detector, alerter,
        state_path=cfg.control_state,
        command_path=cfg.control_commands,
        status_path=cfg.control_status,
        on_mode_change=on_mode_change,
    )

    if cfg.auth_source == "journald":
        _log(f"auth source: journald unit={cfg.journald_unit}")
    else:
        _log(f"auth source: file {cfg.auth_log}")
    _log(f"brute-force rule: >{cfg.bf_threshold} failed logins per IP in {cfg.bf_window}s")
    _log(f"mode={cfg.mode}  responder={cfg.responder_backend}  allowlist={cfg.admin_allowlist}")
    _log(f"live control: edit {cfg.control_state} or use ctl.py; status in {cfg.control_status}")

    controller.start()

    def on_alert(ip, count, reason):
        alerter.fire("bruteforce", ip, count, reason, responder.mode)
        result = responder.handle_alert(ip, count, reason)
        if result == "skipped-allowlist":
            _log(f"note: {ip} is allowlisted; alerted but not blocked")

    stop = threading.Event()

    def ticker():
        while not stop.wait(1.0):
            for ip, count, reason in detector.tick():
                on_alert(ip, count, reason)

    th = threading.Thread(target=ticker, daemon=True)
    th.start()

    collector = AuthCollector(
        source=cfg.auth_source,
        path=cfg.auth_log,
        unit=cfg.journald_unit,
        from_start=cfg.from_start,
    )
    try:
        for ev in collector.events():
            if args.print_events:
                print(f"{ev.log_ts or '-'} [auth] {ev}", flush=True)
            for ip, count, reason in detector.observe(ev):
                on_alert(ip, count, reason)
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
