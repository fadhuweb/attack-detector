"""Engine entrypoint.

Day 1 scope: stand up the auth collector and print every event it parses.
Detection, response and the mode toggle arrive on the following days.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from .config import load_config, validate_config
from .collectors.auth_collector import AuthCollector, JournaldAuthCollector
from .events import Event

DEFAULT_CONFIG = "config.yaml"
log = logging.getLogger("attack_detector")


def build_auth_collector(config: dict, on_event, from_start: bool):
    source = config["sources"]["auth"]
    if source.get("type") == "journald":
        log.info("auth source: journald unit=%s", source.get("unit", "ssh"))
        return JournaldAuthCollector(on_event, unit=source.get("unit", "ssh"))
    log.info("auth source: file %s", source["path"])
    return AuthCollector(source["path"], on_event, from_start=from_start)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="attack-detector")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG)
    parser.add_argument(
        "--auth-log",
        help="override the configured auth log path (useful for replaying a sample)",
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="read the log from its beginning instead of following new lines only",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    config = load_config(args.config)

    errors = validate_config(config)
    if errors:
        for error in errors:
            log.error("config: %s", error)
        return 2

    if args.auth_log:
        config["sources"]["auth"]["type"] = "file"
        config["sources"]["auth"]["path"] = args.auth_log

    counts: dict[str, int] = {}
    lock = threading.Lock()

    def on_event(event: Event) -> None:
        with lock:
            counts[event.event_type] = counts.get(event.event_type, 0) + 1
        print(event, flush=True)

    collector = build_auth_collector(config, on_event, args.from_start)
    collector.start()
    log.info("collector running, mode=%s (day 1: printing only)", config["mode"])

    stop = threading.Event()
    # SIGTERM as well as SIGINT: systemd stops the service with TERM, and the
    # summary below should still print instead of the process being killed.
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        stop.wait()
    except KeyboardInterrupt:
        pass

    collector.stop()
    collector.join(timeout=2.0)
    with lock:
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
    log.info("stopped. events seen: %s", summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
