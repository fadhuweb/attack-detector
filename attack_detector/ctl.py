import argparse
import json
import os
import sys


def _write_mode(state_path, mode):
    with open(state_path, "w") as f:
        json.dump({"mode": mode}, f)
    print(f"requested mode -> {mode} (engine applies within ~1s)")


def _append_command(command_path, cmd):
    with open(command_path, "a") as f:
        f.write(json.dumps(cmd) + "\n")
    print(f"queued: {cmd}")


def _show_status(status_path):
    if not os.path.exists(status_path):
        print("no status file yet; is the engine running?")
        return
    with open(status_path) as f:
        s = json.load(f)
    print(f"mode:      {s.get('mode')}")
    print(f"uptime:    {s.get('uptime_seconds')}s")
    print(f"threshold: >{s.get('threshold')} in {s.get('window_seconds')}s")
    print(f"allowlist: {s.get('allowlist')}")
    print(f"blocked:   {s.get('blocked')}")
    print(f"limited:   {s.get('limited')}")
    print(f"updated:   {s.get('updated')}")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="ctl",
        description="control a running attack-detector engine without restarting it")
    p.add_argument("--state", default="control.json")
    p.add_argument("--commands", default="commands.jsonl")
    p.add_argument("--status", default="status.json")
    sub = p.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mode", help="set mode: off | monitor | enforce")
    m.add_argument("value", choices=["off", "monitor", "enforce"])

    u = sub.add_parser("unblock", help="release a blocked IP")
    u.add_argument("ip")

    ul = sub.add_parser("unlimit", help="remove a rate-limit from an IP")
    ul.add_argument("ip")

    b = sub.add_parser("block", help="manually block an IP (allowlist still applies)")
    b.add_argument("ip")

    sub.add_parser("status", help="print current engine status")

    args = p.parse_args(argv)

    if args.cmd == "mode":
        _write_mode(args.state, args.value)
    elif args.cmd == "unblock":
        _append_command(args.commands, {"action": "unblock", "ip": args.ip})
    elif args.cmd == "unlimit":
        _append_command(args.commands, {"action": "unlimit", "ip": args.ip})
    elif args.cmd == "block":
        _append_command(args.commands, {"action": "block", "ip": args.ip})
    elif args.cmd == "status":
        _show_status(args.status)
    return 0


if __name__ == "__main__":
    sys.exit(main())
