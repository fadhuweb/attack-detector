"""Flask API for the attack-detector engine.

It does NOT run detection. It is a thin control surface that:
  - reads status.json (the engine writes it)
  - reads alerts.log  (the alerter writes it)
  - writes control.json / commands.jsonl (the controller watches them)

So the API and the engine stay decoupled: the API is just a web front end over
the same files the ctl CLI already uses. Bind to localhost; require a token.
"""
import json
import os
from functools import wraps

from flask import Flask, jsonify, request


def _read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _tail_lines(path, n):
    try:
        with open(path) as f:
            lines = f.readlines()
        return [ln.rstrip("\n") for ln in lines[-n:]]
    except FileNotFoundError:
        return []


def create_app(status_path="status.json",
               control_state="control.json",
               control_commands="commands.jsonl",
               alert_log="alerts.log",
               token=None,
               static_dir=None):
    if static_dir is None:
        static_dir = os.path.join(os.path.dirname(__file__), "static")
    app = Flask(__name__, static_folder=static_dir, static_url_path="")

    @app.after_request
    def _cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "X-Auth-Token, Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp

    def require_token(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            if token:
                sent = request.headers.get("X-Auth-Token") or request.args.get("token")
                if sent != token:
                    return jsonify({"error": "unauthorized"}), 401
            return fn(*a, **k)
        return wrapper

    def _queue_command(cmd):
        try:
            with open(control_commands, "a") as f:
                f.write(json.dumps(cmd) + "\n")
            return None
        except OSError as e:
            return e

    def _write_state(mode):
        try:
            with open(control_state, "w") as f:
                json.dump({"mode": mode}, f)
            return None
        except OSError as e:
            return e

    def _perm_hint(e):
        return (f"cannot write control file: {e}. The engine and API must run as "
                f"the same user (both under sudo, or both as the service user). "
                f"This is fixed by the systemd install.")

    @app.get("/api/status")
    @require_token
    def status():
        s = _read_json(status_path)
        if s is None:
            return jsonify({"error": "no status yet; is the engine running?"}), 503
        return jsonify(s)

    @app.get("/api/alerts")
    @require_token
    def alerts():
        n = request.args.get("n", default=50, type=int)
        return jsonify({"alerts": _tail_lines(alert_log, n)})

    @app.post("/api/mode")
    @require_token
    def set_mode():
        body = request.get_json(silent=True) or {}
        mode = body.get("mode")
        if mode not in ("off", "monitor", "enforce"):
            return jsonify({"error": "mode must be off, monitor, or enforce"}), 400
        err = _write_state(mode)
        if err is not None:
            return jsonify({"error": _perm_hint(err)}), 500
        return jsonify({"ok": True, "requested_mode": mode})

    @app.post("/api/unblock")
    @require_token
    def unblock():
        body = request.get_json(silent=True) or {}
        ip = body.get("ip")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        err = _queue_command({"action": "unblock", "ip": ip})
        if err is not None:
            return jsonify({"error": _perm_hint(err)}), 500
        return jsonify({"ok": True, "queued": {"unblock": ip}})

    @app.post("/api/unlimit")
    @require_token
    def unlimit():
        body = request.get_json(silent=True) or {}
        ip = body.get("ip")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        err = _queue_command({"action": "unlimit", "ip": ip})
        if err is not None:
            return jsonify({"error": _perm_hint(err)}), 500
        return jsonify({"ok": True, "queued": {"unlimit": ip}})

    @app.post("/api/block")
    @require_token
    def block():
        body = request.get_json(silent=True) or {}
        ip = body.get("ip")
        if not ip:
            return jsonify({"error": "ip required"}), 400
        err = _queue_command({"action": "block", "ip": ip})
        if err is not None:
            return jsonify({"error": _perm_hint(err)}), 500
        return jsonify({"ok": True, "queued": {"block": ip}})

    @app.route("/api/<path:_any>", methods=["OPTIONS"])
    def _preflight(_any):
        return ("", 204)

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True})

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    return app


def main(argv=None):
    import argparse
    from ..config import load_config
    p = argparse.ArgumentParser(description="attack-detector API server")
    p.add_argument("-c", "--config")
    p.add_argument("--host", default="127.0.0.1")   # localhost only by default
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--token", help="require this token on API calls")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    token = args.token or os.environ.get("AD_API_TOKEN")
    app = create_app(
        status_path=cfg.control_status,
        control_state=cfg.control_state,
        control_commands=cfg.control_commands,
        alert_log=cfg.alert_log,
        token=token,
    )
    print(f"API on http://{args.host}:{args.port}  (token {'set' if token else 'NONE - localhost only'})",
          flush=True)
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
