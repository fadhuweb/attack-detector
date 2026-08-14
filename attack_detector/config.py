"""Load config.yaml, filling in defaults for anything absent."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

MODES = ("off", "monitor", "enforce")

DEFAULTS: dict[str, Any] = {
    "mode": "monitor",
    # Deliberately empty. An unset allowlist must never be mistaken for a safe
    # one, so enforce mode refuses to start until it is filled in -- see
    # validate_config below.
    "admin_allowlist": [],
    "sources": {
        "auth": {
            # "file" reads the path below; "journald" shells out to journalctl
            # for hosts with no rsyslog.
            "type": "file",
            "path": "/var/log/auth.log",
            "unit": "ssh",
        },
    },
    "thresholds": {
        "failed_login": 5,
        "failed_login_window": 60,
    },
    "alerts": {
        "path": "logs/alerts.log",
    },
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return copy.deepcopy(DEFAULTS)
    with open(path, "r", errors="replace") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping at the top level")
    return _merge(DEFAULTS, loaded)


def validate_config(config: dict[str, Any]) -> list[str]:
    """Return the reasons this config must not be run, empty if it is fine."""
    errors: list[str] = []

    mode = config.get("mode")
    if mode not in MODES:
        errors.append(f"mode is {mode!r}, expected one of {', '.join(MODES)}")

    if mode == "enforce" and not config.get("admin_allowlist"):
        errors.append(
            "mode is 'enforce' but admin_allowlist is empty. Enforcing with no "
            "allowlist can block the address you administer this host from and "
            "lock you out. Set admin_allowlist in config.yaml first -- run "
            "scripts/verify_day1.sh to see the address the target sees you on."
        )

    source = config.get("sources", {}).get("auth", {})
    if source.get("type") not in ("file", "journald"):
        errors.append(f"sources.auth.type is {source.get('type')!r}, expected 'file' or 'journald'")

    return errors
