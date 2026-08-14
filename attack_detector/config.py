"""Load config.yaml, filling in defaults for anything absent."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "mode": "monitor",
    "admin_allowlist": ["127.0.0.1"],
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
