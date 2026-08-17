import os
from dataclasses import dataclass

try:
    import yaml
except ImportError:
    yaml = None

VALID_MODES = ("off", "monitor", "enforce")

DEFAULTS = {
    "mode": "monitor",
    "auth_source": "file",
    "auth_log": "/var/log/auth.log",
    "journald_unit": "ssh",
    "from_start": False,
    "admin_allowlist": [],
    "alert_log": "alerts.log",
    "responder_backend": "nftables",   # nftables | memory (memory = dry run)
    "responder_log": "responder.log",
    "control_state": "control.json",
    "control_commands": "commands.jsonl",
    "control_status": "status.json",
    # brute-force rule
    "bf_window": 60,
    "bf_threshold": 5,
    "bf_pair_grace": 3.0,
    # aggregate flood rule (DDoS / volumetric)
    "access_log": "/var/log/nginx/access.log",
    "flood_enabled": True,
    "flood_window": 10,
    "flood_threshold": 2000,
    "flood_cooldown": 30,
    # per-IP request rate rule (single-source flood)
    "req_window": 5,
    "req_threshold": 100,
    "req_cooldown": 30,
    "req_rate_limit": 20,   # in enforce, cap a flooding IP to this many req/sec
    # connection-state rule (SYN flood + Slowloris)
    "connstate_enabled": True,
    "connstate_interval": 5,     # seconds between ss samples
    "syn_threshold": 100,        # SYN-RECV half-open connections fires syn_flood
    "conn_threshold": 50,        # established conns from ONE ip fires conn_hold
    "connstate_cooldown": 30,    # seconds between repeat conn-state alerts
}


@dataclass
class Config:
    mode: str
    auth_source: str
    auth_log: str
    journald_unit: str
    from_start: bool
    admin_allowlist: list
    alert_log: str
    responder_backend: str
    responder_log: str
    control_state: str
    control_commands: str
    control_status: str
    bf_window: int
    bf_threshold: int
    bf_pair_grace: float
    access_log: str
    flood_enabled: bool
    flood_window: int
    flood_threshold: int
    flood_cooldown: int
    req_window: int
    req_threshold: int
    req_cooldown: int
    req_rate_limit: int
    connstate_enabled: bool
    connstate_interval: int
    syn_threshold: int
    conn_threshold: int
    connstate_cooldown: int


class ConfigError(Exception):
    pass


def load_config(path=None, overrides=None):
    data = dict(DEFAULTS)
    if path and os.path.exists(path):
        if yaml is None:
            raise RuntimeError("PyYAML not installed; pip install -r requirements.txt")
        with open(path) as f:
            loaded = yaml.safe_load(f) or {}
        data.update({k: v for k, v in loaded.items() if v is not None})
    if overrides:
        data.update({k: v for k, v in overrides.items() if v is not None})

    cfg = Config(
        mode=data["mode"],
        auth_source=data["auth_source"],
        auth_log=data["auth_log"],
        journald_unit=data["journald_unit"],
        from_start=bool(data["from_start"]),
        admin_allowlist=list(data["admin_allowlist"] or []),
        alert_log=data["alert_log"],
        responder_backend=data["responder_backend"],
        responder_log=data["responder_log"],
        control_state=data["control_state"],
        control_commands=data["control_commands"],
        control_status=data["control_status"],
        bf_window=int(data["bf_window"]),
        bf_threshold=int(data["bf_threshold"]),
        bf_pair_grace=float(data["bf_pair_grace"]),
        access_log=data["access_log"],
        flood_enabled=bool(data["flood_enabled"]),
        flood_window=int(data["flood_window"]),
        flood_threshold=int(data["flood_threshold"]),
        flood_cooldown=int(data["flood_cooldown"]),
        req_window=int(data["req_window"]),
        req_threshold=int(data["req_threshold"]),
        req_cooldown=int(data["req_cooldown"]),
        req_rate_limit=int(data["req_rate_limit"]),
        connstate_enabled=bool(data["connstate_enabled"]),
        connstate_interval=int(data["connstate_interval"]),
        syn_threshold=int(data["syn_threshold"]),
        conn_threshold=int(data["conn_threshold"]),
        connstate_cooldown=int(data["connstate_cooldown"]),
    )
    validate_config(cfg)
    return cfg


def validate_config(cfg):
    """Raise ConfigError on a config that is unsafe to run. The important rule:
    enforce mode with an empty allowlist can block the operator's own admin
    address and lock them out, so it is refused."""
    if cfg.mode not in VALID_MODES:
        raise ConfigError(f"mode must be one of {VALID_MODES}, got '{cfg.mode}'")
    if cfg.mode == "enforce" and not cfg.admin_allowlist:
        raise ConfigError(
            "mode is 'enforce' but admin_allowlist is empty. Enforcing with no "
            "allowlist can block the address you administer this host from and "
            "lock you out. Set admin_allowlist in config.yaml first. SSH via "
            "VirtualBox NAT arrives as 10.0.2.2; confirm yours with: who")
    return cfg
