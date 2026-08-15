from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import time

SSH_FAILED_LOGIN = "ssh_failed_login"
SSH_INVALID_USER = "ssh_invalid_user"
SSH_AUTH_ABORT = "ssh_auth_abort"
SSH_ACCEPTED_LOGIN = "ssh_accepted_login"


@dataclass
class Event:
    etype: str
    source_ip: str
    ingest_ts: float = field(default_factory=time.time)  # when we saw it; windows use this
    log_ts: Optional[str] = None                          # raw log time, display only
    user: Optional[str] = None
    port: Optional[int] = None
    method: Optional[str] = None
    raw: Optional[str] = None

    def dedupe_key(self):
        # one connection attempt shares (ip, port) across its invalid-user
        # and failed-password lines; day 2 collapses on this.
        return (self.source_ip, self.port)

    def __str__(self):
        parts = [f"[{self.etype}]", f"src={self.source_ip}"]
        if self.user is not None:
            parts.append(f"user={self.user}")
        if self.port is not None:
            parts.append(f"port={self.port}")
        if self.method is not None:
            parts.append(f"method={self.method}")
        return " ".join(parts)
