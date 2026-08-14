"""The record every collector produces and every detector consumes."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Event:
    """One parsed occurrence from a source.

    ``ts`` is ingest time, and it is what the sliding-window counters use. It
    stays monotonic with the running engine even when a log line carries a
    stale or clock-skewed timestamp. ``log_ts`` keeps the time the source
    itself claimed, which is what we want for display and for replaying an
    existing file after the fact.
    """

    event_type: str
    src_ip: Optional[str] = None
    source: str = ""
    ts: float = field(default_factory=time.time)
    log_ts: Optional[float] = None
    raw: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        stamp = time.strftime("%H:%M:%S", time.localtime(self.log_ts or self.ts))
        detail = " ".join(f"{k}={v}" for k, v in self.extra.items())
        return (
            f"{stamp} [{self.source}] {self.event_type} "
            f"src={self.src_ip or '-'}{' ' + detail if detail else ''}"
        )
