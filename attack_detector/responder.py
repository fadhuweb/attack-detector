"""STALE SCAFFOLD -- rewritten on day 3. Do not import.

Alert-only, no firewall block and no allowlist check. The real responder
replaces this file wholesale.
"""

import logging
from pathlib import Path


class Responder:
    def __init__(self, alerts_path: str, controller):
        self.alerts_path = Path(alerts_path)
        self.controller = controller
        self._logger = logging.getLogger("attack_detector.responder")
        self._logger.setLevel(logging.INFO)
        self._logger.addHandler(logging.StreamHandler())

    def alert(self, rule: str, src_ip: str, detail: dict):
        # Write a line to the alerts log and print
        line = f"ALERT rule={rule} ip={src_ip} detail={detail}\n"
        try:
            self.alerts_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.alerts_path, "a") as f:
                f.write(line)
        except Exception:
            pass
        self._logger.info(line.strip())
