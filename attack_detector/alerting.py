from datetime import datetime


class Alerter:
    """Day-2 alert sink: writes a line to stdout and to an alert log file.
    Later days add a webhook and feed the dashboard from the same log."""

    def __init__(self, path="alerts.log"):
        self.path = path

    def fire(self, rule, source_ip, count, reason, mode):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = (f"{ts} ALERT rule={rule} src={source_ip} "
                f"count={count} reason={reason} mode={mode}")
        print(line, flush=True)
        try:
            with open(self.path, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass  # never let alert-logging crash the engine
