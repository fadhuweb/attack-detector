#!/usr/bin/env bash
# Install attack-detector as a systemd service on Ubuntu.
# Run from the repo root:  sudo bash deploy/install.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo bash deploy/install.sh" >&2
  exit 1
fi

APP=/opt/attack-detector
ETC=/etc/attack-detector
VAR=/var/lib/attack-detector
SRC="$(cd "$(dirname "$0")/.." && pwd)"

echo ">> installing dependencies"
apt-get update -qq
apt-get install -y -qq python3 python3-yaml python3-flask nftables >/dev/null

echo ">> laying down app at $APP"
mkdir -p "$APP" "$ETC" "$VAR"
cp -r "$SRC/attack_detector" "$APP/"
# runtime dir for control/status/alert files, both services share it
chown -R root:root "$APP" "$VAR"

echo ">> writing config to $ETC/config.yaml"
if [ ! -f "$ETC/config.yaml" ]; then
  # start from the repo config, but repoint runtime paths at $VAR and default
  # to monitor mode so blocking is never armed by a fresh install
  sed -e "s#^control_state:.*#control_state: $VAR/control.json#" \
      -e "s#^control_commands:.*#control_commands: $VAR/commands.jsonl#" \
      -e "s#^control_status:.*#control_status: $VAR/status.json#" \
      -e "s#^alert_log:.*#alert_log: $VAR/alerts.log#" \
      -e "s#^responder_log:.*#responder_log: $VAR/responder.log#" \
      -e "s#^mode:.*#mode: monitor#" \
      "$SRC/config.yaml" > "$ETC/config.yaml"
  # ensure the runtime path keys exist even if the repo config lacked them
  grep -q "^control_state:" "$ETC/config.yaml" || cat >> "$ETC/config.yaml" <<EOF
control_state: $VAR/control.json
control_commands: $VAR/commands.jsonl
control_status: $VAR/status.json
alert_log: $VAR/alerts.log
responder_log: $VAR/responder.log
EOF
  echo "   wrote a fresh config (mode: monitor). review it, especially admin_allowlist."
else
  echo "   $ETC/config.yaml exists; leaving it untouched."
fi

echo ">> generating API token and env file"
if [ ! -f "$ETC/api.env" ]; then
  TOKEN="$(openssl rand -hex 16 2>/dev/null || head -c16 /dev/urandom | xxd -p)"
  cat > "$ETC/api.env" <<EOF
AD_API_TOKEN=$TOKEN
AD_API_PORT=8787
EOF
  chmod 600 "$ETC/api.env"
  echo "   API token written to $ETC/api.env (port 8787)"
else
  echo "   $ETC/api.env exists; keeping existing token."
fi

echo ">> installing systemd units"
cp "$SRC/deploy/attack-detector.service" /etc/systemd/system/
cp "$SRC/deploy/attack-detector-api.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now attack-detector.service
systemctl enable --now attack-detector-api.service

echo
echo "== installed =="
echo "engine:    systemctl status attack-detector"
echo "api:       systemctl status attack-detector-api"
echo "config:    $ETC/config.yaml    (set admin_allowlist before using enforce)"
echo "token:     $ETC/api.env"
echo "dashboard: tunnel with  ssh -L 8787:127.0.0.1:8787 <user>@<host>  then open http://127.0.0.1:8787/"
echo "control:   sudo python3 -m attack_detector.ctl --status $VAR/status.json status"
