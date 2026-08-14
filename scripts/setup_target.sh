#!/usr/bin/env bash
# Day 1 setup, run once on the target VM (192.168.50.10).
# Creates the Python env and grants read access to the auth log.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Python env"
sudo apt-get install -y python3-venv >/dev/null
python3 -m venv .venv
./.venv/bin/pip install -q -r requirements.txt

echo "==> Auth log access"
if [[ ! -r /var/log/auth.log ]]; then
  if [[ ! -e /var/log/auth.log ]]; then
    echo "!! /var/log/auth.log does not exist on this host."
    echo "   rsyslog is probably not installed. Either:"
    echo "     sudo apt-get install -y rsyslog && sudo systemctl enable --now rsyslog"
    echo "   or switch config.yaml to the journald source:"
    echo "     sources.auth.type: journald"
    exit 1
  fi
  echo "   /var/log/auth.log is not readable as $(whoami)."
  echo "   Adding $(whoami) to the 'adm' group."
  sudo usermod -aG adm "$(whoami)"
  echo "   !! Log out and back in for the group to take effect, then re-run this script."
  exit 1
fi

echo "==> auth.log readable as $(whoami). Setup complete."
echo "   Run: ./scripts/run.sh"
