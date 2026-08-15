#!/usr/bin/env bash
set -euo pipefail
# One-time target setup: adm group for auth.log, and PyYAML.

if id -nG "$USER" | grep -qw adm; then
  echo "user $USER already in adm group"
else
  echo "adding $USER to adm group (needs sudo)..."
  sudo usermod -aG adm "$USER"
  echo ">> log out and back in for the group to take effect, then re-run this script"
fi

python3 -c "import yaml" 2>/dev/null && echo "PyYAML present" || {
  echo "installing PyYAML..."
  pip3 install --user pyyaml 2>/dev/null || sudo apt-get install -y python3-yaml
}

echo -n "auth.log readable: "
if [ -r /var/log/auth.log ]; then echo "yes"; else echo "NO (adm group not active yet? re-login)"; fi
