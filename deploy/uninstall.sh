#!/usr/bin/env bash
# Remove attack-detector. Run as root.  sudo bash deploy/uninstall.sh
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi

echo ">> stopping services"
systemctl disable --now attack-detector-api.service 2>/dev/null || true
systemctl disable --now attack-detector.service 2>/dev/null || true
rm -f /etc/systemd/system/attack-detector.service /etc/systemd/system/attack-detector-api.service
systemctl daemon-reload

echo ">> flushing the firewall table"
nft delete table inet attack_detector 2>/dev/null || true

echo ">> removing files"
rm -rf /opt/attack-detector
echo "   left /etc/attack-detector and /var/lib/attack-detector in place (config, token, logs)."
echo "   remove them by hand if you want a full wipe:"
echo "     sudo rm -rf /etc/attack-detector /var/lib/attack-detector"
echo "== uninstalled =="
