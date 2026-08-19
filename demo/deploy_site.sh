#!/usr/bin/env bash
# Deploy the Northwind demo site to nginx on the TARGET. Run as root on target.
#   sudo bash demo/deploy_site.sh
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "run as root on the target" >&2; exit 1; fi

SRC="$(cd "$(dirname "$0")" && pwd)/site"
WWW=/var/www/html

echo ">> backing up current site"
[ -f "$WWW/index.nginx-debian.html" ] && mv "$WWW/index.nginx-debian.html" "$WWW/index.nginx-debian.html.bak" 2>/dev/null || true

echo ">> installing demo site to $WWW"
cp "$SRC/index.html" "$WWW/index.html"
cp "$SRC/health.html" "$WWW/health.html"

echo ">> reloading nginx"
nginx -t && systemctl reload nginx

echo "== demo site live =="
echo "portal:  http://<target>/"
echo "health:  http://<target>/health.html   (should return 'ok')"
echo "test:    curl -s http://127.0.0.1/ | head -3"
