#!/usr/bin/env bash
# Make nginx demo-vulnerable to a lab-sized Slowloris by capping its connection
# capacity. This scales the VICTIM down to match the one-VM attacker, so the
# attack, detection, and blocking stay real while the site can actually be
# overwhelmed. Reversible with --restore.
#
#   sudo bash demo/nginx_demo_limits.sh          # apply demo limits
#   sudo bash demo/nginx_demo_limits.sh --restore
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "run as root on the target" >&2; exit 1; fi

DROPIN=/etc/nginx/conf.d/zz-demo-limits.conf
MAINBAK=/etc/nginx/nginx.conf.demobak

if [ "${1:-}" = "--restore" ]; then
  echo ">> restoring nginx to normal capacity"
  rm -f "$DROPIN"
  if [ -f "$MAINBAK" ]; then mv "$MAINBAK" /etc/nginx/nginx.conf; fi
  nginx -t && systemctl reload nginx
  echo "== restored =="
  exit 0
fi

echo ">> backing up nginx.conf"
cp -n /etc/nginx/nginx.conf "$MAINBAK" || true

echo ">> capping worker_connections so a lab slowloris can exhaust nginx"
# worker_connections lives in the events{} block in the main file; force it low.
# Use sed to set it to 64 (from the usual 768/1024).
sed -i -E 's/worker_connections[[:space:]]+[0-9]+;/worker_connections 64;/' /etc/nginx/nginx.conf
grep -q "worker_connections" /etc/nginx/nginx.conf || \
  sed -i 's/events[[:space:]]*{/events {\n    worker_connections 64;/' /etc/nginx/nginx.conf

# also force a single worker process so the 64 is the whole budget, and add
# short client header timeouts so held-open connections are the binding limit
echo ">> writing demo drop-in ($DROPIN)"
cat > "$DROPIN" <<EOF
# demo limits: small connection budget + tight timeouts so Slowloris bites.
# remove with: sudo bash demo/nginx_demo_limits.sh --restore
client_header_timeout 30s;
client_body_timeout   30s;
keepalive_timeout     15s;
EOF

# pin worker_processes to 1 so total capacity = worker_connections
sed -i -E 's/worker_processes[[:space:]]+[a-z0-9]+;/worker_processes 1;/' /etc/nginx/nginx.conf

nginx -t && systemctl reload nginx
echo
echo "== nginx is now demo-vulnerable =="
echo "capacity: 1 worker x 64 connections. A 1500-conn Slowloris will exhaust it,"
echo "so in MONITOR the portal stalls; in ENFORCE the engine blocks the attacker"
echo "and the portal recovers."
echo "restore normal capacity when done:  sudo bash demo/nginx_demo_limits.sh --restore"
