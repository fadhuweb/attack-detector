#!/usr/bin/env bash
# Start the whole demo on the ATTACKER in one command.
# Runs the probe, the launcher, and the demo page server, checks they came up,
# and stops all three cleanly on Ctrl+C.
#
#   bash demo/start_demo.sh
#
# Env overrides (optional):
#   TARGET_IP=192.168.50.10  PROBE_PORT=8080  LAUNCH_PORT=8090  PAGE_PORT=8070
#   LAUNCH_TOKEN=pickatoken
set -euo pipefail

TARGET_IP="${TARGET_IP:-192.168.50.10}"
PROBE_PORT="${PROBE_PORT:-8080}"
LAUNCH_PORT="${LAUNCH_PORT:-8090}"
PAGE_PORT="${PAGE_PORT:-8070}"
LAUNCH_TOKEN="${LAUNCH_TOKEN:-pickatoken}"

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

echo ">> stopping any old demo services on these ports"
# kill anything we previously started; ignore if nothing is there
pkill -f "probe.py --target" 2>/dev/null || true
pkill -f "launcher.py --port" 2>/dev/null || true
pkill -f "http.server $PAGE_PORT" 2>/dev/null || true
sleep 1

PIDS=()
cleanup(){
  echo
  echo ">> stopping demo services"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  # also stop any attack still running via the launcher's own process group
  pkill -f "probe.py --target" 2>/dev/null || true
  pkill -f "launcher.py --port" 2>/dev/null || true
  pkill -f "http.server $PAGE_PORT" 2>/dev/null || true
  echo ">> done."
  exit 0
}
trap cleanup INT TERM

echo ">> starting probe (measuring http://$TARGET_IP/health.html) on :$PROBE_PORT"
python3 probe.py --target "http://$TARGET_IP/health.html" --port "$PROBE_PORT" \
  >/tmp/demo_probe.log 2>&1 &
PIDS+=($!)

echo ">> starting launcher (target locked to $TARGET_IP) on :$LAUNCH_PORT"
AD_DEMO_TOKEN="$LAUNCH_TOKEN" python3 launcher.py --host 0.0.0.0 --port "$LAUNCH_PORT" --token "$LAUNCH_TOKEN" \
  >/tmp/demo_launcher.log 2>&1 &
PIDS+=($!)

echo ">> starting demo page server on :$PAGE_PORT"
python3 -m http.server "$PAGE_PORT" --bind 0.0.0.0 >/tmp/demo_page.log 2>&1 &
PIDS+=($!)

sleep 2

echo
echo ">> health check:"
ok=1
for p in "$PROBE_PORT" "$LAUNCH_PORT" "$PAGE_PORT"; do
  if ss -tlnp 2>/dev/null | grep -q ":$p "; then
    echo "   :$p  up"
  else
    echo "   :$p  NOT LISTENING  (see /tmp/demo_*.log)"
    ok=0
  fi
done

echo
if [ "$ok" -eq 1 ]; then
  cat <<EOF
== demo services running ==
  probe     :$PROBE_PORT   (health JSON)
  launcher  :$LAUNCH_PORT   (token: $LAUNCH_TOKEN)
  page      :$PAGE_PORT   (demo.html)

On your workstation, open ONE tunnel to the attacker and ONE to the target:

  # attacker: page + probe + launcher
  ssh -L $PAGE_PORT:127.0.0.1:$PAGE_PORT -L $PROBE_PORT:127.0.0.1:$PROBE_PORT -L $LAUNCH_PORT:127.0.0.1:$LAUNCH_PORT <attacker-user>@localhost -p 2223
  # target: detector API (8787) AND the live portal (80 -> local 8088)
  ssh -L 8787:127.0.0.1:8787 -L 8088:127.0.0.1:80 <target-user>@localhost -p 2222

Audience page: http://127.0.0.1:$PAGE_PORT/show.html
  (technical page still at /demo.html)

Leave this terminal running. Ctrl+C here stops all three services.
EOF
else
  echo "!! one or more services failed to start; check /tmp/demo_probe.log, /tmp/demo_launcher.log, /tmp/demo_page.log"
fi

# keep the script alive so the background services keep running until Ctrl+C
wait
