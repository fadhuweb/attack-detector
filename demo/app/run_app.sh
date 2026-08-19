#!/usr/bin/env bash
# Run the fragile Northwind app server on the TARGET. It serves the portal and
# can genuinely be crashed by a connection-exhaustion attack.
#   bash demo/app/run_app.sh            # 8 workers (default)
#   WORKERS=6 bash demo/app/run_app.sh  # fewer workers = crashes faster
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-8000}"
WORKERS="${WORKERS:-8}"
HTML="$HERE/../site/index.html"
pkill -f "fragile_server.py" 2>/dev/null || true
sleep 1
echo ">> fragile app on :$PORT with $WORKERS workers (serving the Northwind portal)"
exec python3 "$HERE/fragile_server.py" --port "$PORT" --workers "$WORKERS" --html "$HTML"
