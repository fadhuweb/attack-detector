#!/usr/bin/env bash
# Run the engine from the repo root, using the venv if one exists.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -x .venv/bin/python ]]; then
  exec ./.venv/bin/python -m attack_detector.engine "$@"
fi
exec python3 -m attack_detector.engine "$@"
