#!/usr/bin/env bash
# Assay — start the web UI on Linux/macOS:  ./run.sh   (server: ASSAY_AUTH_TOKEN=... ./run.sh --host 0.0.0.0)
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
if [ ! -x .venv/bin/python ]; then
  echo "[assay] Creating virtual environment..."
  "$PY" -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -r requirements.txt
fi
[ -f frontend/dist/index.html ] || echo "[assay] WARNING: frontend/dist missing — run: (cd frontend && npm ci && npm run build)"
cd backend
exec ../.venv/bin/python -m app.cli serve "$@"
