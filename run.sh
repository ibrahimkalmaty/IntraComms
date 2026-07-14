#!/usr/bin/env bash
set -euo pipefail

# Helper to set up venv, install deps, init DB and run the dev server (Linux/macOS)
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

# Activate
source .venv/bin/activate

# Install requirements (no-op if already satisfied)
pip install -r requirements.txt

# Initialize DB if missing
if [ ! -f intracomms.db ]; then
  python -m flask --app server/server.py init-db || true
fi

# Enable debug/reload and run
export FLASK_DEBUG=1
python server/server.py
