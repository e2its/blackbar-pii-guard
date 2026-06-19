#!/usr/bin/env bash
# Launch the native blackbar analyzer on :5002 (the default PRESIDIO_ANALYZER_URL).
# Loads the spaCy models once and serves POST /analyze. Set BLACKBAR_LANGUAGES /
# BLACKBAR_MODEL_SIZE to the same values used in setup.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${BLACKBAR_VENV:-$HOME/.local/share/blackbar/presidio-venv}"

export PORT="${PORT:-5002}"
export BLACKBAR_LANGUAGES="${BLACKBAR_LANGUAGES:-en,es,fr,de,it,pt}"
export BLACKBAR_MODEL_SIZE="${BLACKBAR_MODEL_SIZE:-md}"

exec "$VENV/bin/python" "$HERE/analyzer_service.py"
