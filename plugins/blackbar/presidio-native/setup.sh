#!/usr/bin/env bash
# Create the native blackbar analyzer environment: a venv with presidio-analyzer
# + flask and the spaCy models for the chosen languages. No Docker required.
#
#   ./setup.sh                  # en es fr de it pt, md models
#   BLACKBAR_LANGUAGES="en es" ./setup.sh
#   BLACKBAR_MODEL_SIZE=lg ./setup.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${BLACKBAR_VENV:-$HOME/.local/share/blackbar/presidio-venv}"
LANGS="${BLACKBAR_LANGUAGES:-en es fr de it pt}"
SIZE="${BLACKBAR_MODEL_SIZE:-md}"
LANGS="${LANGS//,/ }"   # accept comma or space separated

echo "venv:   $VENV"
echo "langs:  $LANGS"
echo "size:   $SIZE"

python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$HERE/requirements.txt"

for lang in $LANGS; do
  if [ "$lang" = "en" ]; then model="en_core_web_${SIZE}"; else model="${lang}_core_news_${SIZE}"; fi
  echo "downloading $model"
  "$VENV/bin/python" -m spacy download "$model"
done

echo "done. start with: BLACKBAR_LANGUAGES=\"${LANGS// /,}\" BLACKBAR_MODEL_SIZE=$SIZE ./run.sh"
