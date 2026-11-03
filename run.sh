#!/usr/bin/env bash
# Starts the prototype on http://127.0.0.1:8000 (demo mode: fictional data, quick-login box).
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pip install -q --break-system-packages -r requirements.txt 2>/dev/null || python3 -m pip install -q -r requirements.txt
python3 -m app.seed
export ZS_DEMO="${ZS_DEMO:-1}"
[ "$ZS_DEMO" = "1" ] && echo "!! DEMO-MODUS aktiv: Schnell-Login auf der Startseite. In Produktion ZS_DEMO=0 setzen."
exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port "${PORT:-8000}"
