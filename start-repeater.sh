#!/usr/bin/env bash
# Guided F680 onboarding: unlock, scan from the router, select Wi-Fi, install.
set -eu
cd "$(dirname "$0")"

if [ "${1:-}" = "--serve-only" ]; then
    exec python3 tools/serve.py
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required. Install Python 3 and retry." >&2
    exit 1
fi

if ! python3 -c "import requests, Crypto" >/dev/null 2>&1; then
    echo "[*] Installing Python dependencies (requests, pycryptodome) ..."
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        if ! python3 -m pip install -r requirements.txt; then
            echo "[-] pip install failed. Install manually:" >&2
            echo "    python3 -m pip install -r requirements.txt" >&2
            exit 1
        fi
    else
        if ! python3 -m pip install --user -r requirements.txt 2>/dev/null; then
            if ! python3 -m pip install --user --break-system-packages -r requirements.txt 2>/dev/null; then
                echo "[-] pip install failed. Install manually:" >&2
                echo "    python3 -m pip install -r requirements.txt" >&2
                exit 1
            fi
        fi
    fi
fi

exec python3 tools/onboard.py "$@"
