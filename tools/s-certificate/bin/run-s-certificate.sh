#!/usr/bin/env bash
# Run the certificate generator.
# Usage:  ./bin/run-s-certificate.sh <domain> [options]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Auto-activate the virtual environment if it exists and isn't already active.
if [ -z "${VIRTUAL_ENV:-}" ]; then
    if [ -f "venv/bin/activate" ]; then
        # shellcheck disable=SC1091
        source venv/bin/activate
    elif [ -f ".venv/bin/activate" ]; then
        # shellcheck disable=SC1091
        source .venv/bin/activate
    fi
fi

PYTHONPATH=src exec python3 -m s_certificate "$@"
