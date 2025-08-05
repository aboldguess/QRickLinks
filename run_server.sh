#!/usr/bin/env bash
# Start the QRickLinks server on an Azure VM.
# Usage: ./run_server.sh [-p PORT] [--development]
# By default the app runs with Waitress on the chosen port.

set -euo pipefail

PORT=5000
DEV=0

# Parse command line arguments for port and development mode
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        --development)
            DEV=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Load environment variables if present
if [ -f env.sh ]; then
    # shellcheck disable=SC1091  # env.sh is user generated
    source env.sh
fi

# ---------------------------------------------------------------------------
# Ensure a virtual environment exists so dependencies are isolated. This keeps
# the script self-contained and avoids requiring the separate setup script on
# first run.
# ---------------------------------------------------------------------------
if [ ! -f "venv/bin/activate" ]; then
    echo "Creating Python virtual environment and installing dependencies..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    # Activate the existing environment
    source venv/bin/activate
fi

# Allow incoming traffic on the chosen port when a firewall is active. This
# helps make the app reachable externally without requiring manual steps.
if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
    sudo ufw allow "${PORT}"/tcp || true
elif command -v firewall-cmd >/dev/null 2>&1 && sudo firewall-cmd --state >/dev/null 2>&1; then
    sudo firewall-cmd --permanent --add-port="${PORT}/tcp" && sudo firewall-cmd --reload
fi

# Ensure the database schema is ready before starting
python - <<PY
# Import the database initialisation helper from the project-specific module
from qricklinks_app import initialize_database
initialize_database()
PY

# Choose the appropriate server
if [ "$DEV" -eq 1 ]; then
    python rpi_qrlinks.py "$PORT"
else
    python rpi_qrlinks.py "$PORT" --production
fi
