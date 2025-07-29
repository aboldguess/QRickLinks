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
    source env.sh
fi

# Activate the virtual environment
source venv/bin/activate

# Ensure the database schema is ready before starting
python - <<PY
from app import initialize_database
initialize_database()
PY

# Choose the appropriate server
if [ "$DEV" -eq 1 ]; then
    python rpi_qrlinks.py "$PORT"
else
    python rpi_qrlinks.py "$PORT" --production
fi
