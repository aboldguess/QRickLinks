#!/usr/bin/env bash
# Setup script for QRickLinks on an Azure Ubuntu VM.
# Installs dependencies, creates a virtual environment, and generates
# a SECRET_KEY if one is not already present.

set -euo pipefail

# Update package list and install Python if needed
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip

# Create a Python virtual environment called 'venv' if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate the virtual environment for package installation
source venv/bin/activate

# Ensure the latest pip is available
pip install --upgrade pip

# Install required Python packages from requirements.txt
pip install -r requirements.txt

# Generate a random SECRET_KEY when not provided and store it in env.sh
if [ -z "${SECRET_KEY:-}" ]; then
    SECRET_KEY=$(python - <<'PY'
import secrets, base64
print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
PY
)
    echo "export SECRET_KEY=${SECRET_KEY}" > env.sh
    echo "A new SECRET_KEY was generated and written to env.sh"
fi

echo "Setup complete. Run ./run_server.sh to start the application."
