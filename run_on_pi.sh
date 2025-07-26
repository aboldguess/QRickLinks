#!/bin/bash

# QRickLinks hosting helper script for Raspberry Pi
# Usage: ./run_on_pi.sh [PORT]
# If PORT is omitted, the server runs on port 5000.

# Read the first argument as the desired port, falling back to 5000
PORT=${1:-5000}

# Install Python dependencies listed in requirements.txt
pip install --quiet -r requirements.txt

# Start the application accessible from the network
python app.py --port "$PORT"
