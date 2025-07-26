#!/usr/bin/env python3
"""Run the QRickLinks Flask app on a Raspberry Pi.

This script allows specifying the port via a command line argument so the
application can be easily hosted on different ports without modifying the
source code.

Usage:
    python run_rpi.py [port]
If no port is provided, the server defaults to port 5000.
"""

import sys

# Import the Flask application instance from app.py
# Import the Flask app and database initialization helper
from app import app, initialize_database


def main() -> None:
    """Parse the optional port argument and start the server."""
    default_port = 5000
    port = default_port

    # Attempt to read the first command line argument as the port number
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port '{sys.argv[1]}'. Using default {default_port}.")
            port = default_port

    # Prepare the database before starting
    initialize_database()
    # Run the Flask app on all network interfaces so it's accessible on the LAN
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
