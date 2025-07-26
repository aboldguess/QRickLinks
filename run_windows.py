#!/usr/bin/env python3
"""Utility script to install dependencies and run QRickLinks on Windows.

This script installs the required Python packages, prepares the database, and
starts the Flask application on the specified port. It is intended as a
convenient entry point when developing or running the project on Windows.

Usage:
    python run_windows.py [port]
If no port is provided, the server defaults to 5000.
"""

import subprocess
import sys


def main() -> None:
    """Install dependencies, set up the database and run the server."""
    default_port = 5000
    port = default_port

    # Parse the optional port argument from the command line
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port '{sys.argv[1]}'. Using default {default_port}.")
            port = default_port

    # Install required packages using the current Python interpreter
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

    # Import the Flask application only after dependencies are available
    from app import app, initialize_database

    # Perform database migrations and insert default records
    initialize_database()

    # Start the Flask development server on the chosen port
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
