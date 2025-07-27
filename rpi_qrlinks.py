#!/usr/bin/env python3
"""Run the QRickLinks Flask app on a Raspberry Pi.

This helper accepts a port number as its first argument and can optionally
start a production-ready WSGI server when the ``--production`` flag is
present.  Without the flag the built-in Flask development server is used.

Usage::

    python rpi_qrlinks.py [port] [--production]

Omitting ``port`` defaults to ``5000``.
"""

import argparse

# Import the Flask application instance from app.py
# Import the Flask app and database initialization helper
from app import app, initialize_database

try:
    # Waitress is a lightweight production WSGI server
    from waitress import serve
except ImportError:  # pragma: no cover - waitress is optional in dev
    serve = None


def main() -> None:
    """Parse command line arguments and start the appropriate server."""
    parser = argparse.ArgumentParser(
        description="Run QRickLinks on a Raspberry Pi"
    )
    parser.add_argument(
        "port",
        nargs="?",
        default=5000,
        type=int,
        help="Port number to bind to (default: 5000)",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Use the Waitress WSGI server for production",
    )

    args = parser.parse_args()

    # Prepare the database before starting the web server
    initialize_database()

    if args.production and serve:
        # Start the app with Waitress for better performance in production
        serve(app, host="0.0.0.0", port=args.port)
    else:
        # Fall back to the built-in development server
        app.run(host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
