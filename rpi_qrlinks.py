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
import logging

# Import the Flask application instance from the dedicated module
# ``qricklinks_app`` along with helpers for setting up the database and
# reading configuration. Using a descriptive module name makes it clear which
# project the application belongs to and aids debugging when multiple Flask
# apps are installed on the same system.
from qricklinks_app import app, initialize_database, get_settings
import socket
import os

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

    # Update the base URL setting so QR codes and links are reachable over
    # the network.  ``socket`` is used to detect the local IP address without
    # making an external request.  The resulting URL includes the chosen port
    # so it matches the running server.
    from qricklinks_app import db
    with app.app_context():
        settings = get_settings()
        public_base = os.environ.get("PUBLIC_BASE_URL")
        if public_base:
            settings.base_url = public_base.rstrip('/')
        else:
            try:
                # ``socket`` is used in a ``with`` block so the descriptor is
                # released immediately even if an exception occurs while
                # retrieving the address.
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.connect(("8.8.8.8", 80))
                    local_ip = sock.getsockname()[0]
            except Exception as exc:  # pragma: no cover - network dependent
                # Fallback to localhost if the IP cannot be determined (e.g. no
                # network connection).  Logging the exception gives developers a
                # hint as to why the automatic detection failed.
                logging.getLogger(__name__).warning(
                    "Could not determine local IP automatically, defaulting to localhost: %s",
                    exc,
                )
                local_ip = "localhost"
            settings.base_url = f"http://{local_ip}:{args.port}"
      
        # Persist the change immediately in case the server is restarted later.
        db.session.commit()

    if args.production:
        if serve is None:
            logging.getLogger(__name__).warning(
                "Waitress is not installed; falling back to Flask's development server."
            )
        else:
            # Start the app with Waitress for better performance in production
            serve(app, host="0.0.0.0", port=args.port)
            return

    # Fall back to the built-in development server (either explicitly chosen or
    # because Waitress is unavailable).
    app.run(host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
