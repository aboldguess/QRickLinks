"""
# QRickLinks Vercel Entry Point

This lightweight module exposes the Flask application to Vercel's serverless
Python runtime.  The file is intentionally minimal: imports are grouped at the
top, followed by configuration middleware and the exported ``app`` object that
Vercel expects.  Keeping the structure compact makes debugging cold-start
issues straightforward while still offering enough inline documentation for
contributors to understand the deployment flow at a glance.
"""

from werkzeug.middleware.proxy_fix import ProxyFix

from qricklinks_app import app as flask_app

# Wrap the Flask WSGI app so URL generation respects the reverse proxy headers
# provided by Vercel.  The adjusted application is then re-exported using the
# ``app`` name required by the ``@vercel/python`` runtime.
flask_app.wsgi_app = ProxyFix(flask_app.wsgi_app, x_proto=1, x_host=1)
app = flask_app
