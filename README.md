# QRickLinks

QRickLinks is a Flask application that combines a traditional URL shortener with a fully customisable QR code generator.  Each link receives both a human friendly word slug and a compact base62 code so it can be shared as text or embedded in a QR image.  Users can manage their links, personalise the generated codes and review basic statistics from a simple dashboard.

## Features

- User registration and email/password or Google OAuth login
- Random `adjective.adjective.noun` slug generation alongside a base62 short code
- Automatic QR code creation for every link with extensive customisation options
- Dashboard showing existing links, usage quotas and visit counts
- Basic analytics that record IP address, MAC address (when available) and referrer
- Thumbnail previews of destination pages via the thum.io service
- Password reset flow that prints reset links to the console
- Admin interface for managing users, site settings and subscription tiers
- Subscription system with free and paid tiers, including monthly "freebie" allowances

## Installation

1. Install the Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. (Optional) export a `SECRET_KEY` so session cookies are signed with your own value:
   ```bash
   export SECRET_KEY="your-secret-key"
   ```
3. (Optional) configure Google OAuth by setting `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` in the environment.
4. Run the development server:
   ```bash
   python app.py
   ```
   The database is created automatically on first run and minimal default data is inserted.
5. Visit `http://localhost:5000` to register an account and start creating links.

### Alternative entry points

- **Raspberry&nbsp;Pi** – `rpi_qrlinks.py` binds to all interfaces and accepts a port argument plus an optional `--production` flag to run with the Waitress WSGI server:
  ```bash
  python rpi_qrlinks.py 8080 --production
  ```
- **Windows** – `run_windows.py` installs requirements, prepares the database and then starts the development server. Provide a port number to override the default `5000`:
  ```bash
  python run_windows.py 5001
  ```

### Administrator account

The initial database seed creates an administrator user so you can immediately access the admin dashboard:

* Username: `philadmin`
* Password: `Admin12345`

Log in at `http://localhost:5000/admin/login` to adjust global settings such as the base URL used when generating short links.

## How it works

`initialize_database()` performs lightweight migrations at start-up so upgrading does not require manual SQL scripts.  New columns are added on the fly and default subscription tiers are inserted if none exist.

When a user creates a link, two identifiers are generated:

1. A word slug using randomly chosen adjectives and nouns.
2. A six character base62 code for use in QR codes.

Both resolve to the same destination URL.  The QR code image is generated with `qrcode` and stored in `static/qr/`.  Customisation options (colours, module style, error correction level and optional logo) are persisted so the code can be recreated later or downloaded as SVG.

Every visit increments the counter on the associated link and records basic metadata.  The application attempts to resolve the visitor's MAC address from the ARP cache when running on a local network.

Free accounts have monthly quotas for link creation and advanced QR features.  These limits refresh automatically and a small number of "freebies" allow occasional usage beyond the free tier.  Paid tiers remove or increase these limits and can be managed from the admin interface.

## Notes

The project stores all data in a local SQLite database for simplicity.  QR images and uploaded logos are saved under `static/qr/` and `static/logos/` respectively.  The default configuration is suitable for local development or small deployments.  For production use consider placing the database and uploaded files in persistent locations and serving the app with a dedicated WSGI server.
