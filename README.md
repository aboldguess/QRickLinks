# QRickLinks

QRickLinks is a simple URL shortening service that generates short, memorable slugs in the form `adjective.adjective.noun` as well as a compact base&nbsp;62 code. Each link therefore has two ways to access it and a corresponding QR code. Users can register, log in, create short links, and view statistics about link visits. The QR code generator supports extensive customisation such as colours, size, pattern style, error correction level and even embedding a central logo.

## Features

- User registration and authentication
- Short URL generation with random word combinations
- Base62 short codes generated alongside word slugs
- Automatic QR code creation for each short URL (the QR code embeds the
  compact base62 link)
- QR codes can be customised after creation from the dashboard
- URLs missing a scheme are automatically prefixed with `https://`
- Dashboard listing a user's links and visit counts
- Thumbnail preview of each destination page using the thum.io service
- Basic visit tracking (IP address and referrer)
- Admin dashboard with site statistics and settings
- Subscription paywall for advanced QR code features

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   python app.py
   ```
3. Visit `http://localhost:5000` in your browser.

### Raspberry Pi Hosting

Use the provided `rpi_qrlinks.py` script to host the application on a Raspberry Pi.
It binds to all network interfaces and accepts an optional port argument and a
`--production` flag for running with the Waitress WSGI server:

```bash
python rpi_qrlinks.py 8080 --production  # runs the server on port 8080
```

Omit the port argument to use `5000` and drop the flag to use Flask's development server.

### Windows Quick Start

On Windows you can run `run_windows.py` which installs dependencies, prepares
the database and starts the server. An optional port argument overrides the
default:

```bash
python run_windows.py 5001  # starts the app on port 5001
```

Omit the argument to use port `5000`.

### Admin Access

An administrator account is created automatically with the following credentials:

* **Username:** `philadmin`
* **Password:** `Admin12345`

Log in at `http://localhost:5000/admin/login` to view site statistics and manage settings such as the base URL used for generated links.

### Monetisation

Advanced features such as custom colours, advanced styling, logo embedding and analytics views are limited for free users. The monthly quotas for each feature can be configured from the admin settings page. Users marked as premium are not restricted by these limits.

Each account also receives a small number of "freebies" every month which allow
going over the free quotas. The remaining count and renewal date are displayed
on the dashboard so users know when their allowance refreshes. Upgrading to the
Pro plan removes all restrictions.

Visit the new `/pricing` page for plan details and a simple upgrade form. The
current early access program grants the Pro subscription for free but records
the opt-in so payment processing can be integrated later.

## Notes

This project uses SQLite for simplicity and stores generated QR codes in `static/qr/`.
The creation form now only asks for the long URL so the interface stays clutter‑free. After a link is created you can customise its QR code from a pull‑down menu next to the entry on your dashboard. Options include colours, module size, border width, pattern style, error correction level and an optional central logo.

The *rounded* pattern now uses a radius ratio of `1` so every module is drawn as
a circle, providing a clear visual distinction from the default square style.
