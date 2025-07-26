# QRickLinks

QRickLinks is a simple URL shortening service that generates short, memorable slugs in the form `adjective.adjective.noun` and creates corresponding QR codes. Users can register, log in, create short links, and view statistics about link visits. The QR code generator supports extensive customisation such as colours, size, pattern style, error correction level and even embedding a central logo.

## Features

- User registration and authentication
- Short URL generation with random word combinations
- Automatic QR code creation for each short URL
- Customisable QR codes (colours, size, pattern, redundancy and logo)
- URLs missing a scheme are automatically prefixed with `https://`
- Dashboard listing a user's links and visit counts
- Basic visit tracking (IP address and referrer)
- Admin dashboard with site statistics and settings

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

Use the provided `run_rpi.py` script to host the application on a Raspberry Pi.
It binds to all network interfaces and accepts an optional port argument:

```bash
python run_rpi.py 8080  # runs the server on port 8080
```

Omit the argument to use the default port `5000`.

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

## Notes

This project uses SQLite for simplicity and stores generated QR codes in `static/qr/`.
After a link is created you can customise its QR code from a pull-down menu next to the entry on your dashboard. Options include colours, module size, border width, pattern style, error correction level and an optional central logo.

The *rounded* pattern now applies a smaller corner radius so its curved edges are easier to distinguish from the default square modules.
