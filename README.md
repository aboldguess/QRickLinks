# QRickLinks

QRickLinks is a simple URL shortening service that generates short, memorable slugs in the form `adjective.adjective.noun` and creates corresponding QR codes. Users can register, log in, create short links, and view statistics about link visits.

## Features

- User registration and authentication
- Short URL generation with random word combinations
- Automatic QR code creation for each short URL
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

### Admin Access

An administrator account is created automatically with the following credentials:

* **Username:** `philadmin`
* **Password:** `Admin12345`

Log in at `http://localhost:5000/admin/login` to view site statistics and manage settings such as the base URL used for generated links.

## Notes

This project uses SQLite for simplicity and stores generated QR codes in `static/qr/`.
