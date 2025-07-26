# QRickLinks

QRickLinks is a simple URL shortening service that generates short, memorable slugs in the form `adjective.adjective.noun` and creates corresponding QR codes. Users can register, log in, create short links, and view statistics about link visits.

## Features

- User registration and authentication
- Short URL generation with random word combinations
- Automatic QR code creation for each short URL
- Dashboard listing a user's links and visit counts
- Basic visit tracking (IP address and referrer)

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the application (optionally specify a port):
   ```bash
   ./run_on_pi.sh       # defaults to port 5000
   ./run_on_pi.sh 8080 # run on port 8080
   ```
3. Visit `http://<your-pi-ip>:<port>` in your browser.

## Notes

This project uses SQLite for simplicity and stores generated QR codes in `static/qr/`.
