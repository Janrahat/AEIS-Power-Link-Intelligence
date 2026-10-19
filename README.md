# AEIS Power Link Intelligence (Consent-Based)

A small Flask + SQLite dashboard for generating unique links and collecting **limited technical metadata only after a visitor gives informed consent**. Intended for authorized testing, security awareness, and transparent device diagnostics.

## Included
- Password-protected admin dashboard
- Unique shareable link generator with labels
- Consent notice on every visitor page
- On consent only: request IP address, browser user-agent, platform, language, timezone, screen dimensions
- Optional browser geolocation, requiring a separate checkbox and the browser's location permission
- CSV export and deletion of a link plus its records
- SQLite storage and basic security headers

## Important limits
A normal web page cannot silently access a phone's photos, files, contacts, passwords, SMS/WhatsApp messages, or other apps. This project does not attempt to do so. The visitor sees a notice and must actively consent. IP address and device metadata may be personal data; use only for a legitimate purpose, restrict access, and comply with applicable law.

## Run on Termux (local testing)

1. Install Termux from a trusted source, then run:

```sh
pkg update && pkg upgrade
pkg install python
pip install -r requirements.txt
```

2. Set a strong dashboard password and secret:

```sh
export AEIS_ADMIN_PASSWORD='replace-this-with-a-long-unique-password'
export AEIS_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

3. Open `http://127.0.0.1:5000/login` on the same device.

**Local mode is only accessible on your own device.** A link copied from local mode will not work for another person over the internet.

## Shareable links / deployment

To share links with other people, deploy this app to a server you control with HTTPS. Set:

```sh
export AEIS_ADMIN_PASSWORD='a-long-unique-password'
export AEIS_SECRET_KEY='a-long-random-secret'
export AEIS_PUBLIC_BASE_URL='https://your-domain.example'
export AEIS_HTTPS_ONLY=1
```

Replace the example with your own HTTPS domain. Do not expose the built-in Flask development server directly to the public internet. Use a production WSGI server and a properly configured HTTPS reverse proxy/platform. If using a reverse proxy, configure trusted proxy handling carefully before relying on client IP addresses; this starter app intentionally uses the direct connection address and does not trust arbitrary `X-Forwarded-For` headers.

## Data handling
- Records are stored in `aeis.db` beside `app.py` by default.
- Back up the database securely if needed.
- Use the dashboard's Delete button to delete a link and its associated records.
- Export records with the CSV button.
- The dashboard password and secret key must be kept private.
- This beta does not include multi-user accounts, email alerts, advanced rate limiting, or enterprise-grade audit logging.

## Troubleshooting
- If `pip install` fails, update Termux and Python packages, then retry.
- If you see “Setup required”, set `AEIS_ADMIN_PASSWORD` and restart.
- If sharing links does not work, confirm the app is deployed on a public HTTPS domain and `AEIS_PUBLIC_BASE_URL` matches that domain.
