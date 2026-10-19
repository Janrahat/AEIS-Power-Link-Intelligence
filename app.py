import csv
import io
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, abort, flash, make_response, redirect, render_template,
    request, session, url_for
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("AEIS_DB_PATH", os.path.join(APP_DIR, "aeis.db"))
ADMIN_PASSWORD = os.environ.get("AEIS_ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("AEIS_SECRET_KEY", "")
PUBLIC_BASE_URL = os.environ.get("AEIS_PUBLIC_BASE_URL", "").rstrip("/")

app = Flask(__name__)
app.secret_key = SECRET_KEY or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("AEIS_HTTPS_ONLY", "0") == "1",
    MAX_CONTENT_LENGTH=32 * 1024,
)

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                label TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_at TEXT NOT NULL,
                consent INTEGER NOT NULL DEFAULT 0,
                ip_address TEXT,
                user_agent TEXT,
                platform TEXT,
                language TEXT,
                timezone_name TEXT,
                screen_size TEXT,
                geo_lat REAL,
                geo_lon REAL,
                geo_accuracy REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_token ON events(token)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(event_at)")

init_db()

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not ADMIN_PASSWORD:
            return render_template(
                "setup_required.html",
                message="Dashboard password is not configured. Set AEIS_ADMIN_PASSWORD and restart the app."
            ), 503
        if not session.get("admin_authenticated"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), usb=()"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/")
def index():
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if not ADMIN_PASSWORD:
        return render_template(
            "setup_required.html",
            message="Set AEIS_ADMIN_PASSWORD before using the dashboard."
        ), 503
    if request.method == "POST":
        if secrets.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            session.clear()
            session["admin_authenticated"] = True
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Incorrect password.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@admin_required
def dashboard():
    with db() as conn:
        links = conn.execute("""
            SELECT l.*,
              (SELECT COUNT(*) FROM events e WHERE e.token=l.token) AS event_count,
              (SELECT COUNT(*) FROM events e WHERE e.token=l.token AND e.consent=1) AS consent_count
            FROM links l ORDER BY l.id DESC
        """).fetchall()
        events = conn.execute("""
            SELECT e.*, l.label FROM events e
            LEFT JOIN links l ON l.token=e.token
            ORDER BY e.id DESC LIMIT 100
        """).fetchall()
        totals = conn.execute("""
            SELECT COUNT(*) AS events,
                   SUM(CASE WHEN consent=1 THEN 1 ELSE 0 END) AS consents,
                   COUNT(DISTINCT token) AS links_seen
            FROM events
        """).fetchone()
    return render_template(
        "dashboard.html", links=links, events=events, totals=totals,
        public_base_url=PUBLIC_BASE_URL
    )

@app.route("/links", methods=["POST"])
@admin_required
def create_link():
    label = (request.form.get("label") or "").strip()[:100]
    if not label:
        flash("Please enter a label for this link.", "error")
        return redirect(url_for("dashboard"))
    token = secrets.token_urlsafe(18)
    with db() as conn:
        conn.execute(
            "INSERT INTO links(token,label,created_at) VALUES(?,?,?)",
            (token, label, now_iso())
        )
    flash("Consent-based link created.", "success")
    return redirect(url_for("dashboard"))

@app.route("/links/<int:link_id>/delete", methods=["POST"])
@admin_required
def delete_link(link_id):
    with db() as conn:
        row = conn.execute("SELECT token FROM links WHERE id=?", (link_id,)).fetchone()
        if row:
            conn.execute("DELETE FROM events WHERE token=?", (row["token"],))
            conn.execute("DELETE FROM links WHERE id=?", (link_id,))
    flash("Link and its associated records deleted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/visit/<token>", methods=["GET", "POST"])
def visit(token):
    with db() as conn:
        link = conn.execute("SELECT * FROM links WHERE token=?", (token,)).fetchone()
    if not link:
        abort(404)

    if request.method == "POST":
        if request.form.get("consent") != "yes":
            flash("No information was submitted because consent was not given.", "info")
            return render_template("visitor.html", link=link, submitted=False)

        # Only collect browser/device metadata after the visitor actively consents.
        # Do not trust forwarded IP headers unless deployed behind a correctly configured proxy.
        ip_address = request.remote_addr
        user_agent = request.headers.get("User-Agent", "")[:1000]
        platform = (request.form.get("platform") or "")[:200]
        language = (request.form.get("language") or "")[:100]
        timezone_name = (request.form.get("timezone") or "")[:100]
        screen_size = (request.form.get("screen_size") or "")[:50]

        geo_lat = geo_lon = geo_accuracy = None
        try:
            if request.form.get("geo_consent") == "yes":
                geo_lat = float(request.form.get("geo_lat", ""))
                geo_lon = float(request.form.get("geo_lon", ""))
                geo_accuracy = float(request.form.get("geo_accuracy", ""))
                if not (-90 <= geo_lat <= 90 and -180 <= geo_lon <= 180):
                    geo_lat = geo_lon = geo_accuracy = None
        except (TypeError, ValueError):
            geo_lat = geo_lon = geo_accuracy = None

        with db() as conn:
            conn.execute("""
                INSERT INTO events(
                    token,event_type,event_at,consent,ip_address,user_agent,
                    platform,language,timezone_name,screen_size,
                    geo_lat,geo_lon,geo_accuracy
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                token, "consent_submitted", now_iso(), 1, ip_address, user_agent,
                platform, language, timezone_name, screen_size,
                geo_lat, geo_lon, geo_accuracy
            ))
        return render_template("visitor.html", link=link, submitted=True)

    return render_template("visitor.html", link=link, submitted=False)

@app.route("/export.csv")
@admin_required
def export_csv():
    with db() as conn:
        rows = conn.execute("""
            SELECT e.event_at, l.label, e.event_type, e.consent, e.ip_address,
                   e.user_agent, e.platform, e.language, e.timezone_name,
                   e.screen_size, e.geo_lat, e.geo_lon, e.geo_accuracy
            FROM events e LEFT JOIN links l ON l.token=e.token
            ORDER BY e.id DESC
        """).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "timestamp_utc", "link_label", "event_type", "consent",
        "ip_address", "user_agent", "platform", "language", "timezone",
        "screen_size", "geo_latitude", "geo_longitude", "geo_accuracy_m"
    ])
    for row in rows:
        writer.writerow([row[key] for key in row.keys()])
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=aeis-events.csv"
    return response

@app.route("/health")
def health():
    return {"status": "ok", "service": "AEIS Power Link Intelligence"}

if __name__ == "__main__":
    # Local development only. For public use, deploy behind HTTPS with a production WSGI server.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
