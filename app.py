
import os
import sqlite3
import secrets
from pathlib import Path
from datetime import date, datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)

# --------------------------------------------------
# 1. APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY", "dev-only-change-this-secret-key"
)

# Secure cookie settings for HTTPS deployments.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "COOKIE_SECURE", "0"
    ) == "1"
)

DB_PATH = Path(__file__).resolve().parent / "certificates.db"


# --------------------------------------------------
# 2. DATABASE CONNECTION
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# --------------------------------------------------
# 3. DATABASE INITIALIZATION
# --------------------------------------------------

def initialize_database():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS admins (
                admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin'
                    CHECK(role IN ('admin'))
            );

            CREATE TABLE IF NOT EXISTS certificates (
                certificate_id TEXT PRIMARY KEY,
                student_name TEXT NOT NULL,
                course TEXT NOT NULL,
                issue_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE'
                    CHECK(status IN ('ACTIVE', 'REVOKED')),
                issued_by INTEGER NOT NULL,
                FOREIGN KEY (issued_by)
                    REFERENCES admins(admin_id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                action TEXT NOT NULL,
                certificate_id TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (admin_id)
                    REFERENCES admins(admin_id)
            );
        """)

        # Create the demo admin only if it doesn't exist.
        existing = db.execute(
            "SELECT admin_id FROM admins WHERE username = ?",
            ("admin",)
        ).fetchone()

        if not existing:
            db.execute("""
                INSERT INTO admins
                    (username, password_hash, role)
                VALUES (?, ?, ?)
            """, (
                "admin",
                generate_password_hash("admin123"),
                "admin"
            ))


# --------------------------------------------------
# 4. AUDIT LOGGING
# --------------------------------------------------

def log_action(admin_id, action, certificate_id=None):
    with get_db() as db:
        db.execute("""
            INSERT INTO audit_logs
                (admin_id, action, certificate_id, timestamp)
            VALUES (?, ?, ?, ?)
        """, (
            admin_id,
            action,
            certificate_id,
            datetime.now(timezone.utc).isoformat()
        ))


# --------------------------------------------------
# 5. AUTHORIZATION
# --------------------------------------------------

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin_login"))

        if session.get("role") != "admin":
            abort(403)

        # Confirm that the account still exists.
        with get_db() as db:
            admin = db.execute("""
                SELECT admin_id, role
                FROM admins
                WHERE admin_id = ?
            """, (session["admin_id"],)).fetchone()

        if not admin or admin["role"] != "admin":
            session.clear()
            return redirect(url_for("admin_login"))

        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------
# 6. CSRF PROTECTION FOR FORMS
# --------------------------------------------------

def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("_csrf_token", "")

        if (
            not expected
            or not secrets.compare_digest(submitted, expected)
        ):
            abort(
                400,
                description="Invalid form token. Reload the page."
            )


# --------------------------------------------------
# 7. HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# 8. CERTIFICATE VERIFICATION
# --------------------------------------------------

@app.route("/verify", methods=["POST"])
def verify():
    certificate_id = request.form.get(
        "certificate_id", ""
    ).strip().upper()

    if not certificate_id or len(certificate_id) > 80:
        return render_template(
            "verify.html",
            certificate=None,
            searched=False,
            error="Please enter a valid certificate ID."
        )

    with get_db() as db:
        certificate = db.execute("""
            SELECT certificate_id, student_name,
                   course, issue_date, status
            FROM certificates
            WHERE certificate_id = ?
        """, (certificate_id,)).fetchone()

    return render_template(
        "verify.html",
        certificate=certificate,
        searched=True,
        error=None
    )


# --------------------------------------------------
# 9. ADMIN LOGIN
# --------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get("password", "")

        with get_db() as db:
            admin = db.execute("""
                SELECT admin_id, username,
                       password_hash, role
                FROM admins
                WHERE username = ?
            """, (username,)).fetchone()

        if (
            admin
            and check_password_hash(
                admin["password_hash"], password
            )
            and admin["role"] == "admin"
        ):
            # Prevent session fixation.
            session.clear()

            session["admin_id"] = admin["admin_id"]
            session["username"] = admin["username"]
            session["role"] = admin["role"]

            # Generate a new CSRF token for the new session.
            csrf_token()

            log_action(
                admin["admin_id"], "ADMIN_LOGIN"
            )

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("admin_login.html")


# --------------------------------------------------
# 10. ADMIN LOGOUT
# --------------------------------------------------

@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    admin_id = session["admin_id"]

    log_action(admin_id, "ADMIN_LOGOUT")

    session.clear()

    return redirect(url_for("home"))


# --------------------------------------------------
# 11. ADMIN DASHBOARD
# --------------------------------------------------

@app.route("/admin")
@admin_required
def dashboard():
    with get_db() as db:
        certificates = db.execute("""
            SELECT certificate_id, student_name, course,
                   issue_date, status, issued_by
            FROM certificates
            ORDER BY issue_date DESC
        """).fetchall()

    return render_template(
        "dashboard.html",
        certificates=certificates,
        today=date.today().isoformat()
    )


# --------------------------------------------------
# 12. ISSUE A NEW CERTIFICATE
# --------------------------------------------------

@app.route("/admin/add", methods=["POST"])
@admin_required
def add_certificate():
    student_name = request.form.get(
        "student_name", ""
    ).strip()

    course = request.form.get("course", "").strip()

    issue_date = request.form.get(
        "issue_date", ""
    ).strip()

    # Validate required fields and lengths.
    if (
        not student_name
        or len(student_name) > 100
        or not course
        or len(course) > 120
    ):
        flash("Enter valid student and course details.")
        return redirect(url_for("dashboard"))

    # Validate date format and prevent future dates.
    try:
        parsed_date = date.fromisoformat(issue_date)

        if parsed_date > date.today():
            flash("Issue date cannot be in the future.")
            return redirect(url_for("dashboard"))

    except (ValueError, TypeError):
        flash("Please enter a valid issue date.")
        return redirect(url_for("dashboard"))

    admin_id = session["admin_id"]

    # Generate a unique certificate ID.
    certificate_id = None

    for _ in range(5):
        candidate = (
            "CERT-"
            + date.today().strftime("%Y")
            + "-"
            + secrets.token_hex(4).upper()
        )

        with get_db() as db:
            exists = db.execute("""
                SELECT 1 FROM certificates
                WHERE certificate_id = ?
            """, (candidate,)).fetchone()

        if not exists:
            certificate_id = candidate
            break

    if certificate_id is None:
        flash("Could not generate an ID. Please try again.")
        return redirect(url_for("dashboard"))

    try:
        with get_db() as db:
            db.execute("""
                INSERT INTO certificates
                    (certificate_id, student_name, course,
                     issue_date, status, issued_by)
                VALUES (?, ?, ?, ?, 'ACTIVE', ?)
            """, (
                certificate_id,
                student_name,
                course,
                issue_date,
                admin_id
            ))

        log_action(
            admin_id,
            "CERTIFICATE_ISSUED",
            certificate_id
        )

        flash(
            f"Certificate issued successfully. ID: {certificate_id}"
        )

    except sqlite3.IntegrityError:
        flash("Could not issue certificate. Please try again.")

    return redirect(url_for("dashboard"))


# --------------------------------------------------
# 13. REVOKE A CERTIFICATE
# --------------------------------------------------

@app.route(
    "/admin/revoke/<certificate_id>",
    methods=["POST"]
)
@admin_required
def revoke_certificate(certificate_id):
    certificate_id = certificate_id.strip().upper()

    with get_db() as db:
        result = db.execute("""
            UPDATE certificates
            SET status = 'REVOKED'
            WHERE certificate_id = ?
              AND status = 'ACTIVE'
        """, (certificate_id,))

    if result.rowcount == 1:
        log_action(
            session["admin_id"],
            "CERTIFICATE_REVOKED",
            certificate_id
        )

        flash("Certificate revoked successfully.")

    else:
        flash("Certificate not found or already revoked.")

    return redirect(url_for("dashboard"))


# --------------------------------------------------
# 14. VIEW AUDIT LOGS
# --------------------------------------------------

@app.route("/admin/audit")
@admin_required
def audit_logs():
    with get_db() as db:
        logs = db.execute("""
            SELECT audit_logs.log_id,
                   audit_logs.action,
                   audit_logs.certificate_id,
                   audit_logs.timestamp,
                   admins.username
            FROM audit_logs
            LEFT JOIN admins
                ON audit_logs.admin_id = admins.admin_id
            ORDER BY audit_logs.log_id DESC
        """).fetchall()

    return render_template(
        "audit_logs.html",
        logs=logs
    )


# --------------------------------------------------
# 15. ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(403)
def forbidden(error):
    return "Access denied: You are not authorized.", 403


@app.errorhandler(400)
def bad_request(error):
    return (
        "Invalid request. Please reload the page and try again.",
        400
    )


# --------------------------------------------------
# 16. START APPLICATION
# --------------------------------------------------

initialize_database()


if __name__ == "__main__":
    # Local development only. Do not use debug mode in production.
    app.run(debug=True)
