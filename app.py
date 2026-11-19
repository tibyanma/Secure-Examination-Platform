from flask import Flask, request, session, redirect, url_for, jsonify, send_file, g
import mysql.connector
from mysql.connector import pooling
import os
import html as htmllib
import json
from pathlib import Path
import time
import re
import math
import hmac
import secrets
import threading
from datetime import timedelta

from werkzeug.security import generate_password_hash, check_password_hash

import exam_attempts as ea
import exam_locks

BASE_DIR = Path(__file__).resolve().parent


def _load_env_file(path):
    """Minimal .env reader (KEY=VALUE per line). Real environment variables win."""
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass


_load_env_file(BASE_DIR / ".env")

PRODUCTION = os.environ.get("SOEMS_ENV", "development").lower() == "production"
USE_HTTPS_COOKIES = PRODUCTION or os.environ.get("SOEMS_HTTPS", "0") == "1"

app = Flask(__name__)

_secret_key = os.environ.get("FLASK_SECRET_KEY")
if not _secret_key:
    if PRODUCTION:
        raise RuntimeError("FLASK_SECRET_KEY must be set when SOEMS_ENV=production.")
    # Development convenience: a random key per start (everyone is signed out on restart).
    _secret_key = secrets.token_hex(32)
    print("WARNING: FLASK_SECRET_KEY is not set; using a temporary key. "
          "Set it in .env so sessions survive restarts.")
app.secret_key = _secret_key

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=USE_HTTPS_COOKIES,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SOEMS_SESSION_HOURS", "8"))),
    MAX_CONTENT_LENGTH=1024 * 1024,  # 1 MB is far more than any exam request needs
)

if os.environ.get("SOEMS_TRUST_PROXY", "0") == "1":
    # Only enable behind a reverse proxy you control; it makes request.remote_addr
    # (used by the login rate limiter) the real client address.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

BASE_DIR = Path(__file__).resolve().parent

# A student may replace an existing face reference only when this is explicitly
# enabled (development/testing). Otherwise a second person could register their
# own face on someone else's account right before an exam.
ALLOW_FACE_RE_ENROLL = os.environ.get("SOEMS_ALLOW_FACE_RE_ENROLL", "0") == "1"
FACE_LANDMARKER_PATH = BASE_DIR / "face_landmarker.task"

@app.route("/face-landmarker-model")
def face_landmarker_model():
    # MediaPipe loads this model in the student's browser; the server does not
    # open a second camera.
    if not FACE_LANDMARKER_PATH.is_file():
        return "Face landmarker model file is missing.", 404
    return send_file(FACE_LANDMARKER_PATH, mimetype="application/octet-stream")

# Database: a connection pool. Each request borrows one connection and gives it
# back afterwards, so students no longer share (and interleave on) one connection.

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "secure_exam_db"),
    "use_pure": True,
}
if PRODUCTION and (DB_CONFIG["user"] == "root" or not DB_CONFIG["password"]):
    raise RuntimeError("In production, use a dedicated (non-root) MySQL user and set DB_PASSWORD.")

_pool = pooling.MySQLConnectionPool(
    pool_name="soems_pool",
    pool_size=min(max(int(os.environ.get("DB_POOL_SIZE", "16")), 1), 32),
    pool_reset_session=True,
    **DB_CONFIG
)


def _acquire_connection():
    last_error = None
    for _ in range(100):  # wait up to ~5 s if every connection is busy
        try:
            return _pool.get_connection()
        except pooling.PoolError as exc:
            last_error = exc
            time.sleep(0.05)
    raise last_error


def get_db():
    """The current request's database connection (one per request)."""
    if "db" not in g:
        g.db = _acquire_connection()
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    conn = g.pop("db", None)
    if conn is None:
        return
    try:
        if exc is not None:
            conn.rollback()
    except Exception:
        pass
    try:
        conn.close()  # returns the connection to the pool
    except Exception:
        app.logger.exception("Could not return a database connection to the pool")


def run_startup_task(task):
    conn = _acquire_connection()
    try:
        task(conn)
    finally:
        conn.close()

# Face reference storage. A descriptor is 128 floating-point values encoded as JSON.
# user_id is stored as text to avoid assuming the exact type of users.id.
def ensure_face_references_table(conn):
    cursor = conn.cursor()
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS face_references (
            id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(191) NOT NULL UNIQUE,
            descriptor LONGTEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
    )
    conn.commit()
    cursor.close()

run_startup_task(ensure_face_references_table)

# Behavior events: every warning / termination during an exam is stored so the
# teacher can review a report per student.
def ensure_behavior_events_table(conn):
    cursor = conn.cursor()
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS behavior_events (
            id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(191) NOT NULL,
            username VARCHAR(191) NOT NULL,
            student_name VARCHAR(255) NOT NULL,
            exam_title VARCHAR(255) NOT NULL,
            event_type VARCHAR(30) NOT NULL,
            reason TEXT NOT NULL,
            warning_number INT NULL,
            elapsed_seconds INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
    )
    conn.commit()
    cursor.close()

run_startup_task(ensure_behavior_events_table)

# Security helpers: rate limiting, password hashing, CSRF, session handling

class RateLimiter:
    """In-memory sliding-window limiter (per process; resets when the app restarts)."""

    def __init__(self, max_failures, window_seconds):
        self.max = max_failures
        self.window = window_seconds
        self._hits = {}
        self._lock = threading.Lock()

    def _recent(self, key, now):
        hits = [t for t in self._hits.get(key, []) if now - t < self.window]
        if hits:
            self._hits[key] = hits
        else:
            self._hits.pop(key, None)
        return hits

    def blocked(self, key):
        """Seconds until the key may try again, or 0 if it is not blocked."""
        now = time.time()
        with self._lock:
            hits = self._recent(key, now)
            if len(hits) >= self.max:
                return int(self.window - (now - hits[0])) + 1
        return 0

    def fail(self, key):
        now = time.time()
        with self._lock:
            hits = self._recent(key, now)
            hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 5000:  # keep memory bounded
                for k in list(self._hits):
                    self._recent(k, now)

    def reset(self, key):
        with self._lock:
            self._hits.pop(key, None)


LOGIN_LIMITER = RateLimiter(max_failures=5, window_seconds=15 * 60)    # per IP + username
IP_LIMITER = RateLimiter(max_failures=100, window_seconds=15 * 60)     # per IP (password spraying)
FACE_LIMITER = RateLimiter(max_failures=8, window_seconds=10 * 60)     # per student


def minutes_text(seconds):
    return "%d minute(s)" % max(1, math.ceil(seconds / 60))


HASH_METHOD = "pbkdf2:sha256:600000"
_HASH_PREFIXES = ("pbkdf2:", "scrypt:")
WEAK_DEFAULT_PASSWORDS = {"1234"}  # the seeded password: must be changed at first login
MIN_PASSWORD_LENGTH = 8
_DUMMY_HASH = generate_password_hash("not-a-real-password", method=HASH_METHOD)


def hash_password(password):
    return generate_password_hash(password, method=HASH_METHOD)


def check_stored_password(stored, supplied):
    """
    Returns (matches, needs_upgrade).
    Hashed values are verified normally. Old plaintext values still work once
    and are flagged for upgrade, so existing accounts are not locked out.
    """
    if stored is None:
        return False, False
    stored = str(stored)
    if stored.startswith(_HASH_PREFIXES):
        try:
            return check_password_hash(stored, supplied), False
        except Exception:
            return False, False
    return hmac.compare_digest(stored.encode("utf-8"), supplied.encode("utf-8")), True


def authenticate(role, username, password):
    """Returns (user_row, error_message, http_status). Row order: id, username, password, role, name, email."""
    username = username.strip()
    ip = request.remote_addr or "unknown"
    key = (role, ip, username.lower())
    wait = LOGIN_LIMITER.blocked(key) or IP_LIMITER.blocked(ip)
    if wait:
        return None, "Too many failed sign-in attempts. Please try again in %s." % minutes_text(wait), 429

    conn = get_db()
    cursor = conn.cursor(buffered=True)
    cursor.execute(
        "SELECT id, username, password, role, name, email FROM users WHERE username=%s AND role=%s",
        (username, role),
    )
    user = cursor.fetchone()
    cursor.close()

    if user:
        matches, needs_upgrade = check_stored_password(user[2], password)
    else:
        check_password_hash(_DUMMY_HASH, password)  # same work for unknown users (no timing hint)
        matches, needs_upgrade = False, False

    if matches:
        LOGIN_LIMITER.reset(key)
        if needs_upgrade:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password=%s WHERE id=%s", (hash_password(password), user[0]))
            conn.commit()
            cursor.close()
        return user, None, 200

    LOGIN_LIMITER.fail(key)
    IP_LIMITER.fail(ip)
    return None, "Invalid username or password.", 401


def start_session(user, role, supplied_password):
    session.clear()  # new session on login (prevents session fixation)
    session.permanent = True
    session["user_id"] = int(user[0])  # Database primary key; required by face_references and exam_locks
    session["username"] = str(user[1])
    session["role"] = role
    if role == "student":
        session["student_name"] = str(user[4] or user[1])
    if supplied_password in WEAK_DEFAULT_PASSWORDS:
        session["must_change_password"] = True
    csrf_token()


def after_login_redirect(role):
    if session.get("must_change_password"):
        return redirect(url_for("change_password" if role == "student" else "teacher_change_password"))
    return redirect(url_for("student_dashboard" if role == "student" else "teacher_dashboard"))


# CSRF: every form gets a hidden token and every same-origin fetch() sends a header.

def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


_FORM_TAG = re.compile(r'(<form\b[^>]*\bmethod\s*=\s*["\']?post["\']?[^>]*>)', re.I)


def inject_csrf(html):
    field = '<input type="hidden" name="csrf_token" value="%s">' % csrf_token()
    return _FORM_TAG.sub(lambda m: m.group(1) + field, html)


CSRF_FETCH_SCRIPT = """<script>
(function () {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (!meta || !window.fetch) return;
    var token = meta.getAttribute("content");
    var originalFetch = window.fetch;
    window.fetch = function (input, init) {
        try {
            var method = ((init && init.method) || (input && input.method) || "GET").toUpperCase();
            var target = typeof input === "string" ? input : (input.url || String(input));
            var url = new URL(target, window.location.href);
            if (method !== "GET" && method !== "HEAD" && url.origin === window.location.origin) {
                init = init || {};
                var headers = new Headers(init.headers || (input && input.headers) || {});
                headers.set("X-CSRF-Token", token);
                init.headers = headers;
            }
        } catch (e) { /* fall through to the normal request */ }
        return originalFetch.call(this, input, init);
    };
})();
</script>"""


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not sent or not hmac.compare_digest(str(sent), str(expected)):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "csrf",
                                "message": "Your session expired. Please reload the page and try again."}), 403
            return "Your session expired. Please go back, reload the page and try again.", 403
    return None


@app.before_request
def force_password_change():
    """Accounts still on the seeded default password must choose a new one first."""
    if not session.get("must_change_password"):
        return None
    if request.path in ("/student/change-password", "/teacher/change-password", "/logout"):
        return None
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "password_change_required",
                        "message": "Please change your default password first."}), 403
    return redirect(url_for("change_password" if session.get("role") == "student" else "teacher_change_password"))


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
    if response.mimetype in ("text/html", "application/json"):
        response.headers["Cache-Control"] = "no-store"
    if USE_HTTPS_COOKIES:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


# Shared UI

BASE_CSS = """
<style>
* { box-sizing: border-box; }

body {
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #f4f7fb;
    color: #172033;
}

a { text-decoration: none; color: inherit; }

.navbar {
    height: 72px;
    background: #102a43;
    color: white;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 6%;
    box-shadow: 0 3px 14px rgba(0,0,0,.10);
}

.brand {
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 20px;
    font-weight: 700;
}

.logo {
    width: 42px;
    height: 42px;
    border-radius: 12px;
    background: #2f80ed;
    display: grid;
    place-items: center;
    font-size: 22px;
}

.profile-wrap { position: relative; }

.profile-btn {
    border: 0;
    background: rgba(255,255,255,.12);
    color: white;
    width: 44px;
    height: 44px;
    border-radius: 50%;
    cursor: pointer;
    font-size: 20px;
}

.profile-menu {
    display: none;
    position: absolute;
    right: 0;
    top: 54px;
    width: 210px;
    background: white;
    color: #172033;
    border-radius: 12px;
    box-shadow: 0 12px 35px rgba(0,0,0,.15);
    overflow: hidden;
    z-index: 20;
}

.profile-menu a {
    display: block;
    padding: 13px 16px;
    border-bottom: 1px solid #edf0f5;
}

.profile-menu a:hover { background: #f4f7fb; }

.container {
    width: min(1120px, 90%);
    margin: 38px auto;
}

.hero {
    background: linear-gradient(135deg, #102a43, #1f5f8b);
    color: white;
    border-radius: 22px;
    padding: 42px;
    margin-bottom: 28px;
}

.hero h1 { margin: 0 0 10px; font-size: 34px; }
.hero p { margin: 0; color: #dcecff; }

.grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
}

.card {
    background: white;
    border-radius: 18px;
    padding: 25px;
    box-shadow: 0 6px 25px rgba(16,42,67,.08);
    border: 1px solid #e9eef5;
}

.card-icon {
    width: 52px;
    height: 52px;
    border-radius: 14px;
    background: #eaf3ff;
    display: grid;
    place-items: center;
    font-size: 25px;
    margin-bottom: 15px;
}

.card h3 { margin: 0 0 8px; }
.card p { color: #65758b; line-height: 1.5; }

.btn {
    display: inline-block;
    border: 0;
    border-radius: 10px;
    padding: 12px 18px;
    background: #2f80ed;
    color: white;
    font-weight: 700;
    cursor: pointer;
}

.btn:hover { opacity: .9; }

.btn.secondary {
    background: #eaf3ff;
    color: #1f5f8b;
}

.section-title {
    margin: 34px 0 15px;
    font-size: 22px;
}

.status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    background: #eaf8f0;
    color: #18794e;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 700;
}

.exam-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
}

.camera-box {
    margin-top: 20px;
    background: #0d1b2a;
    border-radius: 18px;
    padding: 20px;
    text-align: center;
}

video {
    width: min(100%, 560px);
    border-radius: 12px;
    background: #000;
}

.login-page {
    min-height: 100vh;
    display: grid;
    grid-template-columns: 1.05fr .95fr;
}

.login-side {
    background: linear-gradient(145deg, #102a43, #1f5f8b);
    color: white;
    padding: 9%;
    display: flex;
    flex-direction: column;
    justify-content: center;
}

.login-side h1 { font-size: 42px; margin: 22px 0 12px; }
.login-side p { color: #dcecff; line-height: 1.7; max-width: 500px; }

.security-list {
    margin-top: 28px;
    padding: 0;
    list-style: none;
}

.security-list li {
    margin: 14px 0;
    color: #e8f3ff;
}

.login-area {
    display: grid;
    place-items: center;
    padding: 30px;
}

.login-card {
    width: min(430px, 100%);
    background: white;
    padding: 38px;
    border-radius: 22px;
    box-shadow: 0 15px 45px rgba(16,42,67,.12);
}

.login-card h2 { margin: 0 0 8px; }
.login-card .sub { color: #718096; margin-bottom: 28px; }

label {
    display: block;
    font-size: 14px;
    font-weight: 700;
    margin: 16px 0 8px;
}

.input {
    width: 100%;
    padding: 13px 14px;
    border: 1px solid #d9e1ea;
    border-radius: 10px;
    font-size: 15px;
    outline: none;
}

.input:focus { border-color: #2f80ed; }

.password-wrap { position: relative; }
.password-wrap .input { padding-right: 55px; }

.show-pass {
    position: absolute;
    right: 10px;
    top: 8px;
    border: 0;
    background: transparent;
    cursor: pointer;
    padding: 8px;
}

.full { width: 100%; margin-top: 22px; }

.role-switch {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 20px;
}

.role-switch a {
    text-align: center;
    padding: 11px;
    border-radius: 10px;
    background: #f0f4f8;
    font-weight: 700;
}

.role-switch a.active {
    background: #eaf3ff;
    color: #1f5f8b;
}

.alert {
    background: #fff4e5;
    color: #9a5b00;
    padding: 12px 14px;
    border-radius: 10px;
    margin-bottom: 18px;
}

.back {
    display: inline-block;
    margin-top: 22px;
    color: #2f80ed;
    font-weight: 700;
}

.list-card {
    background: white;
    padding: 20px;
    border-radius: 16px;
    margin: 12px 0;
    box-shadow: 0 5px 20px rgba(16,42,67,.06);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

@media (max-width: 800px) {
    .login-page { grid-template-columns: 1fr; }
    .login-side { display: none; }
    .grid { grid-template-columns: 1fr; }
    .hero { padding: 28px; }
    .exam-row, .list-card { flex-direction: column; align-items: flex-start; }
}
</style>
"""

def page(title, content, scripts=""):
    token = csrf_token()
    content = inject_csrf(content)
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="{token}">
<title>{title}</title>
{CSRF_FETCH_SCRIPT}
{BASE_CSS}
</head>
<body>
{content}
{scripts}
</body>
</html>"""


def navbar(name="Student"):
    return f"""
<nav class="navbar">
    <a href="/student/dashboard" class="brand">
        <span class="logo">🛡️</span>
        Secure Exam Platform
    </a>

    <div class="profile-wrap">
        <button class="profile-btn" onclick="toggleMenu()">👤</button>
        <div id="profileMenu" class="profile-menu">
            <a href="/student/profile">👤 Profile</a>
            <a href="/student/settings">⚙️ Settings</a>
            <a href="/student/change-password">🔑 Change Password</a>
            <a href="/student/support">❓ Support & Help</a>
            <a href="/student/courses">📚 My Courses</a>
            <a href="/logout">🚪 Logout</a>
        </div>
    </div>
</nav>
"""



# Home / Role selection

@app.route("/")
def home():
    content = """
<div class="login-page">
    <section class="login-side">
        <div class="brand">
            <span class="logo">🛡️</span>
            Secure Exam Platform
        </div>
        <h1>Secure. Simple. Focused.</h1>
        <p>
            A secure online examination platform designed to provide
            students and teachers with a reliable examination experience.
        </p>
        <ul class="security-list">
            <li>✓ Secure account authentication</li>
            <li>✓ Camera & microphone verification</li>
            <li>✓ Organized courses and assessments</li>
            <li>✓ Dedicated examination area</li>
        </ul>
    </section>

    <section class="login-area">
        <div class="login-card">
            <h2>Welcome</h2>
            <p class="sub">Choose your account type to continue.</p>

            <div class="role-switch">
                <a class="active" href="/student">🎓 Student</a>
                <a href="/teacher">👨‍🏫 Teacher</a>
            </div>

            <p style="color:#65758b;line-height:1.6;">
                Select your role above. You will be taken to the secure
                login page for your account.
            </p>
        </div>
    </section>
</div>
"""
    return page("Secure Examination Platform", content)



# Student login + dashboard

STUDENT_LOGIN_HTML = """
<div class="login-page">
    <section class="login-side">
        <div class="brand">
            <span class="logo">🛡️</span>
            Secure Exam Platform
        </div>
        <h1>Student Portal</h1>
        <p>
            Sign in to access your courses, assessments and secure
            online examinations.
        </p>
        <ul class="security-list">
            <li>✓ Protected student account</li>
            <li>✓ Secure examination access</li>
            <li>✓ Camera & microphone verification</li>
        </ul>
    </section>

    <section class="login-area">
        <div class="login-card">
            <h2>Student Login</h2>
            <p class="sub">Enter your credentials to continue.</p>

            __LOGIN_ERROR__

            <form method="POST">
                <label>Username</label>
                <input class="input" type="text" name="username"
                       placeholder="Enter your username" required>

                <label>Password</label>
                <div class="password-wrap">
                    <input class="input" id="studentPassword"
                           type="password" name="password"
                           placeholder="Enter your password" required>
                    <button class="show-pass" type="button"
                            onclick="togglePassword('studentPassword')">👁</button>
                </div>

                <button class="btn full" type="submit">Sign In</button>
            </form>

            <a class="back" href="/">← Back to role selection</a>
        </div>
    </section>
</div>
<script>
function togglePassword(id) {
    const input = document.getElementById(id);
    input.type = input.type === "password" ? "text" : "password";
}
</script>
"""


@app.route("/student", methods=["GET", "POST"])
def student():
    if request.method == "GET" and session.get("role") == "student" and session.get("user_id"):
        return redirect(url_for("student_dashboard"))
    error = ""
    status = 200
    if request.method == "POST":
        password = request.form.get("password", "")
        user, message, status = authenticate("student", request.form.get("username", ""), password)
        if user:
            start_session(user, "student", password)
            return after_login_redirect("student")
        error = '<div class="alert">%s</div>' % htmllib.escape(message)
    return page("Student Login", STUDENT_LOGIN_HTML.replace("__LOGIN_ERROR__", error)), status


@app.route("/student/dashboard")
def student_dashboard():
    if session.get("role") != "student" or not session.get("user_id"):
        return redirect(url_for("student"))
    content = navbar() + f"""
<main class="container">
    <section class="hero">
        <span class="status">● Account authenticated</span>
        <h1 style="margin-top:18px;">Welcome, {htmllib.escape(str(session.get("student_name", "Student")))}</h1>
        <p>Your secure student dashboard is ready.</p>
    </section>

    <h2 class="section-title">Quick Access</h2>

    <div class="grid">
        <div class="card">
            <div class="card-icon">📚</div>
            <h3>My Courses</h3>
            <p>View your enrolled courses, lectures and course materials.</p>
            <a class="btn secondary" href="/student/courses">View Courses</a>
        </div>

        <div class="card">
            <div class="card-icon">📝</div>
            <h3>Assessments</h3>
            <p>Check assignments, quizzes and other assessments.</p>
            <a class="btn secondary" href="/student/assessments">View Assessments</a>
        </div>

        <div class="card">
            <div class="card-icon">🎓</div>
            <h3>Examinations</h3>
            <p>Access available exams and complete the security check.</p>
            <a class="btn" href="/student/exams">View Exams</a>
        </div>
        <div class="card">
            <div class="card-icon">🧑‍💻</div>
            <h3>Face Registration</h3>
            <p>Register your face once before attempting a secure exam.</p>
            <a class="btn secondary" href="/student/enroll-face">Register Face</a>
        </div>
    </div>

    <h2 class="section-title">Security Check</h2>

    <div class="card">
        <div class="exam-row">
            <div>
                <h3>Camera & Microphone</h3>
                <p>Before starting an examination, verify that your camera
                   and microphone are working correctly.</p>
            </div>
            <button class="btn" onclick="startCamera()">Test Devices</button>
        </div>

        <div class="camera-box">
            <video id="camera" autoplay playsinline muted></video>
            <p id="cameraStatus" style="color:#dcecff;">
                Camera preview will appear here.
            </p>
        </div>
    </div>
</main>
"""

    scripts = """
<script src="https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.15/dist/face-api.js"></script>
<script>
function toggleMenu() {
    const menu = document.getElementById("profileMenu");
    menu.style.display = menu.style.display === "block" ? "none" : "block";
}

let dashModelsReady = false;
const dashModelUrl = "https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.15/model/";

function setStatus(text, color) {
    const status = document.getElementById("cameraStatus");
    status.textContent = text;
    status.style.color = color || "#dcecff";
}

async function startCamera() {
    try {
        setStatus("Requesting camera and microphone access...");
        const stream = await navigator.mediaDevices.getUserMedia({video: true, audio: true});
        const video = document.getElementById("camera");
        video.srcObject = stream;
        await new Promise(resolve => {
            if (video.readyState >= 2) resolve();
            else video.onloadedmetadata = () => resolve();
        });
        setStatus("Camera and microphone OK. Loading face models (first time can take a while)...");

        if (typeof faceapi === "undefined") {
            setStatus("Face library failed to load. Check your internet connection and reload the page.", "#ffb4b4");
            return;
        }
        if (!dashModelsReady) {
            await Promise.all([
                faceapi.nets.ssdMobilenetv1.loadFromUri(dashModelUrl),
                faceapi.nets.faceLandmark68Net.loadFromUri(dashModelUrl),
                faceapi.nets.faceRecognitionNet.loadFromUri(dashModelUrl)
            ]);
            dashModelsReady = true;
        }

        setStatus("Look at the camera. Verifying your face...");
        const detected = await faceapi.detectSingleFace(video).withFaceLandmarks().withFaceDescriptor();
        if (!detected) {
            setStatus("Camera works, but no clear face was detected. Improve lighting and try again.", "#ffb4b4");
            return;
        }

        const response = await fetch("/api/face-verify", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({descriptor: Array.from(detected.descriptor)})
        });
        let result = {};
        try { result = await response.json(); } catch (e) {}
        console.log("face-verify response", response.status, result);

        if (response.status === 401) {
            setStatus("Your session expired. Please sign in again.", "#ffb4b4");
        } else if (result.needs_enrollment) {
            setStatus("No registered face found. Please register your face first.", "#ffb4b4");
            document.getElementById("cameraStatus").innerHTML += ' <a style="color:#9bcaff" href="/student/enroll-face">Register your face</a>';
        } else if (response.ok && result.ok) {
            setStatus("\u2713 Camera, microphone and face verification passed.", "#7ee2a8");
        } else {
            setStatus(result.message || "Face verification failed.", "#ffb4b4");
        }
    } catch (error) {
        setStatus("Error: " + (error && error.message ? error.message : error), "#ffb4b4");
        console.error(error);
    }
}
</script>
"""
    return page("Student Dashboard", content, scripts)

# Face enrollment and verification APIs
def require_student_json():
    if session.get("role") != "student" or not session.get("user_id"):
        return jsonify({"ok": False, "error": "Please sign in as a student first."}), 401
    return None

@app.route("/student/enroll-face", methods=["GET"])
def enroll_face_page():
    if session.get("role") != "student" or not session.get("user_id"):
        return redirect(url_for("student"))
    content = navbar() + """
<main class="container">
  <section class="hero"><h1>Face Registration</h1><p>Register your face in good lighting. Your browser creates a numerical descriptor; this page does not upload or store a photo.</p></section>
  <div class="card">
    <video id="enrollVideo" autoplay playsinline muted style="width:min(100%,560px);background:#000;border-radius:12px"></video>
    <p id="enrollStatus">Press Start Camera, then Register Face.</p>
    <button class="btn" id="startEnrollCamera" type="button">Start Camera</button>
    <button class="btn secondary" id="saveFaceBtn" type="button" disabled>Register Face</button>
    <p><a class="btn secondary" href="/student/dashboard">Back to Dashboard</a></p>
  </div>
</main>
"""
    scripts = r"""
<script defer src="https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.15/dist/face-api.js"></script>
<script>
let enrollStream = null;
let faceModelsReady = false;
const modelUrl = "https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.15/model/";
async function loadFaceModels() {
  if (faceModelsReady) return;
  await Promise.all([
    faceapi.nets.ssdMobilenetv1.loadFromUri(modelUrl),
    faceapi.nets.faceLandmark68Net.loadFromUri(modelUrl),
    faceapi.nets.faceRecognitionNet.loadFromUri(modelUrl)
  ]);
  faceModelsReady = true;
}
document.getElementById("startEnrollCamera").addEventListener("click", async () => {
  const status = document.getElementById("enrollStatus");
  try {
    enrollStream = await navigator.mediaDevices.getUserMedia({video:true, audio:false});
    document.getElementById("enrollVideo").srcObject = enrollStream;
    await loadFaceModels();
    status.textContent = "Camera ready. Look at the camera, then press Register Face.";
    document.getElementById("saveFaceBtn").disabled = false;
  } catch (e) { status.textContent = "Could not start camera or load face models. Check camera permission and internet access."; console.error(e); }
});
document.getElementById("saveFaceBtn").addEventListener("click", async () => {
  const status = document.getElementById("enrollStatus");
  const video = document.getElementById("enrollVideo");
  try {
    const result = await faceapi.detectSingleFace(video).withFaceLandmarks().withFaceDescriptor();
    if (!result) { status.textContent = "No clear face detected. Improve lighting and try again."; return; }
    const response = await fetch("/api/face-reference", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({descriptor:Array.from(result.descriptor)})});
    const data = await response.json();
    status.textContent = data.ok ? "Face registered successfully. You can now enter an exam." : (data.error || "Could not register face.");
  } catch (e) { status.textContent = "Face registration failed. Please try again."; console.error(e); }
});
window.addEventListener("beforeunload", () => { if (enrollStream) enrollStream.getTracks().forEach(t => t.stop()); });
</script>
"""
    return page("Face Registration", content, scripts)

@app.route("/api/face-reference", methods=["POST"])
def save_face_reference_api():
    auth_error = require_student_json()
    if auth_error:
        return auth_error
    data = request.get_json(silent=True) or {}
    descriptor = data.get("descriptor")
    if not isinstance(descriptor, list) or len(descriptor) != 128:
        return jsonify({"ok": False, "error": "Invalid face descriptor. Please capture your face again."}), 400
    try:
        import face_verification as fv
        if not ALLOW_FACE_RE_ENROLL and fv.get_reference_descriptor(get_db(), session["user_id"]) is not None:
            return jsonify({"ok": False, "error": "A face is already registered for your account. Ask your teacher to reset it."}), 409
        fv.save_reference_descriptor(get_db(), session["user_id"], descriptor)
        session.pop("face_verified_ts", None)
        return jsonify({"ok": True})
    except Exception as exc:
        app.logger.exception("Unable to save face reference")
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({"ok": False, "error": "Could not save the face reference. Please contact support if this continues."}), 500

@app.route("/api/face-verify", methods=["POST"])
def verify_face_api():
    auth_error = require_student_json()
    if auth_error:
        return auth_error
    data = request.get_json(silent=True) or {}
    descriptor = data.get("descriptor")
    session.pop("face_verified_ts", None)  # any new attempt invalidates the previous pass
    face_key = ("face", session["user_id"])
    wait = FACE_LIMITER.blocked(face_key)
    if wait:
        return jsonify({"ok": False, "message": "Too many failed face checks. Please try again in %s." % minutes_text(wait)}), 429
    try:
        import face_verification as fv
        matched, detail = fv.verify_descriptor(get_db(), session["user_id"], descriptor)
        app.logger.info("Face verify user=%s matched=%s detail=%s", session["user_id"], matched, detail)
        if detail == "no_reference":
            return jsonify({"ok": False, "needs_enrollment": True, "message": "Register your face before starting an exam."}), 409
        if detail == "invalid_descriptor":
            return jsonify({"ok": False, "message": "Invalid face data. Please try again."}), 400
        if not matched:
            FACE_LIMITER.fail(face_key)
            return jsonify({"ok": False, "message": "Face verification did not match. Please try again."}), 403
        FACE_LIMITER.reset(face_key)
        session["face_verified_ts"] = time.time()
        return jsonify({"ok": True, "message": "Face verified."})
    except Exception:
        app.logger.exception("Face verification failed")
        return jsonify({"ok": False, "message": "Face verification failed. Please try again."}), 500

# Protect student pages even when a URL is entered directly.
@app.before_request
def protect_student_pages():
    protected_prefixes = ("/student/", "/course/")
    if request.path.startswith(protected_prefixes):
        if session.get("role") != "student" or not session.get("user_id"):
            return redirect(url_for("student"))

# Student pages

@app.route("/student/courses")
def student_courses():
    content = navbar() + """
<main class="container">
    <div class="hero">
        <h1>My Courses</h1>
        <p>Access your courses and learning materials.</p>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-icon">💻</div>
            <h3>Software Engineering</h3>
            <p>Course lectures, recordings and examination materials.</p>
            <a class="btn" href="/course/software-engineering">Open Course</a>
        </div>

        <div class="card">
            <div class="card-icon">🗄️</div>
            <h3>Database Management</h3>
            <p>Course information and available learning resources.</p>
            <a class="btn" href="/course/database">Open Course</a>
        </div>
    </div>

    <a class="back" href="/student/dashboard">← Back to Dashboard</a>
</main>
"""
    return page("My Courses", content)


@app.route("/student/assessments")
def student_assessments():
    content = navbar() + """
<main class="container">
    <div class="hero">
        <h1>Assessments</h1>
        <p>Track your assignments, quizzes and tests.</p>
    </div>

    <div class="list-card">
        <div><strong>Assignment 1</strong><br><small>Course assignment</small></div>
        <span class="status">Available</span>
    </div>

    <div class="list-card">
        <div><strong>Assignment 2</strong><br><small>Course assignment</small></div>
        <span class="status">Available</span>
    </div>

    <div class="list-card">
        <div><strong>Quiz 1</strong><br><small>Online quiz</small></div>
        <span class="status">Available</span>
    </div>

    <div class="list-card">
        <div><strong>Test 1</strong><br><small>Online test</small></div>
        <span class="status">Available</span>
    </div>

    <a class="back" href="/student/dashboard">← Back to Dashboard</a>
</main>
"""
    return page("Assessments", content)


def exam_action_html(exam_key, state):
    if state == "locked":
        return '<span class="status" style="background:#fdecea;color:#b42318;">🔒 Locked</span>'
    if state == "completed":
        return '<span class="status" style="background:#e7f6ee;color:#067647;">✓ Completed</span>'
    label = "Resume" if state == "in_progress" else "Start"
    return '<a class="btn" href="/exam/%s">%s</a>' % (exam_key, label)


@app.route("/student/exams")
def student_exams():
    conn = get_db()
    states = {k: ea.get_exam_state(conn, session["user_id"], k)[0] for k in EXAM_TITLES}
    content = navbar() + f"""
<main class="container">
    <div class="hero">
        <h1>Examinations</h1>
        <p>Select an examination and complete the security verification.</p>
    </div>

    <div class="card">
        <div class="exam-row">
            <div>
                <div class="card-icon">📝</div>
                <h3>Midterm Examination</h3>
                <p>Camera and microphone verification are required.</p>
            </div>
            {exam_action_html("midterm", states["midterm"])}
        </div>
    </div>

    <div class="card" style="margin-top:18px;">
        <div class="exam-row">
            <div>
                <div class="card-icon">🎓</div>
                <h3>Final Examination</h3>
                <p>Complete the security check before entering the exam.</p>
            </div>
            {exam_action_html("final", states["final"])}
        </div>
    </div>

    <a class="back" href="/student/dashboard">← Back to Dashboard</a>
</main>
"""
    return page("Examinations", content)



# Course details

@app.route("/course/<course_name>")
def course(course_name):
    display_name = course_name.replace("-", " ").title()

    content = navbar() + f"""
<main class="container">
    <div class="hero">
        <h1>{display_name}</h1>
        <p>Course information and available resources.</p>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-icon">👨‍🏫</div>
            <h3>Course Information</h3>
            <p>Teacher: Teacher One</p>
            <p>Reference: Course Reference Book</p>
        </div>

        <div class="card">
            <div class="card-icon">📖</div>
            <h3>Lectures</h3>
            <p>Lecture 1</p>
            <p>Lecture 2</p>
            <p>Lecture 3</p>
        </div>

        <div class="card">
            <div class="card-icon">🎥</div>
            <h3>Lecture Recordings</h3>
            <p>Lecture Recording 1</p>
            <p>Lecture Recording 2</p>
        </div>
    </div>

    <div class="card" style="margin-top:20px;">
        <h3>Examination</h3>
        <p>When you are ready, proceed to the final examination.</p>
        <a class="btn" href="/exam/final">Final Exam</a>
    </div>

    <a class="back" href="/student/courses">← Back to Courses</a>
</main>
"""
    return page("Course Details", content)


# Exams

# Sample exam (Database course). Answer keys are intentionally NOT included:
# the browser only receives questions, never correct answers.
SAMPLE_EXAM = {
    "duration_minutes": 30,
    "questions": [
        {"type": "mcq", "marks": 2, "text": "Which SQL command is used to retrieve data from a database?",
         "options": ["INSERT", "SELECT", "UPDATE", "DELETE"]},
        {"type": "mcq", "marks": 2, "text": "What is the main purpose of a PRIMARY KEY?",
         "options": ["To encrypt a table", "To uniquely identify each row", "To sort the table alphabetically", "To delete duplicate tables"]},
        {"type": "mcq", "marks": 2, "text": "Which normal form removes partial dependency?",
         "options": ["First normal form (1NF)", "Second normal form (2NF)", "Third normal form (3NF)", "Boyce-Codd normal form (BCNF)"]},
        {"type": "mcq", "marks": 2, "text": "Which SQL clause is used to filter records?",
         "options": ["GROUP BY", "ORDER BY", "WHERE", "LIMIT"]},
        {"type": "mcq", "marks": 2, "text": "Which keyword is used to sort the result set?",
         "options": ["SORT", "ORDER BY", "ARRANGE", "GROUP"]},
        {"type": "mcq", "marks": 2, "text": "Which of the following is a relational database management system?",
         "options": ["MySQL", "Photoshop", "Excel Charts", "Notepad"]},

        {"type": "tf", "marks": 1, "text": "A table can have more than one primary key."},
        {"type": "tf", "marks": 1, "text": "A foreign key creates a link between two tables."},
        {"type": "tf", "marks": 1, "text": "The DELETE command removes the whole table structure from the database."},
        {"type": "tf", "marks": 1, "text": "NULL is the same as zero."},

        {"type": "match", "marks": 4, "text": "Match each SQL command with its purpose.",
         "left": ["SELECT", "INSERT", "UPDATE", "DELETE"],
         "right": ["Modify existing rows", "Remove rows", "Retrieve data", "Add a new row"]},
        {"type": "match", "marks": 4, "text": "Match each database term with its definition.",
         "left": ["Primary key", "Foreign key", "Index", "View"],
         "right": ["Speeds up searching", "A virtual table built from a query", "Links a table to another table", "Uniquely identifies a row"]},

        {"type": "short", "marks": 4, "text": "Define a database in one or two sentences."},
        {"type": "short", "marks": 4, "text": "Explain the difference between the DELETE and DROP commands."},
        {"type": "short", "marks": 4, "text": "Write an SQL query that returns all columns of every row from a table named students."},
    ],
}
for _i, _q in enumerate(SAMPLE_EXAM["questions"], start=1):
    _q["id"] = "q%d" % _i

# Exams the server knows about. The browser sends only the key; titles and
# durations always come from here, never from the page.
EXAM_TITLES = {"midterm": "Midterm Examination", "final": "Final Examination"}


def ensure_exam_submissions_table(conn):
    cursor = conn.cursor()
    cursor.execute(
        """CREATE TABLE IF NOT EXISTS exam_submissions (
            id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(191) NOT NULL,
            username VARCHAR(191) NOT NULL,
            student_name VARCHAR(255) NOT NULL,
            exam_title VARCHAR(255) NOT NULL,
            status VARCHAR(30) NOT NULL,
            answers LONGTEXT NOT NULL,
            elapsed_seconds INT NOT NULL DEFAULT 0,
            submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
    )
    conn.commit()
    cursor.close()

run_startup_task(ensure_exam_submissions_table)
run_startup_task(ea.ensure_schema)


def log_behavior_event(conn, attempt, etype, reason, warning_number=None):
    """Writes one behavior event. Exam title and elapsed time come from the server."""
    elapsed = max(0, int(time.time()) - attempt["started_ts"])
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO behavior_events
           (user_id, username, student_name, exam_title, event_type, reason,
            warning_number, elapsed_seconds, attempt_id)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (session["user_id"], session.get("username", ""),
         session.get("student_name", session.get("username", "")),
         EXAM_TITLES.get(attempt["exam_key"], attempt["exam_key"]),
         etype, str(reason)[:1000], warning_number, elapsed, attempt["id"])
    )
    conn.commit()
    cursor.close()


@app.route("/api/exam-submit", methods=["POST"])
def exam_submit_api():
    auth_error = require_student_json()
    if auth_error:
        return auth_error
    data = request.get_json(silent=True) or {}
    try:
        conn = get_db()
        attempt = ea.get_attempt_for_user(conn, data.get("attempt_id"), session["user_id"])
        if not attempt:
            return jsonify({"ok": False, "error": "Unknown exam attempt."}), 404
        answers = json.dumps(data.get("answers", {}), ensure_ascii=False)
        if len(answers) > 200000:
            return jsonify({"ok": False, "error": "Answers are too large."}), 400
        client_status = str(data.get("status", "submitted"))[:30]
        final, duplicate = ea.save_submission(
            conn, attempt, client_status, answers,
            session.get("student_name", session.get("username", "")),
            session.get("username", ""),
            EXAM_TITLES.get(attempt["exam_key"], attempt["exam_key"]),
        )
        if not duplicate and final != "terminated":
            note = {"time_up": "Time ended. Exam submitted automatically.",
                    "late": "Exam submitted after the deadline grace period."}.get(final, "Exam submitted.")
            log_behavior_event(conn, attempt, "submitted", note)
        return jsonify({"ok": True, "status": final, "duplicate": duplicate})
    except Exception:
        app.logger.exception("Unable to save exam submission")
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({"ok": False, "error": "Your answers could not be saved. Please try again."}), 500


def exam_page(title, exam_key, back_url="/student/exams"):
    content = navbar() + f"""
<main class="container">
    <div class="hero">
        <span class="status">🛡️ Secure Examination</span>
        <h1>{title}</h1>
        <p>Stay on this examination page. Copying, pasting, translating,
        or leaving the exam window is not allowed.</p>
    </div>

    <div class="card" id="precheckCard">
        <h3>Pre-Exam Security Check</h3>
        <p>Camera and microphone access are required before starting.</p>
        <button class="btn" onclick="startCamera()">Run Security Check</button>

        <div class="camera-box">
    <video id="camera" autoplay playsinline></video>

    <p id="cameraStatus" style="color:#dcecff;margin-top:12px;">
        Waiting for device verification...
    </p>

    <p id="aiStatus" style="color:#dcecff;margin-top:8px;">
        AI monitoring: Not started
    </p>

    <p id="behaviorLive" style="color:#dcecff;margin-top:8px;font-weight:700;"></p>
    <p id="gazeStatus" style="color:#b9d8ff;margin-top:8px;font-size:12px;">Gaze observation: waiting for exam start</p>
    <div id="gazeReminder" role="status" aria-live="polite" style="display:none;margin-top:10px;padding:12px 14px;border-radius:10px;background:#fff4d6;color:#633b00;font-weight:700;">Please look toward your examination screen.</div>
</div>

        <div style="margin-top:20px;">
            <button id="continueBtn" class="btn" disabled onclick="startExam()">
                Continue to Examination
            </button>
        </div>
    </div>

    <div id="examArea" class="card" style="display:none; margin-top:20px;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap;">
            <div>
                <h2 style="margin:0;">{title}</h2>
                <p id="examMeta" style="margin:6px 0;color:var(--muted-fg);">Examination in progress</p>
            </div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
                <span id="examTimer" class="status">⏱ --:--</span>
                <span id="warningCounter" class="status">Warnings: 0 / 3</span>
            </div>
        </div>

        <hr style="border:0;border-top:1px solid var(--border);margin:20px 0;">

        <div class="exam-layout">
            <div id="qPanel"></div>
            <aside class="exam-side">
                <h3 style="margin:0;">Questions</h3>
                <p id="navCounts" style="margin:6px 0 0;font-size:13px;color:var(--muted-fg);"></p>
                <div id="qGrid" class="q-grid"></div>
                <div class="q-legend">
                    <span><i class="dot" style="background:#12b76a;"></i> Answered</span>
                    <span><i class="dot" style="background:#fff;border:1px solid #98a2b3;"></i> Not answered</span>
                    <span>🚩 Flagged</span>
                </div>
                <button class="btn full" style="margin-top:14px;" onclick="openSubmit()">Submit Exam</button>
                <div id="sideCamera"></div>
            </aside>
        </div>
    </div>
</main>

<div id="warningOverlay" class="security-overlay">
    <div class="warning-modal">
        <div id="warningIcon" class="warning-icon">⚠️</div>
        <div id="warningTitle" class="warning-title">Security Warning</div>
        <div id="warningMessage" class="warning-message">
            A prohibited action was detected.
        </div>
        <div id="warningNumber" class="warning-number">Warning 1 of 3</div>
        <button class="btn warning-button" onclick="closeWarning()">
            Continue Exam
        </button>
    </div>
</div>

<div id="terminatedOverlay" class="security-overlay">
    <div class="warning-modal terminated-modal">
        <div class="warning-icon">🚨</div>
        <div class="warning-title">Examination Terminated</div>
        <div class="warning-message">
            You exceeded the maximum number of allowed security violations.
            Your examination session has been terminated.
        </div>
        <button class="btn warning-button"
                onclick="window.location.href='{back_url}'">
            Return to Exams
        </button>
    </div>
</div>

<div id="submitOverlay" class="security-overlay">
    <div class="warning-modal">
        <div class="warning-icon">📝</div>
        <div class="warning-title">Submit your exam?</div>
        <div id="submitMessage" class="warning-message"></div>
        <button class="btn warning-button" id="submitConfirmBtn" onclick="submitExam('submitted')">Yes, submit my exam</button>
        <button class="btn warning-button" style="margin-top:10px;background:#667085;" onclick="closeSubmit()">Go back and review</button>
    </div>
</div>

<div id="doneOverlay" class="security-overlay">
    <div class="warning-modal">
        <div class="warning-icon">✅</div>
        <div class="warning-title">Exam submitted</div>
        <div class="warning-message">Your answers were saved successfully. You may now leave this page.</div>
        <button class="btn warning-button" onclick="window.location.href='{back_url}'">Return to Exams</button>
    </div>
</div>
"""

    scripts = r"""
<style>
#examArea { user-select:none; -webkit-user-select:none; }
#examArea textarea { user-select:text; -webkit-user-select:text; }
.exam-layout { display:grid; grid-template-columns:minmax(0,1fr) 260px; gap:20px; align-items:start; }
@media (max-width:820px) { .exam-layout { grid-template-columns:1fr; } }
.exam-side { position:sticky; top:12px; background:var(--muted); border-radius:var(--radius-sm); padding:16px; }
.q-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:8px; margin:12px 0; }
.q-btn { position:relative; border:2px solid #d0d5dd; background:#fff; color:#101828; border-radius:10px; padding:10px 0; font-weight:700; cursor:pointer; font-size:14px; }
.q-btn.answered { background:#e7f6ec; border-color:#12b76a; color:#067647; }
.q-btn.current { outline:3px solid #2563eb; outline-offset:1px; }
.q-btn.flagged::after { content:"🚩"; position:absolute; top:-9px; right:-6px; font-size:13px; }
.q-legend { display:flex; flex-direction:column; gap:4px; font-size:12px; color:var(--muted-fg); }
.q-legend .dot { display:inline-block; width:11px; height:11px; border-radius:3px; margin-right:6px; vertical-align:middle; }
.q-card { background:var(--muted); border-radius:var(--radius-sm); padding:20px; }
.q-head { display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:6px; }
.q-title { font-weight:800; font-size:18px; }
.q-badge { display:inline-block; font-size:12px; font-weight:700; padding:3px 10px; border-radius:999px; background:#eaf2ff; color:#1d4ed8; margin-left:8px; }
.q-marks { font-size:13px; color:var(--muted-fg); margin-left:8px; }
.q-flag { border:1px solid #d0d5dd; background:#fff; color:#344054; border-radius:10px; padding:8px 12px; font-weight:700; cursor:pointer; }
.q-flag.on { background:#fff4e5; border-color:#f79009; color:#9a5b00; }
.q-text { font-size:17px; line-height:1.6; margin:10px 0 16px; }
.q-opt { display:block; padding:12px 14px; border:1px solid #d0d5dd; border-radius:10px; margin-bottom:10px; background:#fff; color:#101828; cursor:pointer; text-transform:none; font-weight:500; letter-spacing:0; }
.q-opt input { margin-right:10px; }
.q-opt.picked { border-color:#2563eb; background:#eff6ff; }
.match-row { display:grid; grid-template-columns:1fr 1fr; gap:10px; align-items:center; margin-bottom:10px; }
.match-row .term { font-weight:700; }
.match-row select { padding:10px; border-radius:10px; border:1px solid #d0d5dd; background:#fff; color:#101828; font:inherit; }
.short-answer { width:100%; min-height:170px; padding:12px; border-radius:10px; border:1px solid #d0d5dd; font:inherit; resize:vertical; background:#fff; color:#101828; }
.ans-tools { display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; align-items:center; }
.ans-tools button { border:1px solid #d0d5dd; background:#fff; color:#344054; border-radius:8px; padding:6px 12px; font-weight:600; cursor:pointer; }
.ans-tools span { font-size:12px; color:var(--muted-fg); }
.q-actions { display:flex; justify-content:space-between; gap:10px; margin-top:18px; }
.q-actions .btn[disabled] { opacity:.45; cursor:not-allowed; }
.exam-live #precheckCard { display:none; }
.exam-side .camera-box { margin-top:14px; padding:10px; border-radius:14px; }
.exam-side .camera-box video { width:100%; }
.exam-side #cameraStatus { display:none; }
.exam-side .camera-box p { font-size:11px; margin:6px 0 0 !important; }
#submitOverlay, #doneOverlay { z-index:9000; }
#warningOverlay, #terminatedOverlay { z-index:10000; }
</style>
<style>
.security-overlay {
    display:none;
    position:fixed;
    inset:0;
    background:rgba(10,25,48,.68);
    backdrop-filter:blur(4px);
    z-index:99999;
    align-items:center;
    justify-content:center;
    padding:20px;
}
.warning-modal {
    width:min(390px,92vw);
    background:white;
    border-radius:20px;
    padding:32px;
    text-align:center;
    box-shadow:0 20px 60px rgba(0,0,0,.25);
    animation:warningPop .18s ease-out;
    font-family: var(--font-body);
}
@keyframes warningPop {
    from { transform:scale(.92); opacity:0; }
    to { transform:scale(1); opacity:1; }
}
.warning-icon { font-size:42px; margin-bottom:10px; }
.warning-title { font-family: var(--font-display); font-size:21px; font-weight:800; margin-bottom:12px; color: var(--fg); }
.warning-message { color:var(--muted-fg); line-height:1.55; margin-bottom:16px; font-size:14px; }
.warning-number {
    display:inline-block;
    background:#fff4e5;
    color:#9a5b00;
    padding:8px 14px;
    border-radius:20px;
    font-weight:800;
    font-size:12.5px;
    margin-bottom:22px;
}
.warning-button { width:100%; }
.terminated-modal { border-top:6px solid var(--destructive); }
</style>
<script src="https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.15/dist/face-api.js"></script>
<script>
let cameraStream = null;
let examStarted = false;
let warningCount = 0;
let warningOpen = false;
let terminated = false;
let examStartedAt = null;

const EXAM_KEY = "__EXAM_KEY__";
let EXAM = {duration_minutes: 0, questions: []};  // filled in by the server when the attempt starts
let attemptId = null;
let initialRemainingSeconds = 0;
let deadlineAt = 0;
const answers = {};
const flagged = new Set();
let current = 0;
let answerClipboard = "";
let examTimer = null;
let remainingSeconds = 0;
let submitting = false;

function setLive(text, ok) {
    const e = document.getElementById("behaviorLive");
    if (!e) return;
    e.textContent = "Live check: " + text;
    e.style.color = ok ? "#7ee2a8" : "#ffd38a";
}

function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
}

function isAnswered(q) {
    const a = answers[q.id];
    if (a === undefined || a === null) return false;
    if (q.type === "match") return Object.keys(a).length === q.left.length;
    if (q.type === "short") return String(a).trim().length > 0;
    return true;
}

function typeLabel(q) {
    return {mcq: "Multiple choice", tf: "True / False", match: "Matching", short: "Short answer"}[q.type] || q.type;
}

function renderNav() {
    const grid = document.getElementById("qGrid");
    grid.innerHTML = "";
    let answeredCount = 0;
    EXAM.questions.forEach(function (q, i) {
        const b = el("button", "q-btn", String(i + 1));
        b.type = "button";
        if (isAnswered(q)) { b.classList.add("answered"); answeredCount++; }
        if (flagged.has(q.id)) b.classList.add("flagged");
        if (i === current) b.classList.add("current");
        b.onclick = function () { goTo(i); };
        grid.appendChild(b);
    });
    document.getElementById("navCounts").textContent =
        "Answered " + answeredCount + " of " + EXAM.questions.length + " · Flagged " + flagged.size;
}

function goTo(i) {
    if (i < 0 || i >= EXAM.questions.length) return;
    current = i;
    renderQuestion();
}

function renderQuestion() {
    const q = EXAM.questions[current];
    const panel = document.getElementById("qPanel");
    panel.innerHTML = "";
    const card = el("div", "q-card");

    const head = el("div", "q-head");
    const left = el("div");
    left.appendChild(el("span", "q-title", "Question " + (current + 1) + " of " + EXAM.questions.length));
    left.appendChild(el("span", "q-badge", typeLabel(q)));
    left.appendChild(el("span", "q-marks", q.marks + (q.marks === 1 ? " mark" : " marks")));
    head.appendChild(left);
    const flagBtn = el("button", "q-flag" + (flagged.has(q.id) ? " on" : ""), flagged.has(q.id) ? "🚩 Flagged" : "🚩 Flag for review");
    flagBtn.type = "button";
    flagBtn.onclick = function () {
        if (flagged.has(q.id)) flagged.delete(q.id); else flagged.add(q.id);
        renderQuestion();
    };
    head.appendChild(flagBtn);
    card.appendChild(head);

    card.appendChild(el("p", "q-text", q.text));

    if (q.type === "mcq" || q.type === "tf") {
        const opts = q.type === "mcq"
            ? q.options.map(function (t, i) { return {label: t, value: i}; })
            : [{label: "True", value: "true"}, {label: "False", value: "false"}];
        opts.forEach(function (o) {
            const lab = el("label", "q-opt" + (answers[q.id] === o.value ? " picked" : ""));
            const input = document.createElement("input");
            input.type = "radio";
            input.name = q.id;
            input.checked = answers[q.id] === o.value;
            input.onchange = function () { answers[q.id] = o.value; renderQuestion(); };
            lab.appendChild(input);
            lab.appendChild(document.createTextNode(o.label));
            card.appendChild(lab);
        });
    } else if (q.type === "match") {
        const saved = answers[q.id] || {};
        q.left.forEach(function (term, li) {
            const row = el("div", "match-row");
            row.appendChild(el("div", "term", (li + 1) + ". " + term));
            const sel = document.createElement("select");
            const blank = el("option", "", "Choose...");
            blank.value = "";
            sel.appendChild(blank);
            q.right.forEach(function (r, ri) {
                const o = el("option", "", r);
                o.value = String(ri);
                if (saved[li] === ri) o.selected = true;
                sel.appendChild(o);
            });
            sel.onchange = function () {
                const cur = answers[q.id] || {};
                if (sel.value === "") delete cur[li]; else cur[li] = parseInt(sel.value, 10);
                answers[q.id] = cur;
                renderNav();
            };
            row.appendChild(sel);
            card.appendChild(row);
        });
    } else if (q.type === "short") {
        const ta = document.createElement("textarea");
        ta.className = "short-answer";
        ta.placeholder = "Type your answer here...";
        ta.maxLength = 3000;
        ta.value = answers[q.id] || "";
        ta.addEventListener("input", function () { answers[q.id] = ta.value; renderNav(); });
        card.appendChild(ta);

        const tools = el("div", "ans-tools");
        const copyBtn = el("button", "", "Copy my answer");
        copyBtn.type = "button";
        copyBtn.onclick = function () {
            const selected = ta.value.substring(ta.selectionStart, ta.selectionEnd);
            answerClipboard = selected || ta.value;
            note.textContent = "Copied. You can paste it back here if needed.";
        };
        const pasteBtn = el("button", "", "Paste my answer");
        pasteBtn.type = "button";
        pasteBtn.onclick = function () {
            if (!answerClipboard) { note.textContent = "Nothing copied from an answer box yet."; return; }
            ta.setRangeText(answerClipboard, ta.selectionStart, ta.selectionEnd, "end");
            ta.dispatchEvent(new Event("input"));
            note.textContent = "Pasted.";
        };
        const note = el("span", "", "Copy and paste work only inside this answer box.");
        tools.appendChild(copyBtn);
        tools.appendChild(pasteBtn);
        tools.appendChild(note);
        card.appendChild(tools);
    }

    const actions = el("div", "q-actions");
    const prev = el("button", "btn", "← Previous");
    prev.type = "button";
    prev.disabled = current === 0;
    prev.onclick = function () { goTo(current - 1); };
    const next = el("button", "btn", "Next →");
    next.type = "button";
    next.disabled = current === EXAM.questions.length - 1;
    next.onclick = function () { goTo(current + 1); };
    actions.appendChild(prev);
    actions.appendChild(next);
    card.appendChild(actions);

    panel.appendChild(card);
    renderNav();
}

function formatTime(total) {
    const m = Math.floor(total / 60);
    const s = total % 60;
    return String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
}

function tickTimer() {
    remainingSeconds = Math.max(0, Math.round((deadlineAt - Date.now()) / 1000));
    const t = document.getElementById("examTimer");
    t.textContent = "⏱ " + formatTime(Math.max(0, remainingSeconds));
    if (remainingSeconds <= 300) t.style.color = "#b42318";
    if (remainingSeconds <= 0) {
        window.clearInterval(examTimer);
        submitExam("time_up");
    }
}

function initExam() {
    // Move the live camera preview into the side panel so it never covers the exam.
    const cam = document.querySelector(".camera-box");
    const slot = document.getElementById("sideCamera");
    if (cam && slot) slot.appendChild(cam);
    const total = EXAM.questions.reduce(function (n, q) { return n + q.marks; }, 0);
    document.getElementById("examMeta").textContent =
        EXAM.questions.length + " questions · " + total + " marks · " + EXAM.duration_minutes + " minutes";
    remainingSeconds = initialRemainingSeconds;
    deadlineAt = Date.now() + initialRemainingSeconds * 1000;
    document.getElementById("examTimer").textContent = "⏱ " + formatTime(remainingSeconds);
    examTimer = window.setInterval(tickTimer, 1000);
    renderQuestion();
}

function openSubmit() {
    const unanswered = EXAM.questions.filter(function (q) { return !isAnswered(q); }).length;
    let msg = "You answered " + (EXAM.questions.length - unanswered) + " of " + EXAM.questions.length + " questions.";
    if (unanswered) msg += " " + unanswered + " question(s) are still unanswered.";
    if (flagged.size) msg += " " + flagged.size + " question(s) are flagged for review.";
    msg += " You cannot change your answers after submitting.";
    document.getElementById("submitMessage").textContent = msg;
    document.getElementById("submitConfirmBtn").disabled = false;
    document.getElementById("submitOverlay").style.display = "flex";
}

function closeSubmit() {
    document.getElementById("submitOverlay").style.display = "none";
}

function sendSubmission(status) {
    const heading = document.querySelector(".hero h1");
    const elapsed = examStartedAt ? Math.round((Date.now() - examStartedAt) / 1000) : 0;
    const payloadAnswers = {};
    Object.keys(answers).forEach(function (k) { payloadAnswers[k] = answers[k]; });
    return fetch("/api/exam-submit", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        keepalive: true,
        body: JSON.stringify({
            attempt_id: attemptId,
            status: status,
            answers: payloadAnswers,
            elapsed_seconds: elapsed
        })
    });
}

async function submitExam(status) {
    if (submitting) return;
    submitting = true;
    const btn = document.getElementById("submitConfirmBtn");
    btn.disabled = true;
    let saved = false;
    try {
        const response = await sendSubmission(status);
        saved = response.ok;
    } catch (e) {
        console.error(e);
    }
    if (!saved) {
        submitting = false;
        btn.disabled = false;
        document.getElementById("submitMessage").textContent =
            "Your answers could not be saved. Check your internet connection and press submit again.";
        document.getElementById("submitOverlay").style.display = "flex";
        return;
    }
    examStarted = false;
    if (examTimer) window.clearInterval(examTimer);
    if (behaviorTimer) window.clearInterval(behaviorTimer);
    if (faceLandmarker) { faceLandmarker.close(); faceLandmarker = null; }
    if (cameraStream) cameraStream.getTracks().forEach(function (t) { t.stop(); });
    document.body.classList.remove("exam-live");
    document.getElementById("examArea").style.display = "none";
    document.getElementById("submitOverlay").style.display = "none";
    document.getElementById("doneOverlay").style.display = "flex";
}

function inAnswerBox(event) {
    const t = event.target;
    return !!(t && t.classList && t.classList.contains("short-answer"));
}

function logEvent(type, reason, warningNumber) {
    try {
        const heading = document.querySelector(".hero h1");
        const elapsed = examStartedAt ? Math.round((Date.now() - examStartedAt) / 1000) : 0;
        fetch("/api/behavior-event", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            keepalive: true,
            body: JSON.stringify({
                attempt_id: attemptId,
                type: type,
                reason: reason,
                warning_number: warningNumber || null,
                elapsed_seconds: elapsed
            })
        }).then(function (r) { return r.json(); }).then(function (d) {
            // The server is the authority: if it says the attempt is over, end it here too.
            if (d && d.terminated && type === "warning" && !terminated && examStarted) {
                terminateExam();
            }
        }).catch(function (e) { console.error("log failed", e); });
    } catch (e) {
        console.error("log failed", e);
    }
}

let faceVerified = false;
let faceApiReady = false;
let faceLandmarker = null;
let behaviorTimer = null;
let missingFaceSince = null;
let lookingAwaySince = null;
let lastBehaviorWarning = 0;
const BEHAVIOR_SECONDS = 10;
const BEHAVIOR_COOLDOWN_MS = 6000;
const faceApiModelUrl = "https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.15/model/";

async function loadFaceApiModels() {
    if (faceApiReady) return;
    await Promise.all([
        faceapi.nets.ssdMobilenetv1.loadFromUri(faceApiModelUrl),
        faceapi.nets.faceLandmark68Net.loadFromUri(faceApiModelUrl),
        faceapi.nets.faceRecognitionNet.loadFromUri(faceApiModelUrl)
    ]);
    faceApiReady = true;
}

async function startCamera() {
    const status = document.getElementById("cameraStatus");
    const button = document.getElementById("continueBtn");
    button.disabled = true;
    faceVerified = false;
    try {
        cameraStream = await navigator.mediaDevices.getUserMedia({video:true, audio:true});
        const video = document.getElementById("camera");
        video.srcObject = cameraStream;
        await new Promise(resolve => {
            if (video.readyState >= 2) resolve();
            else video.onloadedmetadata = () => resolve();
        });
        status.textContent = "Camera and microphone ready. Loading face models (first time can take a while)…";
        if (typeof faceapi === "undefined") {
            status.textContent = "Face library failed to load. Check your internet connection and reload the page.";
            status.style.color = "#ffb4b4";
            return;
        }
        await loadFaceApiModels();
        status.textContent = "Look at the camera. Verifying your face…";
        const detected = await faceapi.detectSingleFace(video).withFaceLandmarks().withFaceDescriptor();
        if (!detected) {
            status.textContent = "No clear face detected. Improve lighting and run the check again.";
            status.style.color = "#ffb4b4";
            return;
        }
        const response = await fetch("/api/face-verify", {
            method:"POST", headers:{"Content-Type":"application/json"},
            body:JSON.stringify({descriptor:Array.from(detected.descriptor)})
        });
        let result = {};
        try { result = await response.json(); } catch (e) {}
        console.log("face-verify response", response.status, result);
        if (response.status === 401) {
            status.textContent = "Your session expired. Please sign in again.";
            status.style.color = "#ffb4b4";
            return;
        }
        if (!response.ok || !result.ok) {
            status.textContent = result.message || result.error || "Face verification failed.";
            if (result.needs_enrollment) status.innerHTML += ' <a style="color:#9bcaff" href="/student/enroll-face">Register your face</a>.';
            status.style.color = "#ffb4b4";
            return;
        }
        faceVerified = true;
        status.textContent = "✓ Camera, microphone and face verification passed.";
        status.style.color = "#7ee2a8";
        button.disabled = false;
    } catch (error) {
        status.textContent = "Camera/model access failed: " + (error && error.message ? error.message : error);
        status.style.color = "#ffb4b4";
        console.error(error);
    }
}

async function startBehaviorMonitoring() {
    const aiStatus = document.getElementById("aiStatus");
    resetGazeObservation();
    try {
        const vision = await import("https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.14/+esm");
        const fileset = await vision.FilesetResolver.forVisionTasks(
            "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.14/wasm"
        );
        faceLandmarker = await vision.FaceLandmarker.createFromOptions(fileset, {
            baseOptions: {modelAssetPath:"/face-landmarker-model"},
            runningMode:"VIDEO", numFaces:3,
            minFaceDetectionConfidence:0.5,
            minFacePresenceConfidence:0.5,
            minTrackingConfidence:0.5
        });
        aiStatus.textContent = "AI monitoring: Active (face presence, multiple faces and sustained head direction).";
        aiStatus.style.color = "#7ee2a8";
        behaviorTimer = window.setInterval(analyzeBehaviorFrame, 700);
    } catch (error) {
        aiStatus.textContent = "AI monitoring could not start. Please reload and retry before the exam.";
        aiStatus.style.color = "#ffb4b4";
        console.error(error);
        throw error;
    }
}

function behaviorWarning(reason) {
    const now = Date.now();
    if (now - lastBehaviorWarning < BEHAVIOR_COOLDOWN_MS || warningOpen || terminated) return;
    lastBehaviorWarning = now;
    showViolation(reason);
}

// Experimental gaze reminder. Never counts as an exam violation or changes scores.
// MediaPipe iris centers: 468, 473; horizontal eye corners: 33/133, 362/263.
let gazeSamples = [];
let gazeBaseline = null;
let gazeSmoothed = null;
let gazeDeviationSince = null;
let gazeReminderUntil = 0;
const GAZE_CALIBRATION_FRAMES = 20;
const GAZE_SMOOTHING = 0.35;
const GAZE_OFFSET_THRESHOLD = 0.075; // experimental; tune with consented tests
const GAZE_REMINDER_SECONDS = 3;
const GAZE_REMINDER_COOLDOWN_MS = 15000;
let lastGazeReminder = -GAZE_REMINDER_COOLDOWN_MS;
function gazeRatio(iris, a, b) {
    const span = b.x - a.x;
    if (Math.abs(span) < 0.015) return null;
    const ratio = (iris.x - a.x) / span;
    return Number.isFinite(ratio) && ratio > -0.3 && ratio < 1.3 ? ratio : null;
}
function setGazeReminder(visible) {
    const reminder = document.getElementById("gazeReminder");
    if (reminder) reminder.style.display = visible ? "block" : "none";
}
function observeGaze(points) {
    const output = document.getElementById("gazeStatus");
    if (!output) return;
    if (![468, 473, 33, 133, 362, 263].every(i => points[i])) {
        output.textContent = "Gaze: iris landmarks unavailable (no gaze decision)";
        gazeDeviationSince = null;
        setGazeReminder(false);
        return;
    }
    const a = gazeRatio(points[468], points[33], points[133]);
    const b = gazeRatio(points[473], points[362], points[263]);
    if (a === null || b === null) {
        output.textContent = "Gaze: tracking uncertain (no gaze decision)";
        gazeDeviationSince = null;
        setGazeReminder(false);
        return;
    }
    const value = (a + b) / 2;
    gazeSmoothed = gazeSmoothed === null ? value :
        GAZE_SMOOTHING * value + (1 - GAZE_SMOOTHING) * gazeSmoothed;
    if (gazeBaseline === null) {
        gazeSamples.push(gazeSmoothed);
        output.textContent = "Gaze calibration: look at screen center (" +
            gazeSamples.length + "/" + GAZE_CALIBRATION_FRAMES + ")";
        if (gazeSamples.length >= GAZE_CALIBRATION_FRAMES) {
            const sorted = gazeSamples.slice().sort((x,y) => x-y);
            gazeBaseline = sorted[Math.floor(sorted.length / 2)];
        }
        return;
    }
    const delta = Math.abs(gazeSmoothed - gazeBaseline);
    const now = Date.now();
    if (delta < GAZE_OFFSET_THRESHOLD) {
        gazeDeviationSince = null;
        setGazeReminder(false);
        output.textContent = "Gaze: near calibrated center | deviation " + delta.toFixed(3);
        return;
    }
    if (gazeDeviationSince === null) gazeDeviationSince = now;
    const duration = (now - gazeDeviationSince) / 1000;
    output.textContent = "Gaze: horizontal deviation " + delta.toFixed(3) +
        " for " + duration.toFixed(1) + "s (reminder at " + GAZE_REMINDER_SECONDS + "s)";
    if (duration >= GAZE_REMINDER_SECONDS &&
        now - lastGazeReminder >= GAZE_REMINDER_COOLDOWN_MS) {
        lastGazeReminder = now;
        gazeReminderUntil = now + 4000;
    }
    setGazeReminder(now < gazeReminderUntil);
}
function resetGazeObservation() {
    gazeSamples = [];
    gazeBaseline = null;
    gazeSmoothed = null;
    gazeDeviationSince = null;
    gazeReminderUntil = 0;
    lastGazeReminder = -GAZE_REMINDER_COOLDOWN_MS;
    setGazeReminder(false);
}

function analyzeBehaviorFrame() {
    if (!examStarted || terminated || !faceLandmarker) return;
    const video = document.getElementById("camera");
    if (video.readyState < 2) return;
    const nowMs = performance.now();
    const result = faceLandmarker.detectForVideo(video, nowMs);
    const faces = result.faceLandmarks || [];
    const now = Date.now();

    if (faces.length === 0) {
        gazeDeviationSince = null;
        setGazeReminder(false);
        lookingAwaySince = null;
        if (missingFaceSince === null) missingFaceSince = now;
        setLive("No face detected for " + Math.floor((now - missingFaceSince) / 1000) + "s (warning at 10s)", false);
        if (now - missingFaceSince >= BEHAVIOR_SECONDS * 1000) {
            behaviorWarning("No face was visible for more than 10 seconds.");
            missingFaceSince = now;
        }
        return;
    }
    missingFaceSince = null;

    if (faces.length > 1) {
        gazeDeviationSince = null;
        setGazeReminder(false);

        lookingAwaySince = null;
        setLive("More than one face detected", false);
        behaviorWarning("More than one face was detected. Please ensure you are alone in the camera view.");
        return;
    }

    // SOEMS gaze observation (non-enforcing): estimates iris position relative to eye corners.
    // Does not create warnings, locks, scores, or database events.
    observeGaze(faces[0]);
    const landmarks = faces[0];
    if (!landmarks[1] || !landmarks[234] || !landmarks[454]) return;
    const noseX = landmarks[1].x;
    const edgeA = landmarks[234].x;
    const edgeB = landmarks[454].x;
    const leftX = Math.min(edgeA, edgeB);
    const width = Math.abs(edgeB - edgeA);
    if (!width) return;
    const nosePosition = (noseX - leftX) / width;
    const lookingAway = nosePosition < 0.35 || nosePosition > 0.65;
    if (!lookingAway) {
        lookingAwaySince = null;
        setLive("Face detected, looking at the screen", true);
        return;
    }
    if (lookingAwaySince === null) lookingAwaySince = now;
    setLive("Looking away for " + Math.floor((now - lookingAwaySince) / 1000) + "s (warning at 10s)", false);
    if (now - lookingAwaySince >= BEHAVIOR_SECONDS * 1000) {
        behaviorWarning("Your head was turned away for more than 10 seconds. Please look toward the screen.");
        lookingAwaySince = now;
    }
}

async function startExam() {
    if (!faceVerified) {
        alert("Please complete face verification before starting the exam.");
        return;
    }
    const startBtn = document.getElementById("continueBtn");
    startBtn.disabled = true;
    try {
        if (!faceLandmarker) await startBehaviorMonitoring();
    } catch (error) {
        examStarted = false;
        startBtn.disabled = false;
        alert("The behavior monitoring model did not load. The exam has not started.");
        return;
    }

    // The server creates the attempt, fixes the deadline and returns the questions.
    let info = {};
    try {
        const response = await fetch("/api/attempt/start", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({exam_key: EXAM_KEY})
        });
        info = await response.json().catch(function () { return {}; });
        if (!response.ok || !info.ok) {
            if (info.state === "locked" || info.state === "completed") {
                window.location.href = "/exam/" + EXAM_KEY;
                return;
            }
            faceVerified = false;  // the face pass is single-use: verify again
            alert(info.message || "The exam could not be started. Please run the security check again.");
            return;
        }
    } catch (error) {
        startBtn.disabled = false;
        alert("Could not reach the server. Check your connection and press Start again.");
        return;
    }

    EXAM = info.exam;
    attemptId = info.attempt_id;
    warningCount = info.warning_count || 0;
    initialRemainingSeconds = info.remaining_seconds;
    document.getElementById("warningCounter").textContent = "Warnings: " + warningCount + " / 3";
    examStarted = true;
    examStartedAt = Date.now();
    document.body.classList.add("exam-live");
    initExam();
    document.getElementById("examArea").style.display = "block";
    window.scrollTo({top:document.getElementById("examArea").offsetTop - 20, behavior:"smooth"});
}

function showViolation(reason) {
    if (!examStarted || terminated || warningOpen) return;

    warningOpen = true;

    if (warningCount >= 3) {
        logEvent("terminated", "Exam terminated after the final warning. Last violation: " + reason, 4);
        terminateExam();
        return;
    }

    warningCount++;
    logEvent("warning", reason, warningCount);

    const overlay = document.getElementById("warningOverlay");
    const message = document.getElementById("warningMessage");
    const number = document.getElementById("warningNumber");
    const icon = document.getElementById("warningIcon");
    const counter = document.getElementById("warningCounter");

    counter.textContent = "Warnings: " + warningCount + " / 3";

    if (warningCount === 3) {
        icon.textContent = "🚨";
        number.textContent = "Warning 3 of 3 — LAST WARNING";
        number.style.background = "#fdecea";
        number.style.color = "#b42318";
        message.textContent = reason +
            " This is your final warning. Any further security violation " +
            "will terminate your examination.";
    } else {
        icon.textContent = "⚠️";
        number.textContent = "Warning " + warningCount + " of 3";
        number.style.background = "#fff4e5";
        number.style.color = "#9a5b00";
        message.textContent = reason +
            " Please remain on the examination page and do not use prohibited actions.";
    }

    overlay.style.display = "flex";
}

function closeWarning() {
    if (terminated) return;
    document.getElementById("warningOverlay").style.display = "none";
    warningOpen = false;
}

function terminateExam() {
    terminated = true;
    if (examTimer) window.clearInterval(examTimer);
    sendSubmission("terminated").catch(function (e) { console.error(e); });
    examStarted = false;
    warningOpen = true;

    if (cameraStream) {
        cameraStream.getTracks().forEach(track => track.stop());
    }
    if (behaviorTimer) window.clearInterval(behaviorTimer);
    if (faceLandmarker) { faceLandmarker.close(); faceLandmarker = null; }

    document.getElementById("warningOverlay").style.display = "none";
    document.getElementById("terminatedOverlay").style.display = "flex";
}

document.addEventListener("copy", function(event) {
    if (!examStarted) return;
    event.preventDefault();
    if (inAnswerBox(event)) {
        // Allowed: keep a private copy of the student's own answer text only.
        const ta = event.target;
        const selected = ta.value.substring(ta.selectionStart, ta.selectionEnd);
        if (selected) answerClipboard = selected;
        return;
    }
    showViolation("Copying text during the examination is not allowed.");
});

document.addEventListener("cut", function(event) {
    if (!examStarted) return;
    event.preventDefault();
    if (inAnswerBox(event)) {
        const ta = event.target;
        const selected = ta.value.substring(ta.selectionStart, ta.selectionEnd);
        if (selected) {
            answerClipboard = selected;
            ta.setRangeText("", ta.selectionStart, ta.selectionEnd, "end");
            ta.dispatchEvent(new Event("input"));
        }
        return;
    }
    showViolation("Cutting text during the examination is not allowed.");
});

document.addEventListener("paste", function(event) {
    if (!examStarted) return;
    event.preventDefault();
    if (inAnswerBox(event)) {
        // Allowed, but only text the student copied from an answer box in this exam.
        // Anything copied from outside (other websites, files) is ignored.
        const ta = event.target;
        if (answerClipboard) {
            ta.setRangeText(answerClipboard, ta.selectionStart, ta.selectionEnd, "end");
            ta.dispatchEvent(new Event("input"));
        }
        return;
    }
    showViolation("Pasting content during the examination is not allowed.");
});

document.addEventListener("contextmenu", function(event) {
    if (!examStarted) return;
    if (inAnswerBox(event)) return;
    event.preventDefault();
    showViolation("Right-clicking during the examination is not allowed.");
});

document.addEventListener("keydown", function(event) {
    if (!examStarted) return;

    const key = event.key.toLowerCase();

    const boxShortcut = inAnswerBox(event) && ["c","x","v","a"].includes(key);

    if (
        (event.ctrlKey || event.metaKey) &&
        ["c","x","v","a","f","p","s","u"].includes(key) &&
        !boxShortcut
    ) {
        event.preventDefault();
        showViolation("A prohibited keyboard shortcut was detected.");
        return;
    }

    if (
        key === "f12" ||
        (event.ctrlKey && event.shiftKey && ["i","j","c"].includes(key))
    ) {
        event.preventDefault();
        showViolation("A prohibited browser shortcut was detected.");
    }
});

document.addEventListener("visibilitychange", function() {
    if (!examStarted || terminated) return;

    if (document.hidden) {
        showViolation(
            "You left the examination page or switched to another window/tab."
        );
    }
});

window.addEventListener("blur", function() {
    if (!examStarted || terminated) return;

    showViolation("You clicked or moved outside the examination window.");
});

document.addEventListener("dragstart", function(event) {
    if (!examStarted) return;
    if (inAnswerBox(event)) return;
    event.preventDefault();
    showViolation("Dragging content during the examination is not allowed.");
});

document.addEventListener("selectstart", function(event) {
    if (!examStarted) return;
    if (inAnswerBox(event)) return;
    event.preventDefault();
});

window.addEventListener("beforeunload", () => {
    if (behaviorTimer) window.clearInterval(behaviorTimer);
    if (faceLandmarker) faceLandmarker.close();
    if (cameraStream) cameraStream.getTracks().forEach(track => track.stop());
});

const translateMeta = document.createElement("meta");
translateMeta.name = "google";
translateMeta.content = "notranslate";
document.head.appendChild(translateMeta);
document.documentElement.classList.add("notranslate");
</script>
"""

    scripts = scripts.replace("__EXAM_KEY__", exam_key)
    return page(title, content, scripts)


def exam_blocked_page(title, state):
    if state == "locked":
        icon, heading = "🔒", "Examination locked"
        msg = ("Your attempt at this examination was terminated after repeated security "
               "violations, so it cannot be opened again. If you believe this is a mistake, "
               "please contact your teacher.")
    else:
        icon, heading = "✓", "Examination already completed"
        msg = "Your answers for this examination have already been submitted. It cannot be taken again."
    content = navbar() + f"""
<main class="container">
    <div class="hero">
        <h1>{title}</h1>
    </div>
    <div class="card" style="text-align:center;">
        <div class="card-icon" style="margin:0 auto 16px;">{icon}</div>
        <h3>{heading}</h3>
        <p>{msg}</p>
        <a class="btn" href="/student/exams">Back to Examinations</a>
    </div>
</main>
"""
    return page(title, content)


@app.route("/exam/<exam_key>")
def exam_entry(exam_key):
    if session.get("role") != "student" or not session.get("user_id"):
        return redirect(url_for("student"))
    title = EXAM_TITLES.get(exam_key)
    if not title:
        return "Examination not found.", 404
    state, _attempt = ea.get_exam_state(get_db(), session["user_id"], exam_key)
    if state == "locked":
        return exam_blocked_page(title, state), 403
    if state == "completed":
        return exam_blocked_page(title, state)
    return exam_page(title, exam_key)


@app.route("/api/attempt/start", methods=["POST"])
def attempt_start_api():
    auth_error = require_student_json()
    if auth_error:
        return auth_error
    data = request.get_json(silent=True) or {}
    exam_key = str(data.get("exam_key", ""))
    if exam_key not in EXAM_TITLES:
        return jsonify({"ok": False, "message": "Unknown examination."}), 400
    try:
        conn = get_db()
        uid = session["user_id"]
        state, attempt = ea.get_exam_state(conn, uid, exam_key)
        if state == "locked":
            return jsonify({"ok": False, "state": "locked",
                            "message": "This examination is locked for your account."}), 403
        if state == "completed":
            return jsonify({"ok": False, "state": "completed",
                            "message": "This examination has already been completed."}), 403

        # Face-verification gate: a fresh pass is required, and it is single-use.
        verified_at = session.pop("face_verified_ts", None)
        if not verified_at or time.time() - verified_at > ea.FACE_VERIFY_TTL_SECONDS:
            return jsonify({"ok": False, "state": "face_required",
                            "message": "Face verification is required before the exam can start. Please run the security check again."}), 403

        resumed = state == "in_progress"
        if not resumed:
            attempt, created = ea.create_attempt(
                conn, uid, exam_key, SAMPLE_EXAM["duration_minutes"] * 60)
            resumed = not created
        log_behavior_event(conn, attempt, "resumed" if resumed else "started",
                           "Exam resumed after the page was reloaded." if resumed else "Exam started.")
        return jsonify({
            "ok": True,
            "attempt_id": attempt["id"],
            "resumed": resumed,
            "remaining_seconds": ea.remaining_seconds(attempt),
            "warning_count": attempt["warning_count"],
            "exam": SAMPLE_EXAM,
        })
    except Exception:
        app.logger.exception("Unable to start exam attempt")
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({"ok": False, "message": "The exam could not be started. Please try again."}), 500



# Teacher login

@app.route("/teacher", methods=["GET", "POST"])
def teacher():
    if request.method == "GET" and session.get("role") == "teacher" and session.get("user_id"):
        return redirect(url_for("teacher_dashboard"))
    error = ""
    status = 200
    if request.method == "POST":
        password = request.form.get("password", "")
        user, message, status = authenticate("teacher", request.form.get("username", ""), password)
        if user:
            start_session(user, "teacher", password)
            return after_login_redirect("teacher")
        error = '<div class="alert">%s</div>' % htmllib.escape(message)

    content = f"""
<div class="login-page">
    <section class="login-side">
        <div class="brand">
            <span class="logo">🛡️</span>
            Secure Exam Platform
        </div>
        <h1>Teacher Portal</h1>
        <p>
            Manage courses and examinations from one secure platform.
        </p>
        <ul class="security-list">
            <li>✓ Secure teacher authentication</li>
            <li>✓ Course management</li>
            <li>✓ Examination management</li>
        </ul>
    </section>

    <section class="login-area">
        <div class="login-card">
            <h2>Teacher Login</h2>
            <p class="sub">Enter your credentials to continue.</p>

            {error}

            <form method="POST">
                <label>Username</label>
                <input class="input" type="text" name="username"
                       placeholder="Enter your username" required>

                <label>Password</label>
                <div class="password-wrap">
                    <input class="input" id="teacherPassword"
                           type="password" name="password"
                           placeholder="Enter your password" required>
                    <button class="show-pass" type="button"
                            onclick="togglePassword('teacherPassword')">👁</button>
                </div>

                <button class="btn full" type="submit">Sign In</button>
            </form>

            <a class="back" href="/">← Back to role selection</a>
        </div>
    </section>
</div>

<script>
function togglePassword(id) {{
    const input = document.getElementById(id);
    input.type = input.type === "password" ? "text" : "password";
}}
</script>
"""
    return page("Teacher Login", content), status



@app.route("/teacher/dashboard")
def teacher_dashboard():
    if session.get("role") != "teacher" or not session.get("user_id"):
        return redirect(url_for("teacher"))
    content = """
<nav class="navbar">
    <a href="/teacher/dashboard" class="brand">
        <span class="logo">🛡️</span>
        Secure Exam Platform
    </a>
    <span>
        <a href="/teacher/change-password" style="font-weight:700;margin-right:18px;">🔑 Change Password</a>
        <a href="/logout" style="font-weight:700;">🚪 Logout</a>
    </span>
</nav>

<main class="container">
    <section class="hero">
        <span class="status">● Teacher account authenticated</span>
        <h1 style="margin-top:18px;">Teacher Dashboard</h1>
        <p>Manage your courses and examinations.</p>
    </section>

    <div class="grid">
        <div class="card">
            <div class="card-icon">📚</div>
            <h3>My Courses</h3>
            <p>View the courses assigned to you.</p>
            <a class="btn" href="/course/database">View Courses</a>
        </div>

        <div class="card">
            <div class="card-icon">📋</div>
            <h3>Behavior Reports</h3>
            <p>See suspicious behavior detected during exams, per student.</p>
            <a class="btn" href="/teacher/reports">View Reports</a>
        </div>

        <div class="card">
            <div class="card-icon">➕</div>
            <h3>Create Exam</h3>
            <p>Add an examination to the platform.</p>
            <button class="btn" onclick="alert('Exam creation module can be connected here.')">
                Add Exam
            </button>
        </div>
    </div>
</main>
"""
    return page("Teacher Dashboard", content)

BEHAVIOR_CLIENT_EVENTS = {"warning", "terminated"}  # 'started'/'submitted' are written by the server


@app.route("/api/behavior-event", methods=["POST"])
def behavior_event_api():
    auth_error = require_student_json()
    if auth_error:
        return auth_error
    data = request.get_json(silent=True) or {}
    etype = str(data.get("type", "warning"))[:30]
    if etype not in BEHAVIOR_CLIENT_EVENTS:
        return jsonify({"ok": False, "error": "Unsupported event type."}), 400
    reason = str(data.get("reason", ""))[:1000]
    try:
        conn = get_db()
        attempt = ea.get_attempt_for_user(conn, data.get("attempt_id"), session["user_id"])
        if not attempt:
            return jsonify({"ok": False, "error": "Unknown exam attempt."}), 404

        if attempt["status"] == ea.TERMINATED:
            if etype == "terminated":
                cursor = conn.cursor(buffered=True)
                cursor.execute(
                    "SELECT id FROM behavior_events WHERE attempt_id=%s AND event_type='terminated' LIMIT 1",
                    (attempt["id"],))
                already = cursor.fetchone()
                cursor.close()
                if not already:
                    log_behavior_event(conn, attempt, "terminated", reason, ea.MAX_WARNINGS + 1)
            return jsonify({"ok": True, "warning_count": attempt["warning_count"], "terminated": True})
        if attempt["status"] != ea.IN_PROGRESS:
            return jsonify({"ok": False, "error": "This attempt is already closed."}), 409

        if etype == "terminated":
            ea.terminate_attempt(conn, attempt)
            log_behavior_event(conn, attempt, "terminated", reason, ea.MAX_WARNINGS + 1)
            return jsonify({"ok": True, "warning_count": attempt["warning_count"], "terminated": True})

        count, terminated = ea.add_warning(conn, attempt)
        if terminated:
            log_behavior_event(conn, attempt, "terminated",
                               "Exam terminated after the final warning. Last violation: " + reason,
                               ea.MAX_WARNINGS + 1)
        else:
            log_behavior_event(conn, attempt, "warning", reason, count)
        return jsonify({"ok": True, "warning_count": count, "terminated": terminated})
    except Exception:
        app.logger.exception("Unable to save behavior event")
        try:
            get_db().rollback()
        except Exception:
            pass
        return jsonify({"ok": False, "error": "Could not record the event."}), 500


def format_minute(seconds):
    seconds = int(seconds or 0)
    return "%02d:%02d" % (seconds // 60, seconds % 60)


@app.route("/teacher/reports")
def teacher_reports():
    if session.get("role") != "teacher":
        return redirect(url_for("teacher"))

    from risk_analytics import summarize, split_attempts, WEIGHTS
    from collections import defaultdict, Counter
    conn = get_db()
    cursor = conn.cursor(buffered=True)
    cursor.execute(
        """SELECT id, exam_title, user_id, username, student_name, event_type,
                  reason, warning_number, elapsed_seconds, created_at
           FROM behavior_events ORDER BY exam_title, user_id, created_at, id"""
    )
    rows = cursor.fetchall()
    cursor.close()

    groups = defaultdict(list)
    for event_id, exam, uid, username, name, etype, reason, wnum, elapsed, created in rows:
        groups[(exam, uid, username, name)].append({
            "id": event_id, "event_type": etype, "reason": reason,
            "warning_number": wnum, "elapsed_seconds": elapsed,
            "created_at": created,
        })

    esc = htmllib.escape
    cards = []
    exam_summary = defaultdict(lambda: {"attempts": 0, "review": 0, "warnings": 0, "risks": []})
    for (exam, uid, username, name), events in groups.items():
        for attempt_number, attempt in enumerate(split_attempts(events), 1):
            stats = summarize(attempt)
            summary = exam_summary[exam]
            summary["attempts"] += 1
            summary["warnings"] += stats["warnings"]
            summary["risks"].append(stats["risk"])
            if stats["level"] != "Low": summary["review"] += 1
            color = {"High": "#b42318", "Moderate": "#9a5b00", "Low": "#067647"}[stats["level"]]
            count_text = ", ".join(
                f"{key.replace('_', ' ').title()}: {value}"
                for key, value in sorted(stats["counts"].items())
            ) or "No warnings logged"
            event_rows = []
            for event in attempt:
                label = event["event_type"].title()
                event_rows.append(
                    "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                        esc(format_minute(event["elapsed_seconds"])),
                        esc(label), esc(str(event["reason"]))))
            cards.append((stats["risk"],
                '<div class="card" style="margin:14px 0;">'
                '<h3>%s — %s (attempt %d)</h3>'
                '<p>Student index: <b>%s</b></p>'
                '<p><b style="color:%s">%s review priority</b> · Risk: <b>%d/100</b> · Trust: <b>%d/100</b> · Warnings: %d%s</p>'
                '<p>Detected event categories: %s</p>'
                '<div style="overflow-x:auto"><table style="width:100%%;border-collapse:collapse;" border="1" cellpadding="7">'
                '<tr><th>Elapsed time</th><th>Event</th><th>Reason</th></tr>%s</table></div></div>' % (
                    esc(exam), esc(str(name)), attempt_number, esc(str(username)),
                    color, stats["level"], stats["risk"], stats["trust"],
                    stats["warnings"], " · Terminated" if stats["terminated"] else "",
                    esc(count_text), "".join(event_rows))))

    summary_rows = []
    for exam, info in sorted(exam_summary.items()):
        avg = sum(info["risks"]) / len(info["risks"])
        summary_rows.append(
            "<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%.1f</td></tr>" % (
                esc(exam), info["attempts"], info["review"],
                info["warnings"], avg))
    overview = (
        '<div class="card"><h2>Examination overview</h2>'
        '<div style="overflow-x:auto"><table border="1" cellpadding="8" style="width:100%%;border-collapse:collapse">'
        '<tr><th>Exam</th><th>Logged attempts</th><th>Review suggested</th><th>Warnings</th><th>Average risk</th></tr>%s'
        '</table></div></div>' % "".join(summary_rows)
        if summary_rows else '<div class="card">No behavior events have been logged yet.</div>'
    )
    body = "".join(card for _, card in sorted(cards, key=lambda item: -item[0]))
    content = (
        '<nav class="navbar"><a href="/teacher/dashboard" class="brand">Secure Exam Platform</a>'
        '<a href="/logout">Logout</a></nav><main class="container">'
        '<section class="hero"><h1>Behavior Analysis &amp; Risk Dashboard</h1>'
        '<p>Review priorities based on recorded events, not evidence of cheating.</p></section>'
        '<div class="card"><p><b>Interpretation:</b> Risk is a provisional weighted warning index (0–100); '
        'Trust = 100 − Risk. These are not probabilities or verified measures of honesty. '
        'Low: 0–24; Moderate: 25–59; High: 60–100. '
        'Face absence +10, head turned +5, multiple faces +25, tab/window change +15, '
        'browser action +10, other warning +5. Termination sets a minimum risk of 80. '
        'Teachers must review events and context before taking action. '
        'Scores reflect only successfully logged events.</p></div>'
        + overview + '<h2 class="section-title">Student attempts — highest risk first</h2>' + body +
        '<p><a class="btn" href="/teacher/dashboard">Back to dashboard</a></p></main>'
    )
    return page("Behavior Analysis & Risk Dashboard", content)


# Student profile/settings

@app.route("/student/profile")
def student_profile():
    content = navbar() + """
<main class="container">
    <div class="hero">
        <h1>Student Profile</h1>
        <p>View your account information.</p>
    </div>

    <div class="card">
        <h3>Account Information</h3>
        <p><strong>Role:</strong> Student</p>
        <p><strong>Status:</strong> Active</p>
        <p>Student profile information will appear here.</p>
    </div>

    <a class="back" href="/student/dashboard">← Back to Dashboard</a>
</main>
"""
    return page("Student Profile", content)


@app.route("/student/settings")
def student_settings():
    content = navbar() + """
<main class="container">
    <div class="hero">
        <h1>Settings</h1>
        <p>Manage your platform preferences.</p>
    </div>

    <div class="card">
        <h3>Account Settings</h3>
        <p>Student settings will appear here.</p>
    </div>

    <a class="back" href="/student/dashboard">← Back to Dashboard</a>
</main>
"""
    return page("Settings", content)


def teacher_navbar():
    return """
<nav class="navbar">
    <a href="/teacher/dashboard" class="brand">
        <span class="logo">🛡️</span>
        Secure Exam Platform
    </a>
    <span>
        <a href="/teacher/change-password" style="font-weight:700;margin-right:18px;">🔑 Change Password</a>
        <a href="/logout" style="font-weight:700;">🚪 Logout</a>
    </span>
</nav>
"""


def change_password_page(role, message="", success=False):
    nav = navbar() if role == "student" else teacher_navbar()
    back = "/student/dashboard" if role == "student" else "/teacher/dashboard"
    notice = ""
    if session.get("must_change_password"):
        notice = '<div class="alert">You are using a default password. Please choose a new one to continue.</div>'
    if message:
        if success:
            notice += ('<div style="background:#e7f6ee;color:#067647;padding:12px 14px;border-radius:10px;'
                       'margin-bottom:14px;">%s</div>' % htmllib.escape(message))
        else:
            notice += '<div class="alert">%s</div>' % htmllib.escape(message)
    form = "" if success else f"""
        <form method="POST">
            <label>Current password</label>
            <input class="input" type="password" name="current_password" autocomplete="current-password" required>
            <label>New password (at least {MIN_PASSWORD_LENGTH} characters)</label>
            <input class="input" type="password" name="new_password" autocomplete="new-password" required>
            <label>Confirm new password</label>
            <input class="input" type="password" name="confirm_password" autocomplete="new-password" required>
            <button class="btn" type="submit" style="margin-top:14px;">Change Password</button>
        </form>"""
    content = nav + f"""
<main class="container">
    <div class="hero">
        <h1>Change Password</h1>
        <p>Update your account password.</p>
    </div>
    <div class="card">
        {notice}
        {form}
    </div>
    <a class="back" href="{back}">← Back to Dashboard</a>
</main>
"""
    return page("Change Password", content)


def handle_change_password(role):
    message, success, status = "", False, 200
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        uid = session["user_id"]
        key = ("password", uid)
        wait = LOGIN_LIMITER.blocked(key)
        if wait:
            message, status = "Too many incorrect attempts. Please try again in %s." % minutes_text(wait), 429
        else:
            conn = get_db()
            cursor = conn.cursor(buffered=True)
            cursor.execute("SELECT password FROM users WHERE id=%s AND role=%s", (uid, role))
            row = cursor.fetchone()
            cursor.close()
            matches = bool(row) and check_stored_password(row[0], current)[0]
            if not matches:
                LOGIN_LIMITER.fail(key)
                message, status = "Your current password is incorrect.", 400
            elif new != confirm:
                message, status = "The new passwords do not match.", 400
            elif len(new) < MIN_PASSWORD_LENGTH:
                message, status = "The new password must be at least %d characters long." % MIN_PASSWORD_LENGTH, 400
            elif new in WEAK_DEFAULT_PASSWORDS or new == current:
                message, status = "Please choose a password that is different from your current and default passwords.", 400
            else:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password=%s WHERE id=%s", (hash_password(new), uid))
                conn.commit()
                cursor.close()
                LOGIN_LIMITER.reset(key)
                session.pop("must_change_password", None)
                message, success = "Your password has been changed.", True
    return change_password_page(role, message, success), status


@app.route("/student/change-password", methods=["GET", "POST"])
def change_password():
    return handle_change_password("student")


@app.route("/teacher/change-password", methods=["GET", "POST"])
def teacher_change_password():
    if session.get("role") != "teacher" or not session.get("user_id"):
        return redirect(url_for("teacher"))
    return handle_change_password("teacher")


@app.route("/student/support")
def support():
    content = navbar() + """
<main class="container">
    <div class="hero">
        <h1>Support & Help</h1>
        <p>Need assistance with the examination platform?</p>
    </div>

    <div class="card">
        <h3>Getting Help</h3>
        <p>
            If you need help, please contact your instructor or system
            administrator.
        </p>
    </div>

    <a class="back" href="/student/dashboard">← Back to Dashboard</a>
</main>
"""
    return page("Support & Help", content)



# Logout

@app.route("/logout")
def logout():
    session.clear()
    return page(
        "Logged Out",
        """
<div class="login-page">
    <section class="login-side">
        <div class="brand">
            <span class="logo">🛡️</span>
            Secure Exam Platform
        </div>
        <h1>Session Ended</h1>
        <p>Your session has been logged out successfully.</p>
    </section>

    <section class="login-area">
        <div class="login-card" style="text-align:center;">
            <div class="card-icon" style="margin:0 auto 20px;">✓</div>
            <h2>You have been logged out</h2>
            <p class="sub">Thank you for using the Secure Exam Platform.</p>
            <a class="btn full" href="/">Return to Home</a>
        </div>
    </section>
</div>
"""
    )



# Run Flask

if __name__ == "__main__":
    # Debug mode exposes an interactive console; it is off unless you ask for it (development only).
    debug = os.environ.get("FLASK_DEBUG", "0") == "1" and not PRODUCTION
    app.run(host=os.environ.get("SOEMS_HOST", "127.0.0.1"),
            port=int(os.environ.get("SOEMS_PORT", "5000")),
            debug=debug)
