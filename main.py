from scans import user_clean
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
import logging
from logging.handlers import RotatingFileHandler
# Redis removed: using in-memory rate limiter only to keep dependencies minimal.
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash
import time
try:
    from scans.test import search_onion_links
except Exception:
    # Optional module — continue without it and warn
    search_onion_links = None
    print("Warning: scans.test.search_onion_links not available; related features will be disabled.")
import importlib
import subprocess
import json
import sys
import requests
import uuid
from datetime import datetime, timedelta
import re
from functools import wraps
try:
    from flask_session import Session
except Exception:
    Session = None

app = Flask(__name__)

# Session cookie defaults: keep SameSite=Lax for reasonable CSRF protection and
# allow JavaScript to read the cookie if needed (HttpOnly stays True).
# In production you should set SESSION_COOKIE_SECURE=True when using HTTPS.
app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
app.config.setdefault('SESSION_COOKIE_SECURE', False)

_DEBUG_CSRF = os.environ.get('DEBUG_CSRF', '0') in ('1', 'true', 'True')

# Optionally enable server-side sessions if flask-session is available.
if Session is not None:
    try:
        sess_dir = os.path.join(os.path.dirname(__file__), 'flask_session')
        os.makedirs(sess_dir, exist_ok=True)
        app.config['SESSION_TYPE'] = 'filesystem'
        app.config['SESSION_FILE_DIR'] = sess_dir
        app.config.setdefault('SESSION_PERMANENT', False)
        server_session = Session(app)
        app.logger.info('Flask-Session enabled (filesystem)')
    except Exception as e:
        app.logger.warning(f'Failed to enable Flask-Session: {e}; falling back to cookie sessions')
else:
    app.logger.info('Flask-Session not installed; using signed cookie sessions')

# Secret key handling: prefer environment variable, else persist a key in a
# file so restarts don't invalidate sessions during development. In
# production, set SECRET_KEY env var.
secret = os.environ.get("SECRET_KEY")
secret_file = os.path.join(os.path.dirname(__file__), ".secret_key")
secret_source = 'unknown'
if secret:
    app.secret_key = secret
    secret_source = 'env'
else:
    if os.path.exists(secret_file):
        try:
            # read as text if possible
            with open(secret_file, "r", encoding="utf-8") as sf:
                app.secret_key = sf.read()
            secret_source = 'file'
        except Exception:
            # Fallback to generated key
            app.secret_key = os.urandom(24)
            secret_source = 'generated'
            print("Warning: failed to read .secret_key file, using generated key")
    else:
        # Generate and persist a secret key for local/dev use to avoid
        # invalidating sessions on restart. Production should set SECRET_KEY.
        key = os.urandom(24)
        try:
            with open(secret_file, "wb") as sf:
                sf.write(key)
            app.secret_key = key
            secret_source = 'generated_persisted'
            print(f"Warning: SECRET_KEY not set. Generated and saved a key to {secret_file}. Set SECRET_KEY in production.")
        except Exception:
            app.secret_key = key
            secret_source = 'generated'
            print("Warning: SECRET_KEY not set and failed to persist a generated key; sessions will be ephemeral.")

# ---- Structured logging ----
logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(logs_dir, exist_ok=True)
log_path = os.path.join(logs_dir, 'app.log')
handler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
handler.setFormatter(formatter)
app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)
logging.getLogger('werkzeug').addHandler(handler)

# Log where the secret came from (env/file/generated) without printing the secret itself
try:
    secret_len = len(app.secret_key) if app.secret_key else 0
except Exception:
    # secret might be bytes-like
    try:
        secret_len = len(app.secret_key.decode('utf-8'))
    except Exception:
        secret_len = 0
app.logger.info(f"SECRET source={secret_source} secret_len={secret_len}")

# Redis support removed; the app uses an in-memory rate limiter.
redis_client = None


# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


# Expose csrf_token to templates so forms and JS can access it.
# Must be registered at import/setup time (not during a request).
@app.context_processor
def inject_csrf_token():
    return {"csrf_token": session.get('csrf_token', '')}

data = "main.db"
SCAN_RESULTS_DB = "scan_results.db"

# Rate limiting storage
request_counts = {}

def rate_limit(max_requests=5000, window_seconds=180):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" in session:
                user_id = session["user"]
            else:
                # Prefer X-Forwarded-For when behind a proxy, otherwise remote_addr
                user_id = request.headers.get('X-Forwarded-For', request.remote_addr)
                if user_id and ',' in user_id:
                    # Take the left-most (original client)
                    user_id = user_id.split(',')[0].strip()
            now = int(time.time())

            # In-memory rate limiting
            window_start = now - window_seconds
            existing = request_counts.get(user_id, [])
            cleaned = [req_time for req_time in existing if req_time > window_start]
            if len(cleaned) >= max_requests:
                return jsonify({"error": "Rate limit exceeded"}), 429
            cleaned.append(now)
            request_counts[user_id] = cleaned
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            flash("Please login first", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def validate_input(input_str, input_type):
    """Validate different types of input"""
    if not input_str or len(input_str) > 255:
        return False
        
    if input_type == "username":
        return bool(re.match(r'^[a-zA-Z0-9_-]{3,50}$', input_str))
    elif input_type == "email":
        return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_str))
    elif input_type == "phone":
        return bool(re.match(r'^\+?[1-9]\d{1,14}$', input_str))
    elif input_type == "url":
        # Accept http(s) URLs and plain domains
        return bool(re.match(r'^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$', input_str))
    elif input_type == "fullname":
        return bool(re.match(r'^[a-zA-Z\s]{2,100}$', input_str))
    
    return True

# Database setup
def get_db_connection():
    conn = sqlite3.connect(data)
    conn.row_factory = sqlite3.Row
    return conn

def get_scan_db_connection():
    conn = sqlite3.connect(SCAN_RESULTS_DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(data):
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

def init_scan_db():
    conn = get_scan_db_connection()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            results TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()
init_scan_db()

def cleanup_old_scans():
    conn = get_scan_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scan_results WHERE created_at < datetime('now', '-1 hour')")
    conn.commit()
    conn.close()

def store_scan_results(username, target, target_type, scan_type, results):
    scan_id = str(uuid.uuid4())
    conn = get_scan_db_connection()
    c = conn.cursor()
    # Cap results size to avoid storing extremely large payloads (trim if necessary)
    results_json = json.dumps(results)
    MAX_RESULT_BYTES = 200000  # ~200KB
    if len(results_json.encode('utf-8')) > MAX_RESULT_BYTES:
        # Trim sites list to keep most relevant info
        try:
            trimmed = results.copy()
            if isinstance(trimmed.get('sites'), list):
                trimmed['sites'] = trimmed['sites'][:100]
            results_json = json.dumps(trimmed)
        except Exception:
            results_json = json.dumps({"error": "results too large"})

    c.execute("""
        INSERT INTO scan_results (scan_id, username, target, target_type, scan_type, results)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_id, username, target, target_type, scan_type, results_json))
    conn.commit()
    conn.close()
    return scan_id


# Background pruner for request_counts to prevent unbounded growth. Runs
# every minute and removes entries older than the window (default 60s).
def _start_request_counts_pruner(interval_seconds=60, window_seconds=60):
    import threading

    def pruner():
        while True:
            now = time.time()
            window_start = now - window_seconds
            keys = list(request_counts.keys())
            for k in keys:
                cleaned = [t for t in request_counts.get(k, []) if t > window_start]
                if cleaned:
                    request_counts[k] = cleaned
                else:
                    request_counts.pop(k, None)
            time.sleep(interval_seconds)

    t = threading.Thread(target=pruner, daemon=True)
    t.start()


# Start the pruner at import time
_start_request_counts_pruner()

def get_scan_results(scan_id, username):
    conn = get_scan_db_connection()
    c = conn.cursor()
    c.execute("SELECT results FROM scan_results WHERE scan_id = ? AND username = ?", (scan_id, username))
    row = c.fetchone()
    conn.close()
    if row:
        return json.loads(row[0])
    return None

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=60)
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not validate_input(username, "username") or not password:
            flash("Invalid input", "danger")
            return redirect(url_for("login"))

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[0], password):
            session["user"] = username
            session.permanent = False  # Session expires when browser closes
            # Generate CSRF token for the session
            session['csrf_token'] = uuid.uuid4().hex
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.before_request
def _csrf_protect():
    # Only enforce CSRF for state-changing methods
    # Ensure the session always has a csrf_token for templates and JS
    if 'csrf_token' not in session:
        session['csrf_token'] = uuid.uuid4().hex

    if request.method in ('POST', 'PUT', 'DELETE'):
        # Allow login and register to proceed (they generate tokens)
        if request.endpoint in ('login', 'register'):
            return None

        token = session.get('csrf_token')
        if not token:
            abort(400, 'Missing CSRF token in session')

        # Accept token in header or form
        header_token = request.headers.get('X-CSRF-Token')
        form_token = request.form.get('csrf_token') if request.form else None
        if _DEBUG_CSRF:
            # For debugging only: log presence and length, not the full token
            app.logger.info(f"CSRF debug: session_has_token={bool(token)}, session_len={len(token) if token else 0}, header_present={bool(header_token)}, header_len={len(header_token) if header_token else 0}, form_present={bool(form_token)}, form_len={len(form_token) if form_token else 0}")
        if header_token == token or form_token == token:
            return None
        abort(400, 'Invalid CSRF token')


    # no-op for other methods


@app.route('/_diag')
def _diag():
    # Return minimal session diagnostics. Restrict to localhost or when debug enabled.
    remote = request.remote_addr
    if not _DEBUG_CSRF and remote not in ('127.0.0.1', '::1'):
        abort(404)
    s = session
    return jsonify({
        'remote': remote,
        'session_has_csrf': bool(s.get('csrf_token')),
        'session_csrf_len': len(s.get('csrf_token') or ''),
        'session_user': bool(s.get('user'))
    })

@app.route("/register", methods=["GET", "POST"])
@rate_limit(max_requests=3, window_seconds=300)
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not validate_input(username, "username") or len(password) < 8:
            flash("Username must be 3-50 alphanumeric characters and password at least 8 characters", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            # Generate CSRF token for the new session (user should login next)
            session['csrf_token'] = uuid.uuid4().hex
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists", "danger")
            return redirect(url_for("register"))
        except Exception:
            flash("Registration failed", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/dashboard")
@login_required
def dashboard():
    recent_scan = None
    if 'last_scan_id' in session:
        recent_scan = get_scan_results(session['last_scan_id'], session["user"])
    
    return render_template("dashboard.html", 
                         username=session["user"],
                         recent_scan=recent_scan)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route('/scan', methods=['POST'])
@login_required
@rate_limit(max_requests=5, window_seconds=120)
def scan():
    target = request.form.get('target', '').strip()
    target_type = request.form.get('target_type', '')
    scan_type = request.form.get('scan_type', '')

    # Validate inputs
    if not target or not target_type or not scan_type:
        flash("Missing required fields", "danger")
        return redirect(url_for("dashboard"))
    
    if not validate_input(target, target_type):
        flash("Invalid input format", "danger")
        return redirect(url_for("dashboard"))

    country_code = request.form.get('country_code', '+1')

    results = {}
    
    try:
        # Your existing scan logic here (truncated for brevity)
        if target_type == "username" and scan_type == "clean":
            raw_results = user_clean.run(target)
            sites = []
            for r in raw_results["sites"]:
                sites.append({
                    "site": r["site"],
                    "url": r["url"],
                    "found": r.get("found", False)
                })
            results = {
                "target": target,
                "status": "completed",
                "sites": sites
            }
        # ... rest of your scan logic
        
        # Store results
        scan_id = store_scan_results(session["user"], target, target_type, scan_type, results)
        session['last_scan_id'] = scan_id
        cleanup_old_scans()

        # ADD THIS RETURN STATEMENT
        return render_template(
            "dashboard.html",
            username=session["user"],
            target=target,
            results=results,
            scan_id=scan_id
        )

    except Exception as e:
        # Don't expose internal errors to user
        app.logger.error(f"Scan error: {str(e)}")
        flash("Scan failed due to an internal error", "danger")
        # Safely render dashboard with empty/default values
        return render_template(
            "dashboard.html",
            username=session.get("user", "unknown"),
            target=target or "",
            results=results or {},
            scan_id=None,
            recent_scan=None
        )


@app.route("/ask_ai", methods=["POST"])
@login_required
@rate_limit(max_requests=10, window_seconds=300)
def ask_ai():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    question = data.get("question", "").strip()

    if not question or len(question) > 1000:
        return jsonify({"error": "Invalid question"}), 400

    if "last_scan_id" not in session:
        return jsonify({"error": "No scan results found"}), 400

    scan_results = get_scan_results(session['last_scan_id'], session["user"])
    if not scan_results:
        return jsonify({"error": "Scan results not found"}), 400

    # Lightweight local 'AI' responder (no external network required).
    # This is a deterministic summarizer that answers common questions
    # about the most recent scan results. If you want a full LLM
    # integration later, we can add an OpenAI/other provider path that
    # uses an API key stored in an environment variable.

    def _summarize_scan(scan):
        if not scan:
            return "No scan results available."
        summary = scan.get('summary', {})
        parts = []
        parts.append(f"Target: {scan.get('target', 'unknown')}")
        parts.append(f"Status: {scan.get('status', 'unknown')}")
        if summary:
            parts.append(f"Found on {summary.get('found_sites', 0)} out of {summary.get('total_sites', 0)} sites")
            parts.append(f"Scan time: {summary.get('scan_time_seconds', 'N/A')}s")
        return " | ".join(parts)

    def _list_found_sites(scan, limit=20):
        if not scan:
            return "No scan results available."
        sites = [s for s in scan.get('sites', []) if s.get('found')]
        if not sites:
            return "No sites were found for this target."
        lines = [f"{s.get('site')}: {s.get('url')}" for s in sites[:limit]]
        return "\n".join(lines)

    q = question.lower()
    answer = "I'm not sure how to answer that. Try asking for a 'summary' or 'where was it found'."

    if 'summary' in q or 'overview' in q or 'status' in q:
        answer = _summarize_scan(scan_results)
    elif 'where' in q or 'found' in q or 'sites' in q or 'which' in q:
        answer = _list_found_sites(scan_results, limit=50)
    elif 'top' in q or 'most' in q:
        # Show top-found sites by order
        answer = _list_found_sites(scan_results, limit=10)
    else:
        # Default to a short summary followed by found sites
        answer = _summarize_scan(scan_results) + "\n\nFound sites:\n" + _list_found_sites(scan_results, limit=10)

    return jsonify({"answer": answer}), 200

@app.route('/report')
@login_required
def report():
    if "last_scan_id" not in session:
        flash("No recent scan found", "warning")
        return redirect(url_for("dashboard"))
    
    results = get_scan_results(session['last_scan_id'], session["user"])
    if not results:
        flash("Scan results not found", "warning")
        return redirect(url_for("dashboard"))

    return render_template("report.html", 
                         target=results.get('target', ''),
                         results=results, 
                         username=session["user"])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(host="0.0.0.0", port=port)


