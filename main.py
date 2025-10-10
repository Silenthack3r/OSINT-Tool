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
import threading
background_scans = {}
from openai import OpenAI
OPENROUTER_API_KEY = os.environ.get("API_KEY")
client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key=OPENROUTER_API_KEY,
)

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

def rate_limit(max_requests=1000, window_seconds=180):
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

    # Convert only serializable types
    try:
        results_json = json.dumps(results or {})
    except TypeError:
        results_json = json.dumps({"error": "results not serializable"})

    MAX_RESULT_BYTES = 200000
    if len(results_json.encode('utf-8')) > MAX_RESULT_BYTES:
        trimmed = results.copy()
        if isinstance(trimmed.get('sites'), list):
            trimmed['sites'] = trimmed['sites'][:100]
        results_json = json.dumps(trimmed)

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
@rate_limit(max_requests=10, window_seconds=300)
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
            conn.close()  # FIXED: was s.close()
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

@app.route("/scan", methods=['POST'])
@login_required
@rate_limit(max_requests=100, window_seconds=60)
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
        # --- USERNAME CLEAN SCAN ---
        if target_type == "username" and scan_type == "clean":
            try:
                raw_results = user_clean.run(target)

                # normalize into ask_ai format
                sites = []
                for r in raw_results.get("sites", []):
                    sites.append({
                        "site": str(r.get("site", "")),
                        "url": str(r.get("url", "")),
                        "found": bool(r.get("found", False))
                    })

                results = {
                    "target": str(target),
                    "status": "completed",
                    "sites": sites
                }
            except Exception as e:
                results = {
                    "target": str(target),
                    "status": "error", 
                    "sites": [],
                    "error": f"Username search failed: {str(e)}"
                }

        # --- FULL NAME OSINT SCAN ---
        elif target_type == "fullname" and scan_type == "clean":
            try:
                from scans.fullname import run as fullname_run
                raw_results = fullname_run(target)
                
                # Transform the fullname results to match the expected structure
                results = {
                    "target": str(target),
                    "status": raw_results.get("status", "completed"),
                    "sites": [],
                    "error": raw_results.get("error")
                }
                
                # Convert fullname-specific results to the standard sites format
                if "sites" in raw_results:
                    results["sites"] = raw_results["sites"]
                    
                # Add summary information
                if "summary" in raw_results:
                    results["summary"] = raw_results["summary"]
                    
            except Exception as e:
                results = {
                    "target": str(target),
                    "status": "error", 
                    "sites": [],
                    "error": f"Full name search failed: {str(e)}"
                }

        # --- EMAIL OSINT SCAN ---
        elif target_type == "email" and scan_type == "clean":
            try:
                from scans.email import run as email_run
                raw_results = email_run(target)
                
                # Use the raw results directly since they already have the correct structure
                results = {
                    "target": str(target),
                    "status": raw_results.get("status", "completed"),
                    "sites": raw_results.get("sites", []),
                    "breaches": raw_results.get("breaches", []),
                    "social_profiles": raw_results.get("social_profiles", []),
                    "technical_info": raw_results.get("technical_info", {}),
                    "domain_info": raw_results.get("domain_info", {}),
                    "leaked_data": raw_results.get("leaked_data", []),
                    "threat_intel": raw_results.get("threat_intel", []),
                    "reputation_data": raw_results.get("reputation_data", []),
                    "error": raw_results.get("error")
                }
                
                # Add summary information
                if "summary" in raw_results:
                    results["summary"] = raw_results["summary"]
                    
            except Exception as e:
                app.logger.error(f"Email scan error: {str(e)}", exc_info=True)
                results = {
                    "target": str(target),
                    "status": "error",
                    "sites": [],
                    "breaches": [],
                    "social_profiles": [],
                    "technical_info": {},
                    "domain_info": {},
                    "leaked_data": [],
                    "threat_intel": [],
                    "reputation_data": [],
                    "error": f"Email search failed: {str(e)}"
                }

        # --- PHONE NUMBER OSINT SCAN ---
        elif target_type == "phone" and scan_type == "clean":
            try:
                print(f"[PHONE SCAN] Starting scan for: {target} with country: {country_code}")
                
                from scans.phone import run as phone_run
                raw_results = phone_run(target, country_code)
                
                print(f"[PHONE SCAN] Raw results received: {raw_results.get('status')}")
                
                # Simple transformation - just pass through the main structure
                results = {
                    "target": str(target),
                    "status": raw_results.get("status", "completed"),
                    "sites": raw_results.get("sites", []),
                    "carrier_info": raw_results.get("carrier_info", {}),
                    "location_info": raw_results.get("location_info", {}),
                    "social_profiles": raw_results.get("social_profiles", []),
                    "technical_info": raw_results.get("technical_info", {}),
                    "summary": raw_results.get("summary", {}),
                    "error": raw_results.get("error")
                }
                
                print(f"[PHONE SCAN] Final results: {len(results['sites'])} sites")
                    
            except Exception as e:
                print(f"[PHONE SCAN] ERROR: {str(e)}")
                results = {
                    "target": str(target),
                    "status": "error",
                    "sites": [],
                    "carrier_info": {},
                    "location_info": {},
                    "social_profiles": [],
                    "technical_info": {},
                    "error": f"Phone search failed: {str(e)}"
                }

        # --- DARK WEB SCAN (Username/Email) ---
        elif target_type in ["username", "email"] and scan_type == "dark":
            try:
                from scans.darkuser import run as darkuser_run
                raw_results = darkuser_run(target, target_type)
                
                # Transform the dark web results to match the expected structure
                results = {
                    "target": str(target),
                    "target_type": target_type,
                    "status": raw_results.get("status", "completed"),
                    "darkweb_results": [],
                    "leaks_found": [],
                    "breach_data": [],
                    "onion_service_results": {},
                    "error": raw_results.get("error")
                }
                
                # Convert dark web specific results
                if "darkweb_results" in raw_results:
                    results["darkweb_results"] = raw_results["darkweb_results"]
                    
                # Add leaks found if available
                if "leaks_found" in raw_results:
                    results["leaks_found"] = raw_results["leaks_found"]
                    
                # Add breach data if available
                if "breach_data" in raw_results:
                    results["breach_data"] = raw_results["breach_data"]
                    
                # Add onion service results if available
                if "onion_service_results" in raw_results:
                    results["onion_service_results"] = raw_results["onion_service_results"]
                    
                # Add summary information
                if "summary" in raw_results:
                    results["summary"] = raw_results["summary"]
                    
            except Exception as e:
                results = {
                    "target": str(target),
                    "target_type": target_type,
                    "status": "error",
                    "darkweb_results": [],
                    "leaks_found": [],
                    "breach_data": [],
                    "onion_service_results": {},
                    "summary": {},
                    "error": f"Dark web search failed: {str(e)}"
                }

        # --- ONION SCAN ---
        elif target_type == "onion" and scan_type == "search":
            try:
                if search_onion_links:
                    raw_results = search_onion_links(target)
                    
                    # Clean the results
                    def clean_json(obj):
                        if obj is None:
                            return None
                        elif hasattr(obj, '__class__') and 'Undefined' in str(obj.__class__):
                            return None
                        elif isinstance(obj, dict):
                            return {k: clean_json(v) for k, v in obj.items() if v is not None}
                        elif isinstance(obj, list):
                            return [clean_json(item) for item in obj if item is not None]
                        else:
                            return obj
                    
                    results = clean_json(raw_results)
                    
                    # Ensure basic structure
                    if not isinstance(results, dict):
                        results = {}
                    if 'sites' not in results:
                        results['sites'] = []
                    if 'target' not in results:
                        results['target'] = str(target)
                    if 'status' not in results:
                        results['status'] = 'completed'
                else:
                    results = {
                        "target": str(target),
                        "status": "error",
                        "sites": [],
                        "error": "Onion search module not available"
                    }
                    
            except Exception as e:
                results = {
                    "target": str(target),
                    "status": "error",
                    "sites": [],
                    "error": f"Onion search failed: {str(e)}"
                }

        # --- OTHER SCAN TYPES ---
        else:
            try:
                module_name = f"scans.{scan_type}"
                scan_module = importlib.import_module(module_name)
                if hasattr(scan_module, "run"):
                    raw_results = scan_module.run(target)
                    
                    # Clean the results
                    def clean_json(obj):
                        if obj is None:
                            return None
                        elif hasattr(obj, '__class__') and 'Undefined' in str(obj.__class__):
                            return None
                        elif isinstance(obj, dict):
                            return {k: clean_json(v) for k, v in obj.items() if v is not None}
                        elif isinstance(obj, list):
                            return [clean_json(item) for item in obj if item is not None]
                        else:
                            return obj
                    
                    results = clean_json(raw_results)
                    
                    # Ensure basic structure
                    if not isinstance(results, dict):
                        results = {}
                    if 'sites' not in results:
                        results['sites'] = []
                    if 'target' not in results:
                        results['target'] = str(target)
                    if 'status' not in results:
                        results['status'] = 'completed'
                        
                else:
                    results = {"error": f"No 'run' function found in {module_name}"}
            except Exception as e:
                results = {"error": str(e)}

        # Store results
        scan_id = store_scan_results(session["user"], target, target_type, scan_type, results)
        session['last_scan_id'] = scan_id
        cleanup_old_scans()

        # Ensure results are always a serializable dict
        safe_results = results if isinstance(results, dict) else {}

        return render_template(
            "dashboard.html",
            username=session.get("user", "unknown"),
            target=target or "",
            results=safe_results,
            scan_id=scan_id,
            recent_scan=safe_results
        )

    except Exception as e:
        app.logger.error(f"Scan error: {str(e)}", exc_info=True)
        session.pop('csrf_token', None)  # Reset CSRF token to avoid serialization issues
        session['csrf_token'] = uuid.uuid4().hex
        flash("Scan failed — CSRF token refreshed. Try again.", "danger")
        return render_template(
            "dashboard.html",
            username=session.get("user", "unknown"),
            target=target or "",
            results=results or {},
            scan_id=None,
            recent_scan=None
        )

@app.route("/ask_ai", methods=["POST"])
def ask_ai():
    try:
        print("=== AI ENDPOINT CALLED ===")
        
        # Get JSON data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data received"}), 400
            
        question = data.get("question", "").strip()
        print(f"Question: {question}")
        
        if not question:
            return jsonify({"error": "No question provided"}), 400

        # Check if user has scan results
        if "last_scan_id" not in session:
            return jsonify({"error": "No scan results found. Please run a scan first."}), 400

        # Get scan results from database
        scan_id = session['last_scan_id']
        username = session["user"]
        
        scan_results = get_scan_results(scan_id, username)
        if not scan_results:
            return jsonify({"error": "Scan results not found or expired. Please run a new scan."}), 400

        # Build context from scan results
        context = f"""
Scan Results Summary:
- Target: {scan_results.get('target', 'N/A')}
- Status: {scan_results.get('status', 'N/A')}
- Sites Checked: {len(scan_results.get('sites', []))}
"""

        sites = scan_results.get('sites', [])
        if sites:
            context += "\nSite Results:\n"
            for i, site in enumerate(sites[:10], 1):
                site_name = site.get('site', f'Site {i}')
                found = "FOUND" if site.get('found') else "NOT FOUND"
                url = site.get('url', 'No URL')
                context += f"{i}. {site_name}: {found} - {url}\n"

        # Prepare messages for AI
        messages = [
            {
                "role": "system", 
                "content": "You are a cybersecurity assistant. Analyze the scan results and provide helpful, professional answers. Keep responses concise but informative."
            },
            {
                "role": "user", 
                "content": f"{context}\n\nQuestion: {question}\n\nPlease provide a helpful answer based on the scan results above:"
            }
        ]

        print("Sending request to AI...")
        
        # Try multiple WORKING models
        models_to_try = [
            "meta-llama/llama-3.3-70b-instruct:free",  # Newer Llama model
            "meta-llama/llama-3.1-8b-instruct:free",   # Smaller but reliable
            "qwen/qwen-2.5-coder-32b-instruct:free",   # Good coding/analysis
            "microsoft/wizardlm-2-8x22b:free"          # Another good option
        ]
        
        last_error = None
        
        for model in models_to_try:
            try:
                print(f"Trying model: {model}")
                completion = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=500,
                    temperature=0.7,
                    extra_headers={
                        "HTTP-Referer": "http://bnk-osint-tool.onrender.com",
                        "X-Title": "CyberRecon Dashboard"
                    }
                )
                
                # Check if response is valid
                if (completion and 
                    hasattr(completion, 'choices') and 
                    completion.choices and 
                    len(completion.choices) > 0 and
                    hasattr(completion.choices[0], 'message') and
                    completion.choices[0].message and
                    hasattr(completion.choices[0].message, 'content') and
                    completion.choices[0].message.content):
                    
                    answer = completion.choices[0].message.content
                    print(f"Success with model: {model}")
                    print(f"Response: {answer[:100]}...")
                    
                    # Store in session
                    if "ai_history" not in session:
                        session["ai_history"] = []
                    
                    session["ai_history"] = session["ai_history"][-2:] + [{
                        "question": question, 
                        "answer": answer,
                        "timestamp": datetime.now().isoformat(),
                        "model": model
                    }]
                    
                    session.modified = True

                    return jsonify({
                        "answer": answer,
                        "scan_target": scan_results.get('target'),
                        "sites_analyzed": len(sites),
                        "model": model
                    })
                else:
                    raise Exception("Invalid response structure from AI")
                
            except Exception as e:
                last_error = e
                print(f"Model {model} failed: {str(e)}")
                continue  # Try next model
        
        # If all models failed
        error_msg = f"All AI models are currently unavailable. Please try again in a few minutes. Last error: {str(last_error)}"
        return jsonify({"error": error_msg}), 500

    except Exception as e:
        print(f"AI ROUTE ERROR: {str(e)}")
        return jsonify({"error": f"AI service error: {str(e)}"}), 500
def test_ai():
    """Test if AI endpoint is accessible"""
    return jsonify({
        "status": "AI endpoint is working",
        "session_user": session.get("user", "No user"),
        "last_scan_id": session.get("last_scan_id", "No scan ID")
    })

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