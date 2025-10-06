from scans import user_clean
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash
import time
from scans.test import search_onion_links
import importlib
import subprocess
import json
import sys
import requests
import uuid
from datetime import datetime, timedelta
import re
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

data = "main.db"
SCAN_RESULTS_DB = "scan_results.db"

# Rate limiting storage
request_counts = {}

def rate_limit(max_requests=10, window_seconds=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" in session:
                user_id = session["user"]
            else:
                user_id = request.remote_addr
                
            now = time.time()
            window_start = now - window_seconds
            
            # Clean old entries
            request_counts[user_id] = [req_time for req_time in request_counts.get(user_id, []) if req_time > window_start]
            
            # Check rate limit
            if len(request_counts[user_id]) >= max_requests:
                return jsonify({"error": "Rate limit exceeded"}), 429
                
            request_counts[user_id].append(now)
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
        return bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_str))
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
    c.execute("""
        INSERT INTO scan_results (scan_id, username, target, target_type, scan_type, results)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_id, username, target, target_type, scan_type, json.dumps(results)))
    conn.commit()
    conn.close()
    return scan_id

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
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

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

    except Exception as e:
        # Don't expose internal errors to user
        app.logger.error(f"Scan error: {str(e)}")
        flash("Scan failed due to an internal error", "danger")
        return redirect(url_for("dashboard"))

    return render_template(
        "dashboard.html",
        username=session["user"],
        target=target,
        results=results,
        scan_id=scan_id
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

    # Your existing AI logic here
    # ...

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