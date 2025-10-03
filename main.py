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

app = Flask(__name__)
app.secret_key = "supersecretkey" 


port = int(os.environ.get("PORT", 5000))


data = "main.db"
SCAN_RESULTS_DB = "scan_results.db"

# Database setup using sqlite3 :)
def init_db():
    if not os.path.exists(data):
        conn = sqlite3.connect(data)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

# Initialize scan results database
def init_scan_db():
    conn = sqlite3.connect(SCAN_RESULTS_DB)
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

# Clean up old scan results (older than 1 hour)
def cleanup_old_scans():
    conn = sqlite3.connect(SCAN_RESULTS_DB)
    c = conn.cursor()
    c.execute("DELETE FROM scan_results WHERE created_at < datetime('now', '-1 hour')")
    conn.commit()
    conn.close()

# Store scan results in database
def store_scan_results(username, target, target_type, scan_type, results):
    scan_id = str(uuid.uuid4())
    conn = sqlite3.connect(SCAN_RESULTS_DB)
    c = conn.cursor()
    c.execute("""
        INSERT INTO scan_results (scan_id, username, target, target_type, scan_type, results)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_id, username, target, target_type, scan_type, json.dumps(results)))
    conn.commit()
    conn.close()
    return scan_id

# Get scan results from database
def get_scan_results(scan_id, username):
    conn = sqlite3.connect(SCAN_RESULTS_DB)
    c = conn.cursor()
    c.execute("SELECT results FROM scan_results WHERE scan_id = ? AND username = ?", (scan_id, username))
    row = c.fetchone()
    conn.close()
    if row:
        return json.loads(row[0])
    return None

# Links
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(data)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[0], password):
            session["user"] = username
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        try:
            conn = sqlite3.connect(data)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))
    
    # Get recent scan results for display
    recent_scan = None
    if 'last_scan_id' in session:
        recent_scan = get_scan_results(session['last_scan_id'], session["user"])
    
    return render_template("dashboard.html", 
                         username=session["user"],
                         recent_scan=recent_scan)

@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("last_scan_id", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route('/scan', methods=['POST'])
def scan():
    if "user" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    target = request.form['target']
    target_type = request.form['target_type']
    scan_type = request.form['scan_type']

    # Get country code for phone scans
    country_code = request.form.get('country_code', '+1')

    results = {}

    # --- USERNAME CLEAN SCAN ---
    if target_type == "username" and scan_type == "clean":
        try:
            raw_results = user_clean.run(target)

            # normalize into ask_ai format
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
        except Exception as e:
            results = {
                "target": target,
                "status": "error", 
                "sites": [],
                "error": f"Username search failed: {str(e)}"
            }

    # --- FULL NAME OSINT SCAN ---
    elif target_type == "fullname" and scan_type == "clean":
        try:
            from scans.fullname import run as fullname_run
            results = fullname_run(target)
        except Exception as e:
            results = {
                "target": target,
                "status": "error", 
                "sites": [],
                "error": f"Full name search failed: {str(e)}"
            }

    # --- EMAIL OSINT SCAN ---
    elif target_type == "email" and scan_type == "clean":
        try:
            from scans.email import run as email_run
            results = email_run(target)
        except Exception as e:
            results = {
                "target": target,
                "status": "error",
                "sites": [],
                "breaches": [],
                "social_profiles": [],
                "technical_info": {},
                "error": f"Email search failed: {str(e)}"
            }

    # --- PHONE NUMBER OSINT SCAN ---
    elif target_type == "phone" and scan_type == "clean":
        try:
            from scans.phone import run as phone_run
            results = phone_run(target, country_code)
        except Exception as e:
            results = {
                "target": target,
                "status": "error",
                "sites": [],
                "carrier_info": {},
                "location_info": {},
                "social_profiles": [],
                "breach_data": [],
                "technical_info": {},
                "threat_intel": [],
                "number_analysis": {},
                "error": f"Phone search failed: {str(e)}"
            }

    # --- DARK WEB SCAN (Username/Email) ---
    elif target_type in ["username", "email"] and scan_type == "dark":
        try:
            from scans.darkuser import run as darkuser_run
            results = darkuser_run(target, target_type)
        except Exception as e:
            results = {
                "target": target,
                "target_type": target_type,
                "status": "error",
                "darkweb_results": [],
                "leaks_found": [],
                "breach_data": [],
                "onion_service_results": {},
                "summary": {},
                "error": f"Dark web search failed: {str(e)}"
            }

    # --- FUTURE EXPANSIONS ---
    elif target_type == "onion" and scan_type == "search":
        try:
            results = search_onion_links(target)
        except Exception as e:
            results = {
                "target": target,
                "status": "error",
                "sites": [],
                "error": f"Onion search failed: {str(e)}"
            }

    else:
        try:
            module_name = f"scans.{scan_type}"
            scan_module = importlib.import_module(module_name)
            if hasattr(scan_module, "run"):
                results = scan_module.run(target)
            else:
                results = {"error": f"No 'run' function found in {module_name}"}
        except Exception as e:
            results = {"error": str(e)}

    # Store results in database
    scan_id = store_scan_results(session["user"], target, target_type, scan_type, results)
    
    # Store only the scan ID in session (small)
    session['last_scan_id'] = scan_id

    # Clean up old scans periodically
    cleanup_old_scans()

    # Render dashboard with results
    return render_template(
        "dashboard.html",
        username=session["user"],
        target=target,
        results=results,
        scan_id=scan_id
    )
from openai import OpenAI
from flask import request, jsonify, session

# Put your OpenRouter API key here
OPENROUTER_API_KEY = "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"

# OpenAI-compatible client for OpenRouter
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY
)

@app.route("/ask_ai", methods=["POST"])
def ask_ai():
    # Ensure content-type is application/json
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    question = data.get("question", "").strip()

    if not question:
        return jsonify({"error": "No question provided"}), 400

    # Get scan results from database using scan ID
    if "last_scan_id" not in session:
        return jsonify({"error": "No scan results found. Run a scan first."}), 400

    scan_results = get_scan_results(session['last_scan_id'], session["user"])
    if not scan_results:
        return jsonify({"error": "Scan results not found or expired."}), 400

    sites = scan_results.get("sites", [])

    # Convert scan results into readable text for AI
    scan_text_lines = []
    for site in sites:
        # Fallback to empty dict if site is malformed
        site = site or {}
        site_name = site.get("site", "Unknown Site")
        url = site.get("url", "")
        found = "Found" if site.get("found") else "Not Found"
        scan_text_lines.append(f"{site_name}: {found} ({url})")

    scan_text = f"Target: {scan_results.get('target', '')}\nStatus: {scan_results.get('status', '')}\n" + "\n".join(scan_text_lines)

    messages = [
        {"role": "system", "content": "You are a helpful assistant. Use the scan results to answer questions accurately and short way and proffesional as possible and try to answer questions as much as you can."},
        {"role": "user", "content": f"Scan Results:\n{scan_text}\nQuestion: {question}"}
    ]

    try:
        completion = client.chat.completions.create(
            model="x-ai/grok-4-fast:free",
            messages=messages,
            extra_headers={
                "HTTP-Referer": "http://localhost:5000",
                "X-Title": "CyberRecon Dashboard"
            }
        )

        # Access the message safely
        answer = completion.choices[0].message.content
        # Store AI history in database if needed, or keep minimal in session
        if "ai_history" not in session:
            session["ai_history"] = []
        # Keep only last 5 questions to avoid session bloat
        session["ai_history"] = session["ai_history"][-4:] + [{"question": question, "answer": answer}]

        return jsonify({"answer": answer})

    except Exception as e:
        return jsonify({"error": f"AI request failed: {str(e)}"}), 500

@app.route('/report')
def report():
    if "user" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    # Get results from database
    if "last_scan_id" not in session:
        flash("No recent scan found", "warning")
        return redirect(url_for("dashboard"))
    
    results = get_scan_results(session['last_scan_id'], session["user"])
    if not results:
        flash("Scan results not found or expired", "warning")
        return redirect(url_for("dashboard"))

    target = results.get('target', 'No target')

    return render_template("report.html", target=target, results=results, username=session["user"])

#To run say false if you want
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
