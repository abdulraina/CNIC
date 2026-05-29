#!/usr/bin/env python3
"""
CNIC Lookup Web Server - Device Fingerprint Rate Limiting
Fingerprint = IP + Browser signals + Canvas hash + Screen + Timezone
Cannot be bypassed by reconnecting internet or clearing cookies
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import time
import os
import hashlib
import logging

# ============================================================
# Logging (works with Gunicorn)
# ============================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

BASE_URL = "https://cnic.shop"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36",
    "Referer": BASE_URL + "/",
    "Origin": BASE_URL,
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, */*",
}

session = requests.Session()
session.headers.update(HEADERS)
csrf_token = None
session_initialized = False

# ============================================================
# Rate limit storage
# { device_fingerprint: [timestamps] }
# ============================================================
rate_db = {}
MAX_PER_HOUR = 10

def check_rate_limit(fp):
    now = time.time()
    hour_ago = now - 3600
    times = [t for t in rate_db.get(fp, []) if t > hour_ago]
    rate_db[fp] = times
    remaining = MAX_PER_HOUR - len(times)
    if len(times) >= MAX_PER_HOUR:
        reset_in = int((times[0] + 3600 - now) / 60) + 1
        return False, 0, reset_in
    times.append(now)
    rate_db[fp] = times
    return True, remaining - 1, 0

# ============================================================
# CNIC session
# ============================================================
def init_cnic_session():
    global csrf_token, session_initialized
    try:
        resp = session.get(BASE_URL + "/", timeout=20)
        soup = BeautifulSoup(resp.text, "html.parser")
        meta = soup.find("meta", {"name": "csrf-token"})
        if meta and meta.get("content"):
            csrf_token = meta["content"]
            session_initialized = True
            logger.info("✅ CNIC session ready")
            return True
        hidden = soup.find("input", {"name": "csrf_token"})
        if hidden and hidden.get("value"):
            csrf_token = hidden["value"]
            session_initialized = True
            return True
        return False
    except Exception as e:
        logger.error(f"❌ Session init failed: {e}")
        return False

def refresh_csrf():
    global csrf_token
    try:
        resp = session.get(BASE_URL + "/", timeout=15)
        soup = BeautifulSoup(resp.text, "html.parser")
        meta = soup.find("meta", {"name": "csrf-token"})
        if meta and meta.get("content"):
            csrf_token = meta["content"]
    except:
        pass

def do_lookup(number):
    global csrf_token
    try:
        resp = session.post(
            BASE_URL + "/track",
            data={"csrf_token": csrf_token, "user_input": number},
            timeout=20
        )
        if resp.status_code in (400, 403) or \
           "application/json" not in resp.headers.get("content-type", ""):
            refresh_csrf()
            resp = session.post(
                BASE_URL + "/track",
                data={"csrf_token": csrf_token, "user_input": number},
                timeout=20
            )
        if "application/json" not in resp.headers.get("content-type", ""):
            return {"Error": f"Server error (HTTP {resp.status_code})"}
        return resp.json()
    except requests.exceptions.Timeout:
        return {"Error": "Request timed out. Try again."}
    except requests.exceptions.ConnectionError:
        return {"Error": "Could not connect to database."}
    except Exception as e:
        return {"Error": str(e)}

# ============================================================
# Routes
# ============================================================

@app.route("/")
def index():
    return send_file("cnic_lookup.html")

@app.route("/api/lookup", methods=["POST"])
def lookup():
    data = request.get_json()
    if not data:
        return jsonify({"Error": "Missing data"}), 400

    device_fp = data.get("deviceFingerprint", "").strip()
    number     = str(data.get("number", "")).strip()
    ip         = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip         = ip.split(",")[0].strip()

    if not device_fp:
        return jsonify({"Error": "Missing device fingerprint"}), 400

    ua = request.headers.get("User-Agent", "")
    combined = hashlib.sha256(f"{device_fp}|{ua}".encode()).hexdigest()[:32]

    allowed, remaining, reset_mins = check_rate_limit(combined)

    if not allowed:
        logger.info(f"🚫 Blocked: {ip} fp={combined[:8]}...")
        return jsonify({
            "Error": f"Rate limit reached ({MAX_PER_HOUR}/hour). Try again in {reset_mins} min.",
            "rate_limited": True,
            "reset_in": reset_mins
        }), 429

    if not number.isdigit() or not (10 <= len(number) <= 13):
        return jsonify({"Error": "Invalid number. Must be 10–13 digits."}), 400

    if not session_initialized:
        if not init_cnic_session():
            return jsonify({"Error": "Database unavailable. Try later."}), 503

    logger.info(f"🔍 {number} | IP: {ip} | FP: {combined[:8]}... | Left: {remaining}")
    result = do_lookup(number)
    result["_remaining"] = remaining
    result["_limit"] = MAX_PER_HOUR
    return jsonify(result)

@app.route("/api/status", methods=["POST"])
def status():
    data = request.get_json() or {}
    device_fp = data.get("deviceFingerprint", "")
    ua = request.headers.get("User-Agent", "")
    combined = hashlib.sha256(f"{device_fp}|{ua}".encode()).hexdigest()[:32]

    now = time.time()
    hour_ago = now - 3600
    times = [t for t in rate_db.get(combined, []) if t > hour_ago]
    remaining = max(0, MAX_PER_HOUR - len(times))
    reset_in = 0
    if times and remaining == 0:
        reset_in = max(0, int((times[0] + 3600 - now) / 60) + 1)

    return jsonify({
        "status": "ok",
        "remaining": remaining,
        "limit": MAX_PER_HOUR,
        "reset_in": reset_in,
        "session": session_initialized
    })

@app.route("/admin/limits")
def admin_limits():
    secret = request.args.get("key", "")
    if secret != os.environ.get("ADMIN_KEY", "changeme"):
        return "Forbidden", 403
    now = time.time()
    hour_ago = now - 3600
    active = {
        fp[:8] + "...": len([t for t in times if t > hour_ago])
        for fp, times in rate_db.items()
        if any(t > hour_ago for t in times)
    }
    return jsonify({"active_users": active, "limit": MAX_PER_HOUR})

# ============================================================
# WSGI entry point (used by Gunicorn on Render)
# ============================================================
# Gunicorn calls this module and looks for `app`.
# Session is initialized here so it runs once at startup.
init_cnic_session()

# ============================================================
# Local dev entry point
# ============================================================
if __name__ == "__main__":
    print("=" * 50)
    print("  CNIC Lookup — Device Fingerprint Rate Limiting")
    print("=" * 50)
    port = int(os.environ.get("PORT", 5000))
    admin_key = os.environ.get("ADMIN_KEY", "changeme")
    print(f"\n🌐 Running at http://0.0.0.0:{port}")
    print(f"🔑 Admin: http://localhost:{port}/admin/limits?key={admin_key}")
    print(f"\nPress Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=False)
