import os
import re
import time
import json
import hashlib
import hmac
import threading
import logging
import secrets
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, render_template, make_response, redirect
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ALLOWED_ORIGIN   = os.environ.get("ALLOWED_ORIGIN", "")
SEARCH_LIMIT     = int(os.environ.get("SEARCH_LIMIT", "10"))
WINDOW_SECONDS   = int(os.environ.get("WINDOW_SECONDS", "3600"))
MAX_BODY_BYTES   = int(os.environ.get("MAX_BODY_BYTES", "4096"))
STORE_PATH       = Path(os.environ.get("STORE_PATH", "/tmp/ratelimit_store.json"))
COOKIE_NAME      = "rnx_did"
COOKIE_MAX_AGE   = 60 * 60 * 24 * 365   # 1 year

# --- Authentication ---------------------------------------------------------
ADMIN_USERNAME   = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD   = os.environ.get("ADMIN_PASSWORD", "ChangeMeNow!123")
SESSION_SECRET   = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
SESSION_COOKIE   = "rnx_session"
SESSION_MAX_AGE  = int(os.environ.get("SESSION_MAX_AGE", str(60 * 60 * 8)))
LOGIN_MAX_ATTEMPTS   = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("LOGIN_WINDOW_SECONDS", "300"))

BASE_URL  = "https://freshsimtracker.com/numberDetails.php"
BASE_SITE = "https://freshsimtracker.com"

HEADERS = {
    "Origin":       "https://freshsimtracker.com",
    "Referer":      "https://freshsimtracker.com/",
    "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("simtracker")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
app.config["SECRET_KEY"] = SESSION_SECRET
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_for=1)

CORS(
    app,
    resources={r"/api/*": {
        "origins": "*" if not ALLOWED_ORIGIN else [ALLOWED_ORIGIN],
        "allow_headers": ["Content-Type", "X-Fingerprint", "X-CSRF-Token", "X-Requested-With"],
        "methods": ["POST", "GET", "OPTIONS"],
        "supports_credentials": True,
    }},
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _is_https() -> bool:
    return (request.headers.get("X-Forwarded-Proto", "http").lower() == "https"
            or request.is_secure)


def _origin_ok() -> bool:
    """Permissive origin check — allows same-host, configured origin, and localhost."""
    if not ALLOWED_ORIGIN:
        return True

    origin  = (request.headers.get("Origin")  or "").rstrip("/")
    referer = (request.headers.get("Referer") or "").rstrip("/")

    allowed = ALLOWED_ORIGIN.rstrip("/")
    if origin == allowed or referer.startswith(allowed):
        return True

    host = (request.host_url or "").rstrip("/")
    if host and (origin == host or referer.startswith(host)):
        return True

    # Allow localhost for dev
    if origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
        return True
    if referer.startswith("http://localhost") or referer.startswith("http://127.0.0.1"):
        return True

    return False


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

@app.after_request
def _add_security_headers(resp):
    resp.headers["X-Frame-Options"]            = "SAMEORIGIN"
    resp.headers["X-Content-Type-Options"]     = "nosniff"
    resp.headers["Referrer-Policy"]            = "no-referrer"
    resp.headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()"
    return resp


# ---------------------------------------------------------------------------
# Session store (in-memory)
# ---------------------------------------------------------------------------

_sessions_lock = threading.Lock()
_sessions = {}


def _create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[token] = {
            "username": username,
            "expires":  time.time() + SESSION_MAX_AGE,
            "ip":       _client_ip(),
            "ua":       (request.headers.get("User-Agent") or "")[:256],
        }
    return token


def _get_session(token: str):
    if not token:
        return None
    with _sessions_lock:
        s = _sessions.get(token)
        if not s:
            return None
        if time.time() > s["expires"]:
            _sessions.pop(token, None)
            return None
        return s


def _destroy_session(token: str):
    if not token:
        return
    with _sessions_lock:
        _sessions.pop(token, None)


def _cleanup_sessions():
    now = time.time()
    with _sessions_lock:
        expired = [k for k, v in _sessions.items() if now > v["expires"]]
        for k in expired:
            _sessions.pop(k, None)


def _current_user():
    return (_get_session(request.cookies.get(SESSION_COOKIE)) or {}).get("username")


def _require_auth() -> bool:
    return _current_user() is not None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _require_auth():
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Unauthorized."}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Login rate-limit
# ---------------------------------------------------------------------------

_login_attempts_lock = threading.Lock()
_login_attempts = {}


def _login_key(username: str) -> str:
    return hashlib.sha256(f"{_client_ip()}|{username.lower()}".encode()).hexdigest()[:32]


def _check_login_lock(username: str):
    key = _login_key(username)
    now = time.time()
    with _login_attempts_lock:
        e = _login_attempts.get(key)
        if not e:
            return False, 0
        if e.get("locked_until", 0) > now:
            return True, int(e["locked_until"] - now)
        if now - e.get("start", 0) >= LOGIN_WINDOW_SECONDS:
            _login_attempts.pop(key, None)
        return False, 0


def _record_login_failure(username: str):
    key = _login_key(username)
    now = time.time()
    with _login_attempts_lock:
        e = _login_attempts.get(key)
        if not e or now - e.get("start", 0) >= LOGIN_WINDOW_SECONDS:
            e = {"start": now, "count": 0, "locked_until": 0}
            _login_attempts[key] = e
        e["count"] += 1
        if e["count"] >= LOGIN_MAX_ATTEMPTS:
            e["locked_until"] = now + LOGIN_WINDOW_SECONDS


def _clear_login_failures(username: str):
    with _login_attempts_lock:
        _login_attempts.pop(_login_key(username), None)


# ---------------------------------------------------------------------------
# API guard
# ---------------------------------------------------------------------------

_PUBLIC_API_PATHS = {"/api/login", "/api/logout", "/api/health", "/api/session"}


@app.before_request
def _guard_api():
    if not request.path.startswith("/api/"):
        return None

    if request.content_length and request.content_length > MAX_BODY_BYTES:
        return jsonify({"success": False, "error": "Payload too large."}), 413

    if not _origin_ok():
        log.warning("Blocked origin=%r referer=%r ip=%s",
                    request.headers.get("Origin"),
                    request.headers.get("Referer"),
                    _client_ip())
        return jsonify({"success": False, "error": "Forbidden origin."}), 403

    if request.path not in _PUBLIC_API_PATHS:
        if not _require_auth():
            return jsonify({"success": False, "error": "Unauthorized. Please log in."}), 401

    return None


# ---------------------------------------------------------------------------
# Device cookie + Search rate-limit store
# ---------------------------------------------------------------------------

def _ensure_device_cookie() -> str:
    existing = request.cookies.get(COOKIE_NAME)
    if existing and re.fullmatch(r"[a-f0-9]{32}", existing):
        return existing
    new_id = secrets.token_hex(16)
    request.environ["_new_device_cookie"] = new_id
    return new_id


def _maybe_set_cookie(resp):
    new_id = request.environ.get("_new_device_cookie")
    if new_id:
        resp.set_cookie(
            COOKIE_NAME, new_id,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            secure=_is_https(),
            samesite="Lax",
            path="/",
        )


_store_lock = threading.Lock()
_store_cache = None


def _load_store() -> dict:
    global _store_cache
    if _store_cache is not None:
        return _store_cache
    try:
        if STORE_PATH.exists():
            with STORE_PATH.open("r", encoding="utf-8") as f:
                _store_cache = json.load(f)
        else:
            _store_cache = {}
    except Exception:
        _store_cache = {}
    return _store_cache


def _save_store():
    try:
        STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = STORE_PATH.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(_store_cache, f)
        tmp.replace(STORE_PATH)
    except Exception as e:
        log.warning("Failed to persist rate-limit store: %s", e)


def _bucket_keys(cookie_id: str) -> list:
    ip    = _client_ip()
    ua    = (request.headers.get("User-Agent") or "").strip()[:256]
    lang  = (request.headers.get("Accept-Language") or "").strip()[:64]
    fpjs  = (request.headers.get("X-Fingerprint") or "").strip()[:128]

    keys = ["c:" + hashlib.sha256(cookie_id.encode()).hexdigest()[:24]]
    if fpjs:
        keys.append("f:" + hashlib.sha256(fpjs.encode()).hexdigest()[:24])
    keys.append("i:" + hashlib.sha256(f"{ip}|{ua}|{lang}".encode()).hexdigest()[:24])

    seen = set()
    out = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _check_all_buckets(keys: list):
    now = int(time.time())
    with _store_lock:
        store = _load_store()
        worst_remaining = None
        worst_reset_in  = 0
        worst_used      = 0

        for k in keys:
            entry = store.get(k)
            if not entry or now - entry.get("start", 0) >= WINDOW_SECONDS:
                entry = {"start": now, "count": 0}
                store[k] = entry

            used     = entry["count"]
            reset_in = max(WINDOW_SECONDS - (now - entry["start"]), 0)
            remain   = max(SEARCH_LIMIT - used, 0)

            if worst_remaining is None or remain < worst_remaining:
                worst_remaining = remain
                worst_reset_in  = reset_in
                worst_used      = used

            if used >= SEARCH_LIMIT:
                _save_store()
                return False, 0, reset_in, used

        for k in keys:
            store[k]["count"] += 1
        _save_store()
        return True, max(worst_remaining - 1, 0), worst_reset_in, worst_used + 1


# ---------------------------------------------------------------------------
# Network logo helpers
# ---------------------------------------------------------------------------

_NETWORK_FILENAME_MAP = {
    "jazz":    "Jazz",
    "zong":    "Zong",
    "ufone":   "Ufone",
    "telenor": "Telenor",
    "warid":   "Warid",
    "scom":    "SCOM",
    "ptcl":    "PTCL",
    "mob":     "Moblink",
}


def _network_from_image(img_tag):
    if not img_tag:
        return "", ""

    for attr in ("alt", "title", "data-name", "data-network"):
        val = (img_tag.get(attr) or "").strip()
        if val and val.lower() not in ("network", "logo", "img", "icon"):
            return val, ""

    src = (img_tag.get("src") or "").strip()
    if not src:
        return "", ""

    if src.startswith("//"):
        full_url = "https:" + src
    elif src.startswith("http://") or src.startswith("https://"):
        full_url = src
    elif src.startswith("/"):
        full_url = BASE_SITE + src
    else:
        full_url = BASE_SITE + "/" + src

    filename = src.split("?")[0].split("/")[-1]
    filename = re.sub(r"\.(png|jpe?g|gif|svg|webp|bmp)$", "", filename, flags=re.I)
    key = filename.lower().strip().replace("_", "").replace("-", "").replace(" ", "")

    canonical = _NETWORK_FILENAME_MAP.get(key)
    if canonical:
        return canonical, full_url

    pretty = re.sub(r"[_\-\s]+", " ", filename).strip().title()
    return pretty or "", full_url


def _cell_text(td):
    text = td.get_text(" ", strip=True)
    if text:
        return text
    img = td.find("img")
    if img:
        name, _ = _network_from_image(img)
        return name
    return ""


# ---------------------------------------------------------------------------
# Input normalization
# ---------------------------------------------------------------------------

def normalize_cnic(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def normalize_mobile_for_upstream(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    if digits.startswith("0092"):
        digits = digits[4:]
    elif digits.startswith("92") and len(digits) >= 12:
        digits = digits[2:]
    if digits.startswith("0"):
        digits = digits[1:]
    return digits


def normalize_mobile_display(value: str) -> str:
    m = normalize_mobile_for_upstream(value)
    if len(m) == 10 and m.startswith("3"):
        return "0" + m
    return m


def is_valid_mobile(value: str) -> bool:
    m = normalize_mobile_for_upstream(value)
    if len(m) != 10 or not m.startswith("3"):
        return False
    return m[1] in "01234"


def is_valid_cnic(value: str) -> bool:
    return len(normalize_cnic(value)) == 13


def detect_input_type(raw: str) -> str:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 13 and not digits.startswith("0"):
        return "cnic"
    m = normalize_mobile_for_upstream(raw)
    if len(m) == 10 and m.startswith("3"):
        return "mobile"
    return "invalid"


# ---------------------------------------------------------------------------
# HTML parsing
# ---------------------------------------------------------------------------

def parse_results(html: str):
    soup = BeautifulSoup(html, "html.parser")
    table = soup.select_one("table.table")
    if not table:
        return []

    results = []
    for row in table.select("tr"):
        cells = row.select("td")
        if len(cells) < 5:
            continue

        network_td = cells[4]
        img = network_td.find("img")
        network_name = _cell_text(network_td)
        network_logo = ""
        if img:
            _, network_logo = _network_from_image(img)

        results.append({
            "mobile":        _cell_text(cells[0]),
            "name":          _cell_text(cells[1]),
            "cnic":          _cell_text(cells[2]),
            "address":       _cell_text(cells[3]),
            "network":       network_name,
            "network_image": network_logo,
        })
    return results


# ---------------------------------------------------------------------------
# Upstream + merge
# ---------------------------------------------------------------------------

def _fetch_upstream(query_value: str):
    resp = requests.post(
        BASE_URL,
        headers=HEADERS,
        data={"numberCnic": query_value, "searchNumber": "search"},
        timeout=20,
    )
    resp.raise_for_status()
    return parse_results(resp.text)


def _pick_cnic_from_results(results, searched_mobile: str = "") -> str:
    searched = normalize_mobile_for_upstream(searched_mobile) if searched_mobile else ""
    if searched:
        for r in results:
            if normalize_mobile_for_upstream(r.get("mobile", "")) == searched:
                c = normalize_cnic(r.get("cnic", ""))
                if len(c) == 13:
                    return c
    for r in results:
        c = normalize_cnic(r.get("cnic", ""))
        if len(c) == 13:
            return c
    return ""


def _dedupe(results):
    seen = set()
    out = []
    for r in results:
        key = (normalize_mobile_for_upstream(r.get("mobile", "")),
               normalize_cnic(r.get("cnic", "")))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _merge_mobile_then_cnic(mobile_results, cnic_results, searched_mobile):
    searched = normalize_mobile_for_upstream(searched_mobile)
    prioritized = [r for r in mobile_results
                   if normalize_mobile_for_upstream(r.get("mobile", "")) == searched]
    rest_mobile = [r for r in mobile_results
                   if normalize_mobile_for_upstream(r.get("mobile", "")) != searched]
    return _dedupe(prioritized + rest_mobile + cnic_results)


# ---------------------------------------------------------------------------
# ROUTES — Pages
# ---------------------------------------------------------------------------

@app.route("/login")
def login_page():
    if _require_auth():
        return redirect("/app")
    return render_template("login.html")


@app.route("/app")
@login_required
def app_page():
    resp = make_response(render_template("index.html"))
    _ensure_device_cookie()
    _maybe_set_cookie(resp)
    return resp


@app.route("/")
def index():
    return redirect("/app" if _require_auth() else "/login")


# ---------------------------------------------------------------------------
# ROUTES — Auth
# ---------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"success": False, "error": "Missing credentials."}), 400

    if len(username) > 64 or len(password) > 256:
        return jsonify({"success": False, "error": "Invalid input."}), 400

    locked, secs = _check_login_lock(username)
    if locked:
        return jsonify({"success": False,
                        "error": f"Too many failed attempts. Try again in {secs}s."}), 429

    user_ok = hmac.compare_digest(username, ADMIN_USERNAME)
    pass_ok = hmac.compare_digest(password, ADMIN_PASSWORD)

    if not (user_ok and pass_ok):
        _record_login_failure(username)
        time.sleep(0.6)
        log.warning("Failed login user=%r ip=%s", username, _client_ip())
        return jsonify({"success": False, "error": "Invalid username or password."}), 401

    _clear_login_failures(username)
    token = _create_session(username)

    resp = make_response(jsonify({"success": True, "redirect": "/app"}))
    resp.set_cookie(
        SESSION_COOKIE, token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=_is_https(),
        samesite="Lax",
        path="/",
    )
    log.info("Login OK user=%s ip=%s", username, _client_ip())
    return resp


@app.route("/api/logout", methods=["POST"])
def api_logout():
    _destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = make_response(jsonify({"success": True}))
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.route("/api/session")
def api_session():
    if _require_auth():
        return jsonify({"success": True, "user": _current_user()})
    return jsonify({"success": False}), 401


# ---------------------------------------------------------------------------
# ROUTES — Quota / Search
# ---------------------------------------------------------------------------

@app.route("/api/quota", methods=["GET"])
def quota():
    cookie_id = _ensure_device_cookie()
    keys = _bucket_keys(cookie_id)
    now = int(time.time())

    with _store_lock:
        store = _load_store()
        used = 0
        reset_in = WINDOW_SECONDS
        for k in keys:
            entry = store.get(k)
            if not entry or now - entry.get("start", 0) >= WINDOW_SECONDS:
                continue
            if entry["count"] > used:
                used = entry["count"]
                reset_in = max(WINDOW_SECONDS - (now - entry["start"]), 0)

    remaining = max(SEARCH_LIMIT - used, 0)
    resp = make_response(jsonify({
        "success": True,
        "limit": SEARCH_LIMIT,
        "used": used,
        "remaining": remaining,
        "reset_in": reset_in,
        "window_seconds": WINDOW_SECONDS,
    }))
    _maybe_set_cookie(resp)
    return resp


@app.route("/api/search", methods=["POST", "GET"])
def search():
    cookie_id = _ensure_device_cookie()
    keys = _bucket_keys(cookie_id)
    allowed, remaining, reset_in, used = _check_all_buckets(keys)

    if not allowed:
        resp = make_response(jsonify({
            "success": False,
            "error": f"Search limit reached ({SEARCH_LIMIT} per hour). "
                     f"Try again in ~{max(reset_in // 60, 1)} min.",
            "limit": SEARCH_LIMIT,
            "used": used,
            "remaining": 0,
            "reset_in": reset_in,
        }), 429)
        _maybe_set_cookie(resp)
        return resp

    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict() or request.args.to_dict()

    raw = (
        data.get("query")
        or data.get("numberCnic")
        or data.get("cnic")
        or data.get("mobile")
        or ""
    ).strip()

    if not raw:
        resp = make_response(jsonify({
            "success": False,
            "error": "Please enter a CNIC (13 digits) or mobile number (11 digits)."
        }), 400)
        _maybe_set_cookie(resp)
        return resp

    if len(raw) > 40:
        resp = make_response(jsonify({"success": False, "error": "Input too long."}), 400)
        _maybe_set_cookie(resp)
        return resp

    kind = detect_input_type(raw)

    if kind == "cnic":
        query_value = normalize_cnic(raw)
        if not is_valid_cnic(query_value):
            resp = make_response(jsonify({
                "success": False,
                "error": "Invalid CNIC. Must be 13 digits (e.g., 4530448083059)."
            }), 400)
            _maybe_set_cookie(resp)
            return resp
        query_type = "cnic"

    elif kind == "mobile":
        query_value = normalize_mobile_for_upstream(raw)
        if not is_valid_mobile(query_value):
            resp = make_response(jsonify({
                "success": False,
                "error": "Invalid mobile number. Use 11-digit format (e.g., 03001234567)."
            }), 400)
            _maybe_set_cookie(resp)
            return resp
        query_type = "mobile"
    else:
        resp = make_response(jsonify({
            "success": False,
            "error": "Unrecognized input. Enter a 13-digit CNIC or 11-digit mobile number."
        }), 400)
        _maybe_set_cookie(resp)
        return resp

    query_display = (normalize_mobile_display(query_value) if query_type == "mobile"
                     else query_value)

    log.info("Upstream lookup user=%s type=%s value=%s",
             _current_user(), query_type, query_value)

    try:
        first_results = _fetch_upstream(query_value)
    except requests.RequestException as e:
        log.warning("Upstream error: %s", e)
        resp = make_response(jsonify({
            "success": False,
            "error": "Upstream request failed. Try again shortly."
        }), 502)
        _maybe_set_cookie(resp)
        return resp

    meta = {
        "query_type": query_type,
        "upstream_query": query_value,
        "auto_cnic_lookup": False,
        "auto_cnic": "",
        "first_lookup_count": len(first_results),
        "second_lookup_count": 0,
    }

    final_results = first_results

    if query_type == "mobile" and first_results:
        discovered_cnic = _pick_cnic_from_results(first_results, searched_mobile=query_value)
        if discovered_cnic:
            meta["auto_cnic"] = discovered_cnic
            try:
                cnic_results = _fetch_upstream(discovered_cnic)
                meta["auto_cnic_lookup"] = True
                meta["second_lookup_count"] = len(cnic_results)
                final_results = _merge_mobile_then_cnic(
                    mobile_results=first_results,
                    cnic_results=cnic_results,
                    searched_mobile=query_value,
                )
            except requests.RequestException:
                pass

    if not final_results:
        resp = make_response(jsonify({
            "success": True,
            "count": 0,
            "query": query_display,
            "type": query_type,
            "results": [],
            "meta": meta,
            "quota": {"limit": SEARCH_LIMIT, "remaining": remaining, "reset_in": reset_in},
            "message": f"No results found for this {query_type.upper()}.",
        }))
        _maybe_set_cookie(resp)
        return resp

    resp = make_response(jsonify({
        "success": True,
        "count": len(final_results),
        "query": query_display,
        "type": query_type,
        "results": final_results,
        "meta": meta,
        "quota": {"limit": SEARCH_LIMIT, "remaining": remaining, "reset_in": reset_in},
    }))
    _maybe_set_cookie(resp)
    return resp


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "user": _current_user()})


# ---------------------------------------------------------------------------
# Background session cleaner
# ---------------------------------------------------------------------------

def _session_cleaner():
    while True:
        time.sleep(300)
        try:
            _cleanup_sessions()
        except Exception:
            pass


threading.Thread(target=_session_cleaner, daemon=True).start()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
