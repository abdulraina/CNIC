import os
import re
import time
import json
import hashlib
import threading
import logging
from pathlib import Path

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ALLOWED_ORIGIN   = os.environ.get("ALLOWED_ORIGIN", "https://rainaxsimdbpk.onrender.com")
SEARCH_LIMIT     = int(os.environ.get("SEARCH_LIMIT", "10"))       # per window
WINDOW_SECONDS   = int(os.environ.get("WINDOW_SECONDS", "3600"))   # 1 hour
MAX_BODY_BYTES   = int(os.environ.get("MAX_BODY_BYTES", "4096"))
STORE_PATH       = Path(os.environ.get("STORE_PATH", "/tmp/ratelimit_store.json"))

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

CORS(
    app,
    resources={r"/api/*": {"origins": [ALLOWED_ORIGIN]}},
    supports_credentials=False,
    allow_headers=["Content-Type", "X-Client-Id"],
    methods=["POST", "GET", "OPTIONS"],
)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

@app.after_request
def _add_security_headers(resp):
    resp.headers["X-Frame-Options"]            = "DENY"
    resp.headers["X-Content-Type-Options"]     = "nosniff"
    resp.headers["Referrer-Policy"]            = "no-referrer"
    resp.headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return resp


# ---------------------------------------------------------------------------
# Origin guard
# ---------------------------------------------------------------------------

def _origin_ok() -> bool:
    origin  = (request.headers.get("Origin")  or "").rstrip("/")
    referer = (request.headers.get("Referer") or "").rstrip("/")

    if origin == ALLOWED_ORIGIN.rstrip("/"):
        return True
    if referer.startswith(ALLOWED_ORIGIN.rstrip("/")):
        return True

    host = (request.host_url or "").rstrip("/")
    if host and (origin == host or referer.startswith(host)):
        return True

    return False


@app.before_request
def _guard_api():
    if not request.path.startswith("/api/"):
        return None

    if request.content_length and request.content_length > MAX_BODY_BYTES:
        return jsonify({"success": False, "error": "Payload too large."}), 413

    if not _origin_ok():
        log.warning("Blocked request origin=%r referer=%r ip=%s",
                    request.headers.get("Origin"),
                    request.headers.get("Referer"),
                    _client_ip())
        return jsonify({"success": False, "error": "Forbidden origin."}), 403

    return None


# ---------------------------------------------------------------------------
# Device fingerprint + rate limiting
# ---------------------------------------------------------------------------

_store_lock = threading.Lock()
_store_cache = None


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


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


def _device_fingerprint() -> str:
    client_id = (request.headers.get("X-Client-Id") or "").strip()[:128]
    ua        = (request.headers.get("User-Agent") or "").strip()[:256]
    lang      = (request.headers.get("Accept-Language") or "").strip()[:64]
    ip        = _client_ip()

    raw = f"{client_id}|{ua}|{lang}|{ip}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _check_and_increment(fp: str):
    now = int(time.time())

    with _store_lock:
        store = _load_store()
        entry = store.get(fp)

        if not entry or now - entry.get("start", 0) >= WINDOW_SECONDS:
            entry = {"start": now, "count": 0}
            store[fp] = entry

        used = entry["count"]

        if used >= SEARCH_LIMIT:
            reset_in = WINDOW_SECONDS - (now - entry["start"])
            return False, 0, max(reset_in, 0), used

        entry["count"] = used + 1
        _save_store()

        remaining = SEARCH_LIMIT - entry["count"]
        reset_in  = WINDOW_SECONDS - (now - entry["start"])
        return True, remaining, max(reset_in, 0), entry["count"]


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
# Input validation
# ---------------------------------------------------------------------------

def normalize_cnic(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def normalize_mobile(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    if digits.startswith("0092"):
        digits = digits[4:]
    elif digits.startswith("92") and len(digits) == 12:
        digits = digits[2:]
    if len(digits) == 10 and digits.startswith("3"):
        digits = "0" + digits
    return digits


def is_valid_cnic(value: str) -> bool:
    return len(normalize_cnic(value)) == 13


def is_valid_mobile(value: str) -> bool:
    m = normalize_mobile(value)
    if len(m) != 11 or not m.startswith("03"):
        return False
    return m[2] in "01234"


def detect_input_type(raw: str) -> str:
    digits = re.sub(r"\D", "", raw or "")
    stripped = digits
    if stripped.startswith("0092"):
        stripped = stripped[4:]
    elif stripped.startswith("92") and len(stripped) == 12:
        stripped = stripped[2:]

    if len(digits) == 13 and not digits.startswith("0"):
        return "cnic"
    if len(stripped) == 11 and stripped.startswith("03"):
        return "mobile"
    if len(stripped) == 10 and stripped.startswith("3"):
        return "mobile"
    if len(stripped) == 11 and stripped.startswith("0"):
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
    searched = normalize_mobile(searched_mobile) if searched_mobile else ""
    if searched:
        for r in results:
            if normalize_mobile(r.get("mobile", "")) == searched:
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
        key = (normalize_mobile(r.get("mobile", "")),
               normalize_cnic(r.get("cnic", "")))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _merge_mobile_then_cnic(mobile_results, cnic_results, searched_mobile):
    searched = normalize_mobile(searched_mobile)
    prioritized = [r for r in mobile_results
                   if normalize_mobile(r.get("mobile", "")) == searched]
    rest_mobile = [r for r in mobile_results
                   if normalize_mobile(r.get("mobile", "")) != searched]
    return _dedupe(prioritized + rest_mobile + cnic_results)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/quota", methods=["GET"])
def quota():
    fp = _device_fingerprint()
    now = int(time.time())

    with _store_lock:
        store = _load_store()
        entry = store.get(fp)
        if not entry or now - entry.get("start", 0) >= WINDOW_SECONDS:
            used = 0
            reset_in = WINDOW_SECONDS
        else:
            used = entry.get("count", 0)
            reset_in = max(WINDOW_SECONDS - (now - entry["start"]), 0)

    remaining = max(SEARCH_LIMIT - used, 0)
    return jsonify({
        "success": True,
        "limit": SEARCH_LIMIT,
        "used": used,
        "remaining": remaining,
        "reset_in": reset_in,
        "window_seconds": WINDOW_SECONDS,
    })


@app.route("/api/search", methods=["POST", "GET"])
def search():
    fp = _device_fingerprint()
    allowed, remaining, reset_in, used = _check_and_increment(fp)

    if not allowed:
        log.info("Rate limit hit fp=%s used=%s", fp[:8] + "...", used)
        return jsonify({
            "success": False,
            "error": f"Search limit reached ({SEARCH_LIMIT} per hour). "
                     f"Try again in ~{max(reset_in // 60, 1)} min.",
            "limit": SEARCH_LIMIT,
            "used": used,
            "remaining": 0,
            "reset_in": reset_in,
        }), 429

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
        return jsonify({
            "success": False,
            "error": "Please enter a CNIC (13 digits) or mobile number (11 digits)."
        }), 400

    if len(raw) > 40:
        return jsonify({"success": False, "error": "Input too long."}), 400

    kind = detect_input_type(raw)

    if kind == "cnic":
        query_value = normalize_cnic(raw)
        if not is_valid_cnic(query_value):
            return jsonify({
                "success": False,
                "error": "Invalid CNIC. Must be 13 digits (e.g., 4530448083059)."
            }), 400
        query_type = "cnic"
    elif kind == "mobile":
        query_value = normalize_mobile(raw)
        if not is_valid_mobile(query_value):
            return jsonify({
                "success": False,
                "error": "Invalid mobile number. Use 11-digit format (e.g., 03001234567)."
            }), 400
        query_type = "mobile"
    else:
        return jsonify({
            "success": False,
            "error": "Unrecognized input. Enter a 13-digit CNIC or 11-digit mobile number."
        }), 400

    try:
        first_results = _fetch_upstream(query_value)
    except requests.RequestException as e:
        log.warning("Upstream error: %s", e)
        return jsonify({
            "success": False,
            "error": "Upstream request failed. Try again shortly."
        }), 502

    meta = {
        "query_type": query_type,
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
        return jsonify({
            "success": True,
            "count": 0,
            "query": query_value,
            "type": query_type,
            "results": [],
            "meta": meta,
            "quota": {"limit": SEARCH_LIMIT, "remaining": remaining, "reset_in": reset_in},
            "message": f"No results found for this {query_type.upper()}.",
        })

    log.info("Search ok fp=%s type=%s count=%s remaining=%s",
             fp[:8] + "...", query_type, len(final_results), remaining)

    return jsonify({
        "success": True,
        "count": len(final_results),
        "query": query_value,
        "type": query_type,
        "results": final_results,
        "meta": meta,
        "quota": {"limit": SEARCH_LIMIT, "remaining": remaining, "reset_in": reset_in},
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
