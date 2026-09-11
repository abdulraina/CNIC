import os
import re
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)
CORS(app)

BASE_URL  = "https://freshsimtracker.com/numberDetails.php"
BASE_SITE = "https://freshsimtracker.com"

HEADERS = {
    "Origin":       "https://freshsimtracker.com",
    "Referer":      "https://freshsimtracker.com/",
    "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
}


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
# Upstream lookup
# ---------------------------------------------------------------------------

def _fetch_upstream(query_value: str):
    """
    POST to upstream and return parsed results (or raise).
    """
    resp = requests.post(
        BASE_URL,
        headers=HEADERS,
        data={"numberCnic": query_value, "searchNumber": "search"},
        timeout=20,
    )
    resp.raise_for_status()
    return parse_results(resp.text)


def _pick_cnic_from_results(results, searched_mobile: str = "") -> str:
    """
    Find a valid 13-digit CNIC from the results.
    Prefers the row whose mobile matches the searched number.
    """
    searched = normalize_mobile(searched_mobile) if searched_mobile else ""

    # 1. Try the row that matches the searched mobile
    if searched:
        for r in results:
            if normalize_mobile(r.get("mobile", "")) == searched:
                c = normalize_cnic(r.get("cnic", ""))
                if len(c) == 13:
                    return c

    # 2. Otherwise, first valid CNIC in the list
    for r in results:
        c = normalize_cnic(r.get("cnic", ""))
        if len(c) == 13:
            return c

    return ""


def _dedupe(results):
    """Deduplicate by (normalized mobile, normalized cnic). Preserves order."""
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
    """
    Put the row matching the searched mobile first, then all mobile-lookup rows,
    then all CNIC-lookup rows. Deduplicate.
    """
    searched = normalize_mobile(searched_mobile)
    prioritized = [r for r in mobile_results
                   if normalize_mobile(r.get("mobile", "")) == searched]
    rest_mobile = [r for r in mobile_results
                   if normalize_mobile(r.get("mobile", "")) != searched]

    merged = prioritized + rest_mobile + cnic_results
    return _dedupe(merged)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/search", methods=["POST", "GET"])
def search():
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

    # ---- First lookup -----------------------------------------------------
    try:
        first_results = _fetch_upstream(query_value)
    except requests.RequestException as e:
        return jsonify({
            "success": False,
            "error": f"Upstream request failed: {str(e)}"
        }), 502

    meta = {
        "query_type": query_type,
        "auto_cnic_lookup": False,
        "auto_cnic": "",
        "first_lookup_count": len(first_results),
        "second_lookup_count": 0,
    }

    final_results = first_results

    # ---- Second lookup (only when searching a mobile) ---------------------
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
                # Second lookup failed → silently fall back to first results
                pass

    if not final_results:
        return jsonify({
            "success": True,
            "count": 0,
            "query": query_value,
            "type": query_type,
            "results": [],
            "meta": meta,
            "message": f"No results found for this {query_type.upper()}.",
        })

    return jsonify({
        "success": True,
        "count": len(final_results),
        "query": query_value,
        "type": query_type,
        "results": final_results,
        "meta": meta,
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
