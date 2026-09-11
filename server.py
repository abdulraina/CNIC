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

# Map image filename (lowercase, no extension, no separators) → canonical name
_NETWORK_FILENAME_MAP = {
    "jazz":    "Jazz",
    "zong":    "Zong",
    "ufone":   "Ufone",
    "telenor": "Telenor",
    "warid":   "Warid",
    "scom":    "SCOM",
    "ptcl":    "PTCL",
    # The upstream site uses "Mob.png" as a generic/older icon.
    # Change this if you know it maps to a specific network.
    "mob":     "Moblink",
}


def _network_from_image(img_tag):
    """
    Extract (network_name, full_logo_url) from an <img> tag.
    Returns ("", "") if nothing usable.
    """
    if not img_tag:
        return "", ""

    # 1. Prefer alt / title attributes if meaningful
    for attr in ("alt", "title", "data-name", "data-network"):
        val = (img_tag.get(attr) or "").strip()
        if val and val.lower() not in ("network", "logo", "img", "icon"):
            return val, ""

    # 2. Fall back to the src filename
    src = (img_tag.get("src") or "").strip()
    if not src:
        return "", ""

    # Build full URL for the logo
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

    # Unknown filename → best-effort title-case
    pretty = re.sub(r"[_\-\s]+", " ", filename).strip().title()
    return pretty or "", full_url


def _cell_text(td):
    """
    Return visible text of a <td>. If empty, fall back to the network
    name derived from any <img> inside it.
    """
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
    """Strip all non-digits from a CNIC."""
    return re.sub(r"\D", "", value or "")


def normalize_mobile(value: str) -> str:
    """
    Normalize a Pakistani mobile number to 11-digit form (03XXXXXXXXX).
    Accepts: 03001234567, 3001234567, +923001234567,
             00923001234567, 92-300-1234567, +92 300 1234567
    """
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
    """
    Return 'cnic' | 'mobile' | 'invalid'.
    """
    digits = re.sub(r"\D", "", raw or "")

    stripped = digits
    if stripped.startswith("0092"):
        stripped = stripped[4:]
    elif stripped.startswith("92") and len(stripped) == 12:
        stripped = stripped[2:]

    # 13 digits not starting with 0 → CNIC
    if len(digits) == 13 and not digits.startswith("0"):
        return "cnic"

    # Mobile variants
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

    try:
        resp = requests.post(
            BASE_URL,
            headers=HEADERS,
            data={"numberCnic": query_value, "searchNumber": "search"},
            timeout=20,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        return jsonify({
            "success": False,
            "error": f"Upstream request failed: {str(e)}"
        }), 502

    results = parse_results(resp.text)

    if not results:
        return jsonify({
            "success": True,
            "count": 0,
            "query": query_value,
            "type": query_type,
            "results": [],
            "message": f"No results found for this {query_type.upper()}.",
        })

    return jsonify({
        "success": True,
        "count": len(results),
        "query": query_value,
        "type": query_type,
        "results": results,
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
