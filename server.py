import os
import re
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)
CORS(app)

BASE_URL = "https://freshsimtracker.com/numberDetails.php"
HEADERS = {
    "Origin": "https://freshsimtracker.com",
    "Referer": "https://freshsimtracker.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
}

# Pakistani mobile prefixes (without leading 0 or +92) → e.g. 300, 301, ... 349
VALID_MOBILE_PREFIXES = {
    "30", "31", "32", "33", "34", "35",
    "40", "41", "42", "43", "44", "45",
    "46", "47", "48", "49",
    "50", "51", "52", "53", "54", "55",
    "56", "57", "58", "59",
    "20", "21", "22", "23", "24", "25",
    "26", "27", "28", "29",
}


def normalize_cnic(value: str) -> str:
    """Strip non-digits from a CNIC."""
    return re.sub(r"\D", "", value or "")


def normalize_mobile(value: str) -> str:
    """
    Normalize a Pakistani mobile number to 11-digit form (03XXXXXXXXX).
    Accepts: 03001234567, 3001234567, +923001234567, 00923001234567, 92-300-1234567
    """
    digits = re.sub(r"\D", "", value or "")

    # Strip country code variations
    if digits.startswith("0092"):
        digits = digits[4:]
    elif digits.startswith("92") and len(digits) == 12:
        digits = digits[2:]

    # Add leading 0 if missing (10-digit local form: 3XXXXXXXXX)
    if len(digits) == 10 and digits.startswith("3"):
        digits = "0" + digits

    return digits


def is_valid_cnic(value: str) -> bool:
    return len(normalize_cnic(value)) == 13


def is_valid_mobile(value: str) -> bool:
    m = normalize_mobile(value)
    if len(m) != 11 or not m.startswith("0"):
        return False
    # Must start with 03
    if not m.startswith("03"):
        return False
    # Third digit must be a valid Pakistani mobile prefix digit (0-4)
    # Format: 03XXXXXXXXX  → 11 digits total
    return m[2] in "01234"


def detect_input_type(raw: str) -> str:
    """
    Returns 'cnic', 'mobile', or 'invalid' based on the given input.
    Prefers CNIC if 13 digits (unambiguous), else mobile if 11/10/12/13 with leading 0/92.
    """
    digits = re.sub(r"\D", "", raw or "")

    # Strip 92 / 0092 to compare fairly
    stripped = digits
    if stripped.startswith("0092"):
        stripped = stripped[4:]
    elif stripped.startswith("92") and len(stripped) == 12:
        stripped = stripped[2:]

    # CNIC = 13 digits (no leading 0 in typical Pakistani CNIC)
    if len(digits) == 13 and not digits.startswith("0"):
        return "cnic"

    # Mobile variants
    if len(stripped) == 11 and stripped.startswith("03"):
        return "mobile"
    if len(stripped) == 10 and stripped.startswith("3"):
        return "mobile"
    if len(stripped) == 11 and stripped.startswith("0"):
        # Could still be a malformed CNIC — treat as mobile attempt
        return "mobile"

    return "invalid"


def parse_results(html: str):
    soup = BeautifulSoup(html, "html.parser")
    table = soup.select_one("table.table")
    if not table:
        return []

    results = []
    for row in table.select("tr"):
        cells = [c.get_text(" ", strip=True) for c in row.select("td")]
        if len(cells) < 5:
            continue
        results.append({
            "mobile":  cells[0],
            "name":    cells[1],
            "cnic":    cells[2],
            "address": cells[3],
            "network": cells[4],
        })
    return results


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/search", methods=["POST", "GET"])
def search():
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict() or request.args.to_dict()

    # Accept any of these keys from client
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

    # Upstream site uses the same field name for both lookups
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
