from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import re

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

BASE_URL = "https://freshsimtracker.com/numberDetails.php"
HEADERS = {
    "Origin": "https://freshsimtracker.com",
    "Referer": "https://freshsimtracker.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
}


def is_valid_cnic(cnic: str) -> bool:
    """Validate CNIC: 13 digits, optionally with dashes."""
    cleaned = re.sub(r"\D", "", cnic or "")
    return len(cleaned) == 13


def parse_results(html: str):
    """Parse the results table from the response HTML."""
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
            "mobile": cells[0],
            "name": cells[1],
            "cnic": cells[2],
            "address": cells[3],
            "network": cells[4],
        })
    return results


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/search", methods=["POST", "GET"])
def search():
    # Accept both JSON and form data
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict() or request.args.to_dict()

    cnic = (data.get("numberCnic") or data.get("cnic") or "").strip()

    if not cnic:
        return jsonify({"success": False, "error": "CNIC is required."}), 400

    if not is_valid_cnic(cnic):
        return jsonify({
            "success": False,
            "error": "Invalid CNIC. Must be 13 digits (e.g., 4530448083059)."
        }), 400

    try:
        resp = requests.post(
            BASE_URL,
            headers=HEADERS,
            data={"numberCnic": cnic, "searchNumber": "search"},
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
            "results": [],
            "message": "No results found for this CNIC.",
        })

    return jsonify({
        "success": True,
        "count": len(results),
        "results": results,
    })


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
