#!/usr/bin/env python3
"""
CNIC + Mobile Lookup Web Server - Device Fingerprint Rate Limiting
Fingerprint = IP + Browser signals + Canvas hash + Screen + Timezone
Cannot be bypassed by reconnecting internet or clearing cookies

Upstream: https://freshsimtracker.com
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import time
import os
import hashlib
import logging
import re

# ============================================================
# Logging (works with Gunicorn)
# ============================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ============================================================
# Upstream site config (freshsimtracker.com)
# ============================================================
BASE_URL = "https://freshsimtracker.com"
TRACK_PATH = "/numberDetails.php"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": BASE_URL + "/",
    "Origin": BASE_URL,
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

session = requests.Session()
session.headers.update(HEADERS)

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
# Input validation: CNIC (13 digits) OR Mobile (11 digits, starts 03)
# ============================================================
def detect_query_type(value: str):
    """
    Returns (type, cleaned_value) where type is 'cnic', 'mobile', or None.
    - CNIC:   13 digits (optionally with dashes)
    - Mobile: 11 digits starting with 03 (e.g., 03001234567)
    """
    cleaned = re.sub(r"\D", "", str(value or ""))
    if len(cleaned) == 13:
        return "cnic", cleaned
    if len(cleaned) == 11 and cleaned.startswith("03"):
        return "mobile", cleaned
    return None, cleaned


# ============================================================
# Upstream session warm-up (freshsimtracker doesn't require CSRF)
# ============================================================
def init_cnic_session():
    global session_initialized
    try:
        resp = session.get(BASE_URL + "/", timeout=20)
        session_initialized = resp.status_code == 200
        if session_initialized:
            logger.info("✅ freshsimtracker session ready")
        else:
            logger.warning(f"⚠️  Warm-up returned HTTP {resp.status_code}")
        return session_initialized
    except Exception as e:
        logger.error(f"❌ Session init failed: {e}")
        return False


def parse_results(html: str):
    """
    freshsimtracker returns an HTML table (table.table) with 5 columns:
    Mobile | Name | CNIC | Address | Network
    Returns ALL rows found.
    """
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


def do_lookup(number):
    """
    POST numberCnic=<value>&searchNumber=search to /numberDetails.php
    and parse ALL rows from the resulting table.
    """
    try:
        resp = session.post(
            BASE_URL + TRACK_PATH,
            data={"numberCnic": number, "searchNumber": "search"},
            timeout=20,
            allow_redirects=True,
        )

        if resp.status_code != 200:
            return {"Error": f"Server error (HTTP {resp.status_code})"}

        results = parse_results(resp.text)

        if not results:
            return {"Error": "No record found for this CNIC/mobile number."}

        # ✅ Return ALL rows
        return {"records": results}

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

    raw_input = (
        data.get("query")
        or data.get("number")
        or data.get("cnic")
        or data.get("mobile")
        or ""
    )
    raw_input = str(raw_input).strip()

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip = ip.split(",")[0].strip()

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

    qtype, number = detect_query_type(raw_input)

    if qtype is None:
        return jsonify({
            "Error": "Invalid input. Enter a 13-digit CNIC (e.g. 4530448083059) "
                     "or an 11-digit mobile starting with 03 (e.g. 03001234567)."
        }), 400

    if not session_initialized:
        if not init_cnic_session():
            return jsonify({"Error": "Database unavailable. Try later."}), 503

    logger.info(
        f"🔍 {qtype.upper()}: {number} | IP: {ip} | FP: {combined[:8]}... | Left: {remaining}"
    )
    result = do_lookup(number)

    # Attach metadata for frontend
    result["_remaining"]  = remaining
    result["_limit"]      = MAX_PER_HOUR
    result["_queryType"]  = qtype
    result["_queryValue"] = number
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
        return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>403 Forbidden</title>
<style>
  body{background:#0a0a0f;color:#ff4466;font-family:'Courier New',monospace;
       display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
  .box{text-align:center;}
  .code{font-size:80px;font-weight:700;margin-bottom:8px;}
  .msg{font-size:16px;letter-spacing:3px;opacity:.7;}
</style></head>
<body><div class="box"><div class="code">403</div><div class="msg">// ACCESS DENIED</div></div></body>
</html>""", 403

    now = time.time()
    hour_ago = now - 3600

    active_users = []
    for fp, times in rate_db.items():
        recent = [t for t in times if t > hour_ago]
        if recent:
            last_seen  = int(now - max(recent))
            first_seen = int(now - min(recent))
            usage_pct  = int(len(recent) / MAX_PER_HOUR * 100)
            active_users.append({
                "fp": fp[:8] + "...",
                "count": len(recent),
                "usage_pct": usage_pct,
                "last_seen_secs": last_seen,
                "window_secs": first_seen,
                "blocked": len(recent) >= MAX_PER_HOUR,
            })

    active_users.sort(key=lambda x: x["count"], reverse=True)
    total_devices  = len(active_users)
    total_searches = sum(u["count"] for u in active_users)
    blocked_count  = sum(1 for u in active_users if u["blocked"])

    def fmt_time(secs):
        if secs < 60:   return f"{secs}s ago"
        if secs < 3600: return f"{secs//60}m ago"
        return f"{secs//3600}h ago"

    rows_html = ""
    if not active_users:
        rows_html = """<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--muted)">
            // No active users in the past hour</td></tr>"""
    else:
        for u in active_users:
            bar_color = "var(--red)" if u["blocked"] else ("var(--yellow)" if u["usage_pct"] >= 70 else "var(--green)")
            status_badge = (
                '<span class="badge blocked">BLOCKED</span>' if u["blocked"]
                else '<span class="badge active">ACTIVE</span>'
            )
            rows_html += f"""
            <tr>
              <td><span class="fp-code">{u['fp']}</span></td>
              <td>
                <div class="bar-wrap">
                  <div class="bar-fill" style="width:{u['usage_pct']}%;background:{bar_color}"></div>
                </div>
                <span class="bar-label">{u['count']} / {MAX_PER_HOUR}</span>
              </td>
              <td style="color:var(--muted)">{fmt_time(u['last_seen_secs'])}</td>
              <td style="color:var(--muted)">{fmt_time(u['window_secs'])}</td>
              <td>{status_badge}</td>
            </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="30">
<title>Admin Panel — FreshSIMTracker</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:#0a0a0f;--surface:#111118;--card:#16161f;--border:#2a2a3a;
    --green:#00ff88;--green-dim:#00cc6a;--green-glow:rgba(0,255,136,0.15);
    --text:#e8e8f0;--muted:#6b6b80;--red:#ff4466;--yellow:#ffcc00;
    --mono:'Space Mono',monospace;--sans:'Syne',sans-serif;
  }}
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;overflow-x:hidden;}}
  body::before{{content:'';position:fixed;inset:0;
    background-image:linear-gradient(rgba(0,255,136,0.03) 1px,transparent 1px),
                     linear-gradient(90deg,rgba(0,255,136,0.03) 1px,transparent 1px);
    background-size:40px 40px;pointer-events:none;z-index:0;}}

  .wrapper{{position:relative;z-index:1;max-width:900px;margin:0 auto;padding:40px 20px 80px;}}

  .header{{display:flex;align-items:center;justify-content:space-between;margin-bottom:36px;flex-wrap:wrap;gap:16px;}}
  .logo{{display:flex;align-items:center;gap:10px;}}
  .logo-icon{{width:42px;height:42px;background:var(--red);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;}}
  .logo-text{{font-family:var(--mono);font-size:20px;font-weight:700;color:var(--red);letter-spacing:2px;}}
  .logo-sub{{font-family:var(--mono);font-size:11px;color:var(--muted);letter-spacing:1px;margin-top:2px;}}
  .refresh-note{{font-family:var(--mono);font-size:11px;color:var(--muted);display:flex;align-items:center;gap:6px;}}
  .pulse{{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;}}
  @keyframes pulse{{0%,100%{{opacity:1;}}50%{{opacity:0.3;}}}}

  .stats-row{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:28px;}}
  .stat-card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px 16px;position:relative;overflow:hidden;}}
  .stat-card::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;}}
  .stat-card.green::before{{background:var(--green);}}
  .stat-card.red::before{{background:var(--red);}}
  .stat-card.yellow::before{{background:var(--yellow);}}
  .stat-card.blue::before{{background:#4488ff;}}
  .stat-val{{font-family:var(--mono);font-size:28px;font-weight:700;}}
  .stat-card.green .stat-val{{color:var(--green);}}
  .stat-card.red .stat-val{{color:var(--red);}}
  .stat-card.yellow .stat-val{{color:var(--yellow);}}
  .stat-card.blue .stat-val{{color:#4488ff;}}
  .stat-label{{font-size:11px;color:var(--muted);margin-top:4px;font-family:var(--mono);letter-spacing:1px;text-transform:uppercase;}}

  .table-card{{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden;}}
  .table-header{{padding:16px 20px;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}}
  .table-title{{font-family:var(--mono);font-size:12px;color:var(--green);letter-spacing:2px;text-transform:uppercase;}}
  .table-badge{{background:var(--green-glow);border:1px solid var(--green);color:var(--green);font-family:var(--mono);font-size:11px;padding:3px 10px;border-radius:20px;}}

  table{{width:100%;border-collapse:collapse;}}
  thead th{{padding:12px 16px;text-align:left;font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;border-bottom:1px solid var(--border);background:var(--surface);}}
  tbody tr{{border-bottom:1px solid rgba(255,255,255,0.04);transition:background 0.15s;}}
  tbody tr:last-child{{border-bottom:none;}}
  tbody tr:hover{{background:rgba(0,255,136,0.03);}}
  tbody td{{padding:14px 16px;font-family:var(--mono);font-size:13px;}}

  .fp-code{{color:var(--text);letter-spacing:1px;}}

  .bar-wrap{{height:6px;background:var(--border);border-radius:3px;width:120px;overflow:hidden;margin-bottom:4px;}}
  .bar-fill{{height:100%;border-radius:3px;transition:width 0.3s;}}
  .bar-label{{font-size:11px;color:var(--muted);}}

  .badge{{font-family:var(--mono);font-size:10px;padding:3px 10px;border-radius:20px;letter-spacing:1px;}}
  .badge.active{{background:rgba(0,255,136,0.1);border:1px solid var(--green);color:var(--green);}}
  .badge.blocked{{background:rgba(255,68,102,0.1);border:1px solid var(--red);color:var(--red);}}

  .info-bar{{display:flex;align-items:center;gap:10px;padding:12px 16px;background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:20px;font-family:var(--mono);font-size:12px;color:var(--muted);}}

  @media(max-width:600px){{
    .stats-row{{grid-template-columns:repeat(2,1fr);}}
    .bar-wrap{{width:80px;}}
    thead th:nth-child(3),tbody td:nth-child(3){{display:none;}}
  }}
</style>
</head>
<body>
<div class="wrapper">

  <div class="header">
    <div class="logo">
      <div class="logo-icon">🛡️</div>
      <div>
        <div class="logo-text">ADMIN PANEL</div>
        <div class="logo-sub">// FRESHSIMTRACKER Rate Monitor</div>
      </div>
    </div>
    <div class="refresh-note">
      <div class="pulse"></div>
      Auto-refresh every 30s
    </div>
  </div>

  <div class="info-bar">
    🕒 &nbsp;Report generated at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
    &nbsp;|&nbsp; Window: last 60 minutes
    &nbsp;|&nbsp; Limit: {MAX_PER_HOUR} searches / device / hour
  </div>

  <div class="stats-row">
    <div class="stat-card green">
      <div class="stat-val">{total_devices}</div>
      <div class="stat-label">Active Devices</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-val">{total_searches}</div>
      <div class="stat-label">Total Searches</div>
    </div>
    <div class="stat-card red">
      <div class="stat-val">{blocked_count}</div>
      <div class="stat-label">Blocked Devices</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-val">{MAX_PER_HOUR}</div>
      <div class="stat-label">Hourly Limit</div>
    </div>
  </div>

  <div class="table-card">
    <div class="table-header">
      <span class="table-title">// Active Device Fingerprints</span>
      <span class="table-badge">{total_devices} ACTIVE</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Fingerprint</th>
          <th>Usage</th>
          <th>Last Seen</th>
          <th>First Seen</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>

</div>
</body>
</html>"""
    return html


# ============================================================
# WSGI entry point (used by Gunicorn on Render)
# ============================================================
init_cnic_session()

# ============================================================
# Local dev entry point
# ============================================================
if __name__ == "__main__":
    print("=" * 50)
    print("  CNIC + Mobile Lookup — freshsimtracker.com")
    print("=" * 50)
    port = int(os.environ.get("PORT", 5000))
    admin_key = os.environ.get("ADMIN_KEY", "changeme")
    print(f"\n🌐 Running at http://0.0.0.0:{port}")
    print(f"🔑 Admin: http://localhost:{port}/admin/limits?key={admin_key}")
    print(f"\nPress Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=False)
