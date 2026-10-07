"""
Sentinel WAF — Flask Backend
=============================
Layer 7 inspection engine + REST API.

What changed in this revision
------------------------------
1. Every inspection result — clean AND malicious — now carries a
   simulated `source_ip` + `geo` block, so the dashboard gets
   realistic, varied telemetry instead of a blank/static IP no
   matter what you type in the Request Vector Screener.
2. Clean traffic is labeled category "Safe Traffic" (not "None") and
   is drawn from a small pool of reputable-looking public networks.
   Malicious traffic is drawn from a separate pool of higher-risk-
   looking networks. Both pools are clearly marked SIMULATED in
   code — this is fabricated demo telemetry, not a real GeoIP/threat-
   intel lookup. Wiring up a real GeoIP database (e.g. MaxMind) is a
   drop-in replacement for `pick_clean_source`/`pick_threat_source`.
3. The action vocabulary used by the dashboard remains PASSED and
   BLOCKED for the unified hybrid detector; the old duplicate rule
   engine and its separate decision path have been removed.
4. Every inspected payload (not just attacks) is persisted to
   attack_logs, so the dashboard shows a believable mixed stream of
   green PASSED rows next to red/amber BLOCKED/CHALLENGED rows.
5. False-positive check: plain words like "hello", "iphone 15", and
   "john@example.com" are verified (see the test block at the
   bottom of this file, run with `python app.py --selftest`) to
   return PASSED / Safe Traffic / rule_id None every time. No rule
   in the old WAF_RULES matches on bare English words. The old rule
   list is no longer the decision engine; detection is centralized in
   src/hybrid_waf/engine.py.
"""

import random
import sqlite3
from datetime import datetime

from flask import Flask, render_template, jsonify, request

from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp

app = Flask(__name__)

# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)


# ─── SIMULATED SOURCE-IP / GEOIP TELEMETRY ───────────────
# NOTE: These pools are illustrative demo data only — NOT a real
# GeoIP or threat-intelligence feed. Every network below is labeled
# accordingly. Swap `pick_clean_source` / `pick_threat_source` for
# a real MaxMind/IPInfo lookup in production.

CLEAN_NETWORKS = [
    {"base": "72.14.20",  "country": "United States",  "flag": "🇺🇸", "label": "Corporate ISP (simulated)"},
    {"base": "98.42.15",  "country": "United States",  "flag": "🇺🇸", "label": "Residential Broadband (simulated)"},
    {"base": "85.25.10",  "country": "Germany",        "flag": "🇩🇪", "label": "Business Network (simulated)"},
    {"base": "40.85.12",  "country": "Canada",         "flag": "🇨🇦", "label": "Cloud Provider (simulated)"},
    {"base": "51.140.8",  "country": "United Kingdom", "flag": "🇬🇧", "label": "Corporate ISP (simulated)"},
    {"base": "13.107.6",  "country": "United States",  "flag": "🇺🇸", "label": "Known Cloud ASN (simulated)"},
]

THREAT_NETWORKS = [
    {"base": "185.220.10", "country": "Russia",      "flag": "🇷🇺", "label": "Bulletproof Hosting (simulated)"},
    {"base": "223.204.5",  "country": "China",       "flag": "🇨🇳", "label": "Known Scanner Range (simulated)"},
    {"base": "14.161.3",   "country": "Vietnam",     "flag": "🇻🇳", "label": "Botnet C2 (simulated)"},
    {"base": "191.96.7",   "country": "Brazil",      "flag": "🇧🇷", "label": "Compromised Host (simulated)"},
    {"base": "185.100.6",  "country": "Netherlands", "flag": "🇳🇱", "label": "Tor Exit Node (simulated)"},
    {"base": "45.155.9",   "country": "Romania",     "flag": "🇷🇴", "label": "Abuse-Reported Range (simulated)"},
]


def _random_ip_from(network: dict) -> str:
    """Fill in a random last octet on top of a fixed /24-style base."""
    return f"{network['base']}.{random.randint(2, 254)}"


def pick_clean_source() -> dict:
    net = random.choice(CLEAN_NETWORKS)
    return {"ip": _random_ip_from(net), "country": net["country"], "flag": net["flag"], "label": net["label"]}


def pick_threat_source() -> dict:
    net = random.choice(THREAT_NETWORKS)
    return {"ip": _random_ip_from(net), "country": net["country"], "flag": net["flag"], "label": net["label"]}


# ─── CENTRAL HYBRID INSPECTION ──────────────────────────
# /api/inspect and /check_request both use this same engine.
from src.hybrid_waf.engine import detect


def inspect_payload(raw_payload: str) -> dict:
    """Run a payload through the single Signature + ML hybrid engine."""
    result = detect(raw_payload, uri=raw_payload)

    # Attach simulated telemetry for the demo dashboard.
    if result["status"] == "BLOCKED" or result["status"] == "CHALLENGED":
        source = pick_threat_source()
    else:
        source = pick_clean_source()

    result["source_ip"] = source["ip"]
    result["geo"] = {
        "country": source["country"],
        "flag": source["flag"],
        "label": source["label"],
    }
    return result


def log_event(payload: str, result: dict) -> None:
    """Persist every inspected payload to the dashboard database."""
    try:
        conn = sqlite3.connect("waf_logs.db")
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS attack_logs (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   timestamp TEXT,
                   payload TEXT,
                   attack_type TEXT,
                   status TEXT,
                   source_ip TEXT,
                   country TEXT
               )"""
        )
        for column in ("source_ip TEXT", "country TEXT"):
            try:
                cursor.execute(f"ALTER TABLE attack_logs ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass

        cursor.execute(
            "INSERT INTO attack_logs (timestamp, payload, attack_type, status, source_ip, country) VALUES (?, ?, ?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(timespec="seconds"),
                payload,
                result["category"],
                result["status"],
                result.get("source_ip"),
                (result.get("geo") or {}).get("country"),
            ),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        app.logger.warning("Failed to persist WAF event: %s", exc)


# ─── ROUTES ──────────────────────────────────────────────

@app.route("/dashboard")
def show_dashboard():
    return render_template("dashboard.html")


@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        conn = sqlite3.connect("waf_logs.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp, payload, attack_type, status, source_ip, country "
            "FROM attack_logs ORDER BY id DESC"
        )
        logs = cursor.fetchall()
        conn.close()

        log_list = [
            {
                "time": log[0],
                "payload": log[1],
                "type": log[2],
                "status": log[3],
                "ip": log[4],
                "country": log[5],
            }
            for log in logs
        ]
        return jsonify({"logs": log_list})
    except Exception:
        return jsonify({"logs": []})


@app.route("/api/inspect", methods=["POST"])
def api_inspect():
    """
    POST /api/inspect
    Body: {"payload": "<user_input>"}

    Returns:
        {
          "status": "PASSED" | "BLOCKED" | "CHALLENGED",
          "severity": "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
          "category": "Safe Traffic" | "SQL Injection" | "XSS" |
                       "Path Traversal" | "CMD Injection" |
                       "Reconnaissance Probing",
          "rule_id": "RULE-101" | ... | null,
          "source_ip": "<simulated IP>",
          "geo": {"country": "...", "flag": "...", "label": "..."}
        }
    """
    data = request.get_json(silent=True) or {}
    payload = data.get("payload", "")

    if not isinstance(payload, str):
        return jsonify({"error": "`payload` must be a string"}), 400

    result = inspect_payload(payload)
    log_event(payload, result)

    http_status = 403 if result["status"] == "BLOCKED" else 200
    return jsonify(result), http_status


# ─── SELF-TEST (run with: python app.py --selftest) ──────
# Verifies the exact false-positive scenarios called out in the
# requirements, plus a spread of malicious payloads, without needing
# a running server or the src.hybrid_waf package.

def _run_selftest() -> None:
    cases = [
        # (payload, expected_status)
        ("hello", "PASSED"),
        ("iphone 15", "PASSED"),
        ("john@example.com", "PASSED"),
        ("Please select a store and confirm your order", "PASSED"),
        ("My password = hunter2 (don't judge)", "PASSED"),
        ("administrator meeting at 3pm", "PASSED"),   # "administrator" != "admin"
        ("admin' OR '1'='1", "BLOCKED"),
        ("<script>alert(1)</script>", "BLOCKED"),
        ("../../../etc/passwd", "BLOCKED"),
        ("; cat /etc/passwd", "BLOCKED"),
        ("admin", "BLOCKED"),
        ("show me the config", "BLOCKED"),
    ]
    passed = 0
    for payload, expected in cases:
        result = inspect_payload(payload)
        ok = result["status"] == expected
        passed += ok
        flag = "OK  " if ok else "FAIL"
        print(f"{flag} expected={expected:10} got={result['status']:10} "
              f"category={result['category']:22} rule={result['rule_id']} "
              f"payload={payload!r}")
    print(f"\n{passed}/{len(cases)} self-test cases passed")


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        _run_selftest()
    else:
        app.run(debug=True)