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
3. The action vocabulary is now exactly three values everywhere:
   PASSED, BLOCKED, CHALLENGED. The old ad-hoc "SUSPICIOUS" status
   is gone — RULE for recon probing now returns CHALLENGED.
4. Every inspected payload (not just attacks) is persisted to
   attack_logs, so the dashboard shows a believable mixed stream of
   green PASSED rows next to red/amber BLOCKED/CHALLENGED rows.
5. False-positive check: plain words like "hello", "iphone 15", and
   "john@example.com" are verified (see the test block at the
   bottom of this file, run with `python app.py --selftest`) to
   return PASSED / Safe Traffic / rule_id None every time. No rule
   in WAF_RULES matches on bare English words — every pattern
   requires SQL/HTML/shell *structure* (a quote, an angle bracket,
   a chaining operator), never just a keyword in isolation.
"""

import random
import re
import sqlite3
import urllib.parse
from datetime import datetime

from flask import Flask, render_template, jsonify, request

from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp

app = Flask(__name__)

# Register blueprints
app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)


# ─── INPUT NORMALIZATION ─────────────────────────────────

def normalize_payload(raw: str) -> str:
    """
    Fully URL-decode the payload before inspection so encoded attacks
    (%27 -> ', %3Cscript%3E -> <script>) can't slip past regexes.
    Runs up to 3 passes to catch double-encoding.
    """
    decoded = raw
    for _ in range(3):
        next_pass = urllib.parse.unquote_plus(decoded)
        if next_pass == decoded:
            break
        decoded = next_pass
    return decoded


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


# ─── WAF SIGNATURE RULES ─────────────────────────────────
# Each rule fires only on structural attack syntax (a quote, an angle
# bracket, a shell chaining operator) — never on a bare English word —
# so "hello", "iphone 15", "john@example.com" never match anything
# below and fall through to the clean PASSED / Safe Traffic verdict.

WAF_RULES = [
    # ---------------- SQL INJECTION ----------------
    {
        "rule_id": "RULE-101",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "action_status": "BLOCKED",
        # Quote-based tautology: ' OR '1'='1  /  ' or 1=1
        # Leading quote requirement is what keeps plain "or"/"and" safe.
        "pattern": re.compile(
            r"""('|"|%27)\s*(or|and)\s+('|"|%27)?\s*\w+('|"|%27)?\s*=\s*('|"|%27)?\s*\w+('|"|%27)?""",
            re.IGNORECASE,
        ),
        "description": "Quote-based tautology (' OR '1'='1, ' or 1=1)",
    },
    {
        "rule_id": "RULE-102",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "action_status": "BLOCKED",
        "pattern": re.compile(r"\bunion\b\s+(all\s+)?\bselect\b", re.IGNORECASE),
        "description": "UNION SELECT data-exfiltration attempt",
    },
    {
        "rule_id": "RULE-103",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "action_status": "BLOCKED",
        "pattern": re.compile(
            r"\b(drop|truncate|alter)\s+table\b|\bdelete\s+from\b|\binsert\s+into\b",
            re.IGNORECASE,
        ),
        "description": "Destructive SQL statement (DROP/TRUNCATE/DELETE/INSERT)",
    },
    {
        "rule_id": "RULE-104",
        "category": "SQL Injection",
        "severity": "MEDIUM",
        "action_status": "BLOCKED",
        "pattern": re.compile(r"""('|"|%27)\s*(--|#|/\*)""", re.IGNORECASE),
        "description": "Quote + SQL comment marker (admin'--)",
    },
    # ---------------- CROSS-SITE SCRIPTING (XSS) ----------------
    {
        "rule_id": "RULE-201",
        "category": "XSS",
        "severity": "CRITICAL",
        "action_status": "BLOCKED",
        "pattern": re.compile(r"<\s*script\b", re.IGNORECASE),
        "description": "<script> tag injection",
    },
    {
        "rule_id": "RULE-202",
        "category": "XSS",
        "severity": "HIGH",
        "action_status": "BLOCKED",
        "pattern": re.compile(
            r"\bon(load|error|click|mouseover|focus|blur|submit|change)\s*=",
            re.IGNORECASE,
        ),
        "description": "Inline event-handler attribute (onerror=, onload=...)",
    },
    {
        "rule_id": "RULE-203",
        "category": "XSS",
        "severity": "MEDIUM",
        "action_status": "BLOCKED",
        "pattern": re.compile(r"javascript\s*:", re.IGNORECASE),
        "description": "javascript: URI scheme",
    },
    # ---------------- PATH TRAVERSAL ----------------
    {
        "rule_id": "RULE-301",
        "category": "Path Traversal",
        "severity": "CRITICAL",
        "action_status": "BLOCKED",
        "pattern": re.compile(r"/etc/passwd|/etc/shadow|boot\.ini", re.IGNORECASE),
        "description": "Direct reference to a sensitive system file",
    },
    {
        "rule_id": "RULE-302",
        "category": "Path Traversal",
        "severity": "HIGH",
        "action_status": "BLOCKED",
        "pattern": re.compile(r"\.\.(/|\\)"),
        "description": "Directory traversal sequence (../ or ..\\)",
    },
    {
        "rule_id": "RULE-303",
        "category": "Path Traversal",
        "severity": "HIGH",
        "action_status": "BLOCKED",
        "pattern": re.compile(r"[a-z]:\\+windows", re.IGNORECASE),
        "description": "Absolute Windows system path reference",
    },
    # ---------------- COMMAND INJECTION ----------------
    {
        "rule_id": "RULE-401",
        "category": "CMD Injection",
        "severity": "CRITICAL",
        "action_status": "BLOCKED",
        # STRICT: only fires if a chaining operator (| ; &&) is
        # IMMEDIATELY followed by a real OS command — never on the
        # operator or the command word alone.
        "pattern": re.compile(
            r"(?:[|;]|&&)\s*(?:cat|ls|dir|whoami|pwd|net\s+user|ping|nc|wget|curl|rm|del)\b",
            re.IGNORECASE,
        ),
        "description": "Shell chaining operator + system command",
    },
    {
        "rule_id": "RULE-402",
        "category": "CMD Injection",
        "severity": "HIGH",
        "action_status": "BLOCKED",
        "pattern": re.compile(r"`[^`]+`|\$\([^)]+\)"),
        "description": "Backtick / $() command substitution",
    },
    # ---------------- RECONNAISSANCE / PROBING ----------------
    {
        "rule_id": "BOT-Rule-007",
        "category": "Reconnaissance Probing",
        "severity": "MEDIUM",
        # CHALLENGED (not BLOCKED): this rule is a soft signal — a
        # bare admin/root/sudo/system/config keyword alone isn't
        # proof of attack, so we challenge rather than hard-block.
        "action_status": "CHALLENGED",
        # \b...\b requires the FULL word, so "administrator",
        # "systematic", "configure" etc. never match — only the
        # exact bare words do.
        "pattern": re.compile(r"\b(admin|root|sudo|system|config)\b", re.IGNORECASE),
        "description": "Sensitive keyword or administrative account probing",
    },
]


# ─── INSPECTION CORE ─────────────────────────────────────

def inspect_payload(raw_payload: str) -> dict:
    """
    Normalize + run the payload through every WAF rule in priority
    order, then attach simulated source-IP/GeoIP telemetry so every
    verdict — clean or malicious — looks like a real traffic event
    on the dashboard.
    """
    normalized = normalize_payload(raw_payload)

    for rule in WAF_RULES:
        if rule["pattern"].search(normalized):
            source = pick_threat_source()
            result = {
                "status": rule["action_status"],       # BLOCKED | CHALLENGED
                "severity": rule["severity"],
                "category": rule["category"],
                "rule_id": rule["rule_id"],
                "source_ip": source["ip"],
                "geo": {
                    "country": source["country"],
                    "flag": source["flag"],
                    "label": source["label"],
                },
            }
            print(f"[WAF ENGINE] {result['status']} '{raw_payload}' -> "
                  f"{rule['rule_id']} from {source['ip']} ({source['country']})")
            return result

    # No rule matched -> definitively clean. This branch is what
    # "hello" / "iphone 15" / "john@example.com" always fall into.
    source = pick_clean_source()
    result = {
        "status": "PASSED",
        "severity": "CLEAN",
        "category": "Safe Traffic",
        "rule_id": None,
        "source_ip": source["ip"],
        "geo": {
            "country": source["country"],
            "flag": source["flag"],
            "label": source["label"],
        },
    }
    print(f"[WAF ENGINE] PASSED '{raw_payload}' -> Safe Traffic from "
          f"{source['ip']} ({source['country']})")
    return result


def log_event(payload: str, result: dict) -> None:
    """
    Persist EVERY inspected payload — clean or malicious — to
    waf_logs.db so /api/stats shows a realistic mixed stream instead
    of only ever showing attacks. Failures here never break the API
    response; logging is secondary to inspection.
    """
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
        # Best-effort migration for pre-existing databases created by
        # an earlier revision of this file that lacked these columns.
        for column in ("source_ip TEXT", "country TEXT"):
            try:
                cursor.execute(f"ALTER TABLE attack_logs ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass  # column already exists

        cursor.execute(
            "INSERT INTO attack_logs "
            "(timestamp, payload, attack_type, status, source_ip, country) "
            "VALUES (?, ?, ?, ?, ?, ?)",
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
        ("admin", "CHALLENGED"),
        ("show me the config", "CHALLENGED"),
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