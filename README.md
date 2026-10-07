# 🛡️ SentinelWAF

**Hybrid Signature + Machine Learning Web Application Firewall**  
**Status:** Working Educational Prototype · Cybersecurity · 2026

> SentinelWAF is a Flask-based Web Application Firewall prototype that combines **signature-based detection** with a **second-stage ML detector** for suspicious or obfuscated requests. Manual requests and simulated attack traffic use the same central detection pipeline.

---

## ⚠️ Disclaimer

**Educational and authorized testing only.**

SentinelWAF was developed as a cybersecurity training/project prototype. Use it only with applications, requests, and systems that you own or are explicitly authorized to test. Do not use the attack examples in this project against third-party systems without permission.

The IP addresses, countries, and network labels displayed by the dashboard are **simulated demo telemetry**. They are not real GeoIP or threat-intelligence results.

---

## 📌 What SentinelWAF Does

A Web Application Firewall inspects web traffic before it reaches an application and can block requests that match known attack patterns.

SentinelWAF demonstrates a **hybrid detection approach**:

1. **Normalize the request** so common URL-encoded or repeatedly encoded payloads can be inspected.
2. **Signature detection** checks the normalized request against known malicious and suspicious patterns.
3. If a known malicious pattern is found, the request is **blocked immediately**.
4. If the signature layer considers the request **obfuscated/suspicious**, SentinelWAF extracts security features and sends them to the **ML model**.
5. The ML model provides the second-stage decision for that suspicious request.
6. The result is returned to the UI and, for the dashboard inspection API, stored in SQLite telemetry.

### The important architectural point

There is **one central detection engine** in:

```text
src/hybrid_waf/engine.py
```

Both major dashboard request sources use that same engine:

```text
Manual Intercept ──────┐
                       │
Attack Stress Test ────┼──> /api/inspect ──> engine.detect()
                       │                         │
                       │                         ├── Signature
                       │                         │      │
                       │                         │      ├── malicious → BLOCKED
                       │                         │      └── obfuscated → ML
                       │                         │                         │
                       │                         │                    BLOCKED/PASSED
                       │                         │
                       │                         └── valid → PASSED
                       │
                       └───────────────────────────────────────────────
```

The older `/check_request` endpoint also calls the **same `engine.detect()` function**. It keeps its original response format so the existing request-checker page can continue to work.

**The routes are not calling each other over HTTP.** They reuse the same Python detection function. This avoids maintaining two separate detection engines.

---

## 🧠 Detection Architecture

### Stage 1 — Signature Detection

Implemented in:

```text
src/hybrid_waf/utils/signature_checker.py
```

The signature checker looks for known attack or obfuscation patterns. Examples include:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal / file-inclusion style payloads
- Reconnaissance/probing patterns
- URL/encoding and other obfuscation indicators
- Existing project-specific malicious patterns such as HTML/CSRF/SSRF-related signatures

Known malicious traffic can be blocked without involving the ML model.

### Stage 2 — ML Detection

Suspicious/obfuscated traffic is passed to:

```text
src/hybrid_waf/utils/preprocessor.py
src/hybrid_waf/utils/ml_checker.py
src/hybrid_waf/models/ml_model.pkl
```

The preprocessor extracts request-level features such as:

1. URI length
2. GET-data length
3. POST-data length
4. URI Shannon entropy
5. GET-data Shannon entropy
6. POST-data Shannon entropy
7. Numeric-to-text ratio
8. Special-character count

The trained classifier then predicts whether the suspicious request should be treated as malicious.

### ML is NOT run for every request

This is intentional.

```text
Normal request
     ↓
Signature check
     ↓
Valid → PASSED
```

```text
Suspicious / obfuscated request
     ↓
Signature check
     ↓
ML feature extraction
     ↓
ML prediction
     ↓
BLOCKED or PASSED
```

This keeps the signature layer fast for ordinary traffic while giving suspicious traffic a second layer of analysis.

---

## 🔄 Request Sources

### 1. Manual Intercept

The user enters a request/payload manually in the dashboard and submits it.

The frontend sends the payload to:

```text
POST /api/inspect
```

The endpoint passes it to the shared hybrid engine.

### 2. Attack Stress Test

The dashboard contains predefined demonstration payloads representing common attack classes such as:

- SQL Injection
- XSS
- Path Traversal
- Command Injection

These are **simulated test inputs**. They are not attacks being launched against an external target.

The stress-test button sends each test payload through the same:

```text
/api/inspect → engine.detect()
```

pipeline used by Manual Intercept.

### 3. Request Checker / `/check_request`

The older request-checker flow uses:

```text
POST /check_request
```

This endpoint also calls:

```text
engine.detect()
```

It converts the common engine result into the response format expected by the existing frontend.

Therefore, the **detection logic is shared**, while the **response formatting is route-specific for frontend compatibility**.

---

## 🧩 Main Components

### `engine.py`

Central hybrid decision pipeline.

Responsibilities:

- Normalize the input
- Call `check_signature()`
- Block known malicious signatures
- Send obfuscated/suspicious requests to the ML stage
- Produce a common result containing status, category, severity, rule ID, detection stage, and ML information when applicable

### `signature_checker.py`

Contains the actual signature/regex detection logic.

This is the authoritative first-stage detector.

### `preprocessor.py`

Extracts the numerical features required by the ML model.

### `ml_checker.py`

Loads the trained model with `joblib` and performs the second-stage prediction.

### `ml_model.pkl`

The trained classifier used for suspicious/obfuscated traffic.

### `app.py`

Creates the Flask application and provides the main dashboard inspection API and telemetry endpoints.

Important routes:

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Main SentinelWAF interface |
| `/home` | GET | Existing home route |
| `/dashboard` | GET | Threat dashboard |
| `/api/inspect` | POST | Main unified inspection API used by the dashboard |
| `/api/stats` | GET | Returns stored dashboard telemetry |
| `/check_request` | POST | Compatibility/request-checker endpoint using the same engine |
| `/logs` | GET | Redirects to the dashboard |

### `routes/main.py`

Contains the main page routes and the legacy database helper.

### `routes/proxy.py`

Contains `/check_request`. It does **not** contain a separate detection engine; it delegates detection to `engine.detect()`.

### `database.py`

Initializes the SQLite `attack_logs` table.

### `waf_logs.db`

SQLite database used by the dashboard telemetry flow.

### `logs/detections.log`

Text log used by the WAF logging layer.

---

## 📁 Project Structure

```text
SentinelWAF/
│
├── app.py                         # Flask application + unified inspection API
├── database.py                    # SQLite database initialization
├── requirements.txt               # Python dependencies
├── README.md                      # Project documentation
│
├── src/
│   └── hybrid_waf/
│       ├── __init__.py
│       ├── engine.py              # CENTRAL hybrid Signature + ML pipeline
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   └── ml_model.pkl       # Trained ML classifier
│       │
│       ├── routes/
│       │   ├── __init__.py
│       │   ├── main.py            # Page routes
│       │   └── proxy.py           # /check_request compatibility route
│       │
│       └── utils/
│           ├── __init__.py
│           ├── signature_checker.py # Stage 1 signatures
│           ├── preprocessor.py      # ML feature extraction
│           └── ml_checker.py        # Stage 2 ML prediction
│
├── templates/
│   ├── index.html                # Main dashboard / inspection UI
│   ├── home.html                 # Legacy request-checker template
│   └── dashboard.html            # Threat dashboard page
│
├── static/
│   ├── styles.css
│   ├── script.js
│   └── home.js
│
├── logs/
│   └── detections.log
│
├── output-screenshots/
│   └── ...                       # Project screenshots
│
└── waf_logs.db                   # SQLite telemetry database
```

---

## 🚀 Installation

### Requirements

- Python 3.10 or newer
- pip
- A virtual environment is recommended
- Windows PowerShell, Command Prompt, Linux, or macOS terminal

### 1. Clone the repository

```bash
git clone https://github.com/khushisharma20101-design/Sentinel-WAF.git
cd SentinelWAF
```

If the downloaded project folder has a different name, simply `cd` into that folder.

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

The project uses Flask, NumPy/SciPy, scikit-learn, LightGBM, and joblib for the application and ML pipeline.

### 4. Initialize the database

```bash
python database.py
```

This creates `waf_logs.db` and the `attack_logs` table if it does not already exist.

> `app.py` also ensures the required telemetry table/columns exist when it logs an inspection, so database initialization is mainly a convenient first-time setup step.

### 5. Start SentinelWAF

```bash
python app.py
```

Open:

```text
http://localhost:5000/
```

Dashboard:

```text
http://localhost:5000/dashboard
```

---

## 🧪 Testing the Detection Engine

### Quick manual examples

Try clean inputs:

```text
hello
iphone 15
john@example.com
```

Expected result:

```text
PASSED
```

Try known malicious examples in the authorized local demo:

```text
admin' OR '1'='1
<script>alert(1)</script>
../../../etc/passwd
; cat /etc/passwd
```

These should be detected by the signature stage and return **BLOCKED**.

A suspicious/obfuscated payload may be routed to the ML stage. In that case the result can show:

```text
Detection Stage: ML
ML Used: true
```

The exact ML verdict depends on the bundled trained model.

### Built-in self-test

The project contains a small backend self-test in `app.py`.

Run:

```bash
python app.py --selftest
```

It checks clean traffic and representative malicious payloads, including SQLi, XSS, path traversal, command injection, and reconnaissance-style inputs.

---

## 🖥️ Dashboard Features

The main SentinelWAF interface provides a visual security-monitoring experience including:

- Manual request inspection
- Attack Stress Test demonstration
- Detection status and severity
- Attack category classification
- Rule ID display
- Detection-stage information
- Simulated source IP and country telemetry
- Live threat/traffic tables
- Attack statistics and charts
- Network Matrix UI
- Log Inspector UI
- Client-side CSV/JSON export options for supported dashboard data

Some dashboard controls are **prototype/demo controls** rather than real network enforcement mechanisms. For example, the displayed IP/geolocation data is simulated and the Network Matrix is a UI demonstration rather than a production firewall rule system.

---

## 🌐 Simulated Network Telemetry

For demonstration purposes, SentinelWAF attaches a simulated source IP and country to inspection results.

Example concept:

```text
Request
   ↓
Hybrid Detection
   ↓
PASSED / BLOCKED
   ↓
Simulated source IP + country
   ↓
Dashboard telemetry
```

This should **not** be described as real GeoIP detection.

A production deployment could replace the simulated source-selection functions with a real GeoIP/threat-intelligence service.

---

## 💾 Logging and Telemetry

The `/api/inspect` flow records inspected traffic in `waf_logs.db`.

The dashboard reads this information through:

```text
GET /api/stats
```

The stored information includes fields such as:

- Timestamp
- Payload
- Attack category
- Status
- Simulated source IP
- Country

The text logging layer also writes detection information to:

```text
logs/detections.log
```

---

## 🔐 Example Detection Flow

### Known SQL Injection

```text
User enters payload
        ↓
POST /api/inspect
        ↓
engine.detect()
        ↓
Normalize input
        ↓
check_signature()
        ↓
SQLi signature matched
        ↓
BLOCKED
        ↓
Log result
        ↓
Dashboard
```

### Obfuscated/Suspicious Request

```text
User enters suspicious payload
        ↓
POST /api/inspect
        ↓
engine.detect()
        ↓
Normalize input
        ↓
check_signature()
        ↓
Obfuscated / suspicious
        ↓
extract_features()
        ↓
ML model prediction
        ↓
BLOCKED or PASSED
        ↓
Dashboard / logging
```

### Clean Request

```text
Normal request
     ↓
engine.detect()
     ↓
Signature check
     ↓
No malicious signature
     ↓
PASSED
```

---

## 🧩 API Examples

### `/api/inspect`

Request:

```http
POST /api/inspect
Content-Type: application/json
```

```json
{
  "payload": "<script>alert(1)</script>"
}
```

A blocked response contains fields such as:

```json
{
  "status": "BLOCKED",
  "severity": "HIGH",
  "category": "XSS",
  "rule_id": "XSS-002",
  "detection_stage": "SIGNATURE",
  "ml_used": false
}
```

The exact telemetry values can vary because source IP/country data is simulated.

### `/check_request`

Request:

```http
POST /check_request
Content-Type: application/json
```

```json
{
  "user_request": "admin' OR '1'='1"
}
```

This endpoint uses the same `engine.detect()` pipeline but returns the legacy response format expected by the request-checker frontend.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Core implementation |
| Flask | Web application and HTTP APIs |
| Regular Expressions | Signature-based attack detection |
| scikit-learn / LightGBM | ML model support |
| joblib | Loading the trained model |
| NumPy / SciPy | ML/scientific dependencies |
| SQLite | Persistent inspection telemetry |
| HTML/CSS/JavaScript | Frontend and dashboard |
| Chart.js | Dashboard charts |

---

## 📊 Detection Categories

The current centralized engine can classify detected traffic into categories including:

- **SQL Injection** — CRITICAL
- **XSS** — HIGH
- **Command Injection** — CRITICAL
- **Path Traversal** — HIGH
- **Reconnaissance Probing** — MEDIUM
- **Suspicious Activity** — used for ML detections that do not map to one of the more specific categories
- **Safe Traffic** — clean requests

The rule IDs shown by the dashboard are classification/telemetry identifiers associated with the detected category. The actual first-stage allow/block decision is made by `check_signature()`, followed by ML when the signature result is obfuscated/suspicious.

---

## 🧪 False-Positive Checks

The project includes explicit checks for ordinary inputs so common words and normal-looking data are not treated as attacks simply because they contain words that can appear inside security terminology.

Examples include:

```text
hello
iphone 15
john@example.com
Please select a store and confirm your order
My password = hunter2 (don't judge)
administrator meeting at 3pm
```

The test suite expects these examples to pass through the normal clean path.

---

## ⚙️ Design Decisions

### Why use a hybrid engine?

Signature detection is fast and deterministic for known attack patterns. However, attackers can encode or obfuscate payloads so that a simple exact pattern may not match. The ML stage provides an additional analysis layer for requests identified as suspicious/obfuscated.

### Why not send every request to ML?

The project uses ML as a **second-stage detector**, not as the first check for every request. This reduces unnecessary ML processing for clearly normal traffic and keeps the architecture easier to explain and demonstrate.

### Why centralize detection in `engine.py`?

Without a shared engine, Manual Intercept and other request sources could accidentally use different rules and produce different security decisions.

With the current architecture:

```text
Different request sources
        ↓
Same detection function
        ↓
Same Signature stage
        ↓
Same ML fallback stage
        ↓
Consistent security decision
```

This also makes future changes to detection logic easier because the main decision pipeline is maintained in one place.

---

## ⚠️ Current Prototype Limitations

SentinelWAF is a training/demo prototype, not a production WAF.

Important limitations include:

- The dashboard uses simulated IP/geolocation telemetry.
- The bundled ML model is a demonstration model and should not be treated as production-grade threat intelligence.
- The project does not currently operate as a transparent reverse proxy in front of an external production web application.
- The dashboard's Network Matrix and related controls demonstrate security concepts in the UI; they do not provide OS-level or network-level IP blocking.
- Detection quality depends on the signatures and the trained ML model included with the project.
- A production WAF would require stronger request parsing, authentication/authorization controls, rate limiting, production logging, secure deployment, model monitoring, and a larger validated dataset.

### Important terminology for presentations

It is accurate to say:

> **“SentinelWAF demonstrates an inline-style request inspection architecture through a Flask inspection API.”**

It is not accurate to claim that this prototype is already transparently intercepting all traffic to a real external web application.

---

## 🔮 Possible Future Enhancements

- Deploy the inspection engine as a real reverse proxy between a client and backend application.
- Forward clean requests to the protected backend automatically.
- Add real GeoIP lookup and threat-intelligence feeds.
- Add rate limiting and IP reputation scoring.
- Add configurable rule/severity policies.
- Expand and validate the training dataset.
- Retrain and benchmark the ML model on a larger dataset.
- Add authentication and role-based access to the dashboard.
- Add production-grade structured logging and alerting.
- Add automated unit/integration tests for every attack category and API route.

---

## 🎓 Learning Outcomes

This project demonstrates practical work with:

- Web Application Firewall concepts
- HTTP request inspection
- Signature/regex-based security detection
- Obfuscation handling and URL normalization
- Security feature engineering
- Shannon entropy as a signal for suspicious input
- Machine-learning-based second-stage classification
- Flask APIs and blueprints
- SQLite logging
- Security dashboards and telemetry
- False-positive testing
- Separation of detection logic from UI routes

---

## 👩‍💻 Project Information

| Category | Details |
|---|---|
| Project Name | SentinelWAF |
| Project Type | Cybersecurity Web Application / WAF Prototype |
| Domain | Web Application Security |
| Language | Python 3 |
| Framework | Flask |
| Detection | Signature + ML hybrid pipeline |
| Storage | SQLite |
| Status | Working Educational Prototype |
| Context | Cybersecurity Summer Training Project |
| Developed By | Khushi Sharma |
| Year | 2026 |

---

## 🏷️ Keywords

`CyberSecurity` `WAF` `WebApplicationFirewall` `Python` `Flask` `MachineLearning` `SQLInjection` `XSS` `CommandInjection` `PathTraversal` `AnomalyDetection` `SecurityMonitoring`
