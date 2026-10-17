# 🛡️ SentinelShield — Web Application Firewall & Security Operations Platform

> A cloud-deployed, intelligent **reverse-proxy WAF** that inspects every incoming HTTP request, blocks cyberattacks in real time, and gives security teams an interactive operations dashboard for monitoring, forensics, and rule management.

---

## 📺 Live Demo

| Service | URL |
|:--------|:----|
| 🛡️ WAF Gateway | `https://sentinelshield-gateway.onrender.com` |
| 📊 Security Dashboard | `https://sentinelshield-dashboard.onrender.com` |

> **Free tier note:** Services spin down after 15 minutes of inactivity and take ~30 seconds to cold-start on first visit.

---

## Table of Contents

1. [What It Does](#1-what-it-does)
2. [Architecture](#2-architecture)
3. [Technology Stack](#3-technology-stack)
4. [Detection Rules](#4-detection-rules)
5. [Dashboard Pages](#5-dashboard-pages)
6. [API Reference](#6-api-reference)
7. [Database Schema](#7-database-schema)
8. [Local Development](#8-local-development)
9. [Cloud Deployment (Render)](#9-cloud-deployment-render)
10. [Security Limitations](#10-security-limitations)
11. [Demo Script](#11-demo-script-25-minutes)

---

## 1. What It Does

Web applications face constant threats from SQL injection, cross-site scripting, path traversal, and volumetric abuse. SentinelShield sits **in front of any backend application** as a transparent reverse proxy:

- **Intercepts** every HTTP request before it reaches the backend.
- **Inspects** headers, query parameters, form data, and the request body against 10+ security rules.
- **Blocks** malicious requests with HTTP 403/429 — the backend never sees them.
- **Forwards** legitimate requests to the protected application and relays the response.
- **Logs** every decision (ALLOW/BLOCK/RATE_LIMITED) to a SQLite database with full forensic metadata.
- **Exposes** a Streamlit Security Operations Center for live monitoring, attack simulation, rule management, and reporting.

---

## 2. Architecture

```text
       Internet Traffic
              │
              ▼
 ┌────────────────────────────┐
 │   SentinelShield Gateway   │  ← Inspects all requests
 │  (Flask + Gunicorn, :5000) │    Rules engine runs on every hit
 │    Logs events to SQLite   │
 └────────────┬───────────────┘
              │
     ┌────────┴────────┐
     │                 │
 [MALICIOUS]        [SAFE]
     │                 │
     ▼                 ▼
🚫 BLOCKED (403)  Protected App
   Logged to DB   (Flask, :5001)
     │
     ▼
 ┌────────────────────────────┐
 │   Streamlit SOC Dashboard  │  ← Reads from Gateway API
 │   (Streamlit, :8501)       │    Analytics, forensics, rules,
 │                            │    attack simulation
 └────────────────────────────┘
```

**Security Properties:**
- Protected app has **no public port** — only the Gateway can reach it (via `PROTECTED_APP_URL`).
- All containers run as **non-root users**.
- Defensive HTTP security headers are injected on every response (`X-Frame-Options`, `CSP`, `HSTS`).
- SQLite uses **WAL mode** with `BEGIN IMMEDIATE` transactions for safe multi-worker concurrency.

---

## 3. Technology Stack

| Component | Technology | Version |
|:----------|:-----------|:--------|
| WAF Gateway | Python / Flask | 3.11 / 3.0.3 |
| WSGI Server | Gunicorn | 22.0.0 |
| Protected App | Python / Flask | 3.11 / 3.0.3 |
| Dashboard | Streamlit | 1.35.0 |
| Charts | Plotly | 5.22.0 |
| Data | Pandas + PyArrow | 2.2.2 / <17 |
| Database | SQLite (WAL mode) | Built-in |
| HTTP Client | Requests | 2.32.3 |
| Containers | Docker (3 services) | — |
| Cloud | Render (free tier) | — |

---

## 4. Detection Rules

### SQL Injection

| Rule ID | What It Detects | Severity |
|:--------|:----------------|:---------|
| SQL-001 | Tautologies: `' OR '1'='1`, `' OR 1=1--` | HIGH |
| SQL-002 | `UNION SELECT` data extraction | HIGH |
| SQL-003 | SQL comment truncation `--` `/**/` | MEDIUM |
| SQL-004 | DDL/DML: `DROP TABLE`, `DELETE FROM`, `INSERT INTO` | HIGH |

### Cross-Site Scripting (XSS)

| Rule ID | What It Detects | Severity |
|:--------|:----------------|:---------|
| XSS-001 | `<script>` tag injection | HIGH |
| XSS-002 | `javascript:` URI scheme | HIGH |
| XSS-003 | Event handlers: `onerror=`, `onload=`, `onmouseover=` | MEDIUM |

### Path Traversal

| Rule ID | What It Detects | Severity |
|:--------|:----------------|:---------|
| PT-001 | `../`, `%2e%2e/`, `%252e%252e` (URL-decoded up to 3 rounds) | HIGH |

### Validation

| Rule ID | Check | Threshold |
|:--------|:------|:----------|
| VAL-001 | URL max length | 2048 characters |
| VAL-002 | Request body max size | 100 KB |
| VAL-003 | HTTP method allowlist | GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS |

### Rate Limiting

| Rule ID | Limit | Window |
|:--------|:------|:-------|
| RL-001 | 30 requests per client IP | 60 seconds sliding window |

---

## 5. Dashboard Pages

| Page | Description |
|:-----|:------------|
| 🏠 **Home / Command Center** | Real-time gateway status badge, live KPI cards (total requests, threats blocked, block rate, legitimate traffic), module navigation hub, and 1-click WAF smoke tests |
| 📊 **Security Overview** | Live Plotly charts: ALLOW/BLOCK donut, hourly timeline, attack categories, status code distribution, and top triggered rule |
| ⚔️ **Attack Simulator** | Built-in pen-testing sandbox: fire SQLi, XSS, Path Traversal, and rate-limit burst scenarios through the live WAF and see real block/allow decisions |
| 📜 **Security Logs** | Full forensic audit trail with filtering by decision, severity, category, and time range; export to CSV |
| ⚙️ **Rules Config** | Enable/disable each of the 10 rules at runtime without restarting services; reset to defaults |
| 📋 **Reports** | Compliance and incident summary export with threat trend analytics |
| ℹ️ **System Info** | Gateway health probe, upstream connectivity, SQLite WAL status, security header verification |

---

## 6. API Reference

All endpoints are served by the WAF Gateway. Admin endpoints require `X-API-Key: <API_SECRET>` header.

| Method | Endpoint | Auth | Description |
|:-------|:---------|:-----|:------------|
| GET | `/health` | No | Gateway liveness probe |
| GET | `/api/stats` | No | Aggregate statistics (totals, block %) |
| GET | `/api/events` | No | Security event list (filterable + paginated) |
| GET | `/api/events/<id>` | No | Single event by request UUID |
| GET | `/api/charts` | No | Chart-ready event data |
| GET | `/api/rules` | No | All 10 security rules + enabled state |
| PATCH | `/api/rules/<rule_id>` | Yes | Toggle a rule enabled/disabled |
| POST | `/api/rules/reset` | Yes | Reset all rules to defaults |
| POST | `/api/demo/reset` | Yes | Clear all demo event data |
| GET | `/api/db-stats` | No | SQLite WAL size, event count |
| GET | `/api/audit` | Yes | Admin audit trail |

**`/api/events` query parameters:**
```
limit     int  (max 1000)
offset    int
decision  ALLOW | BLOCK | RATE_LIMITED | VALIDATION_ERROR
severity  INFO | LOW | MEDIUM | HIGH | CRITICAL
category  SQL_INJECTION | XSS | PATH_TRAVERSAL | VALIDATION | RATE_LIMIT | NONE
from      ISO-8601 timestamp
to        ISO-8601 timestamp
```

---

## 7. Database Schema

### `security_events`

| Column | Type | Description |
|:-------|:-----|:------------|
| `id` | INTEGER PK | Auto-increment |
| `request_id` | TEXT | UUID4 correlation ID |
| `timestamp_utc` | TEXT | ISO-8601 UTC |
| `method` | TEXT | HTTP method |
| `route` | TEXT | Sanitized path |
| `decision` | TEXT | ALLOW / BLOCK / RATE_LIMITED / VALIDATION_ERROR |
| `status_code` | INTEGER | HTTP response code |
| `matched_rule_ids` | TEXT | JSON array of rule IDs |
| `attack_category` | TEXT | SQL_INJECTION / XSS / PATH_TRAVERSAL / etc. |
| `severity` | TEXT | INFO / LOW / MEDIUM / HIGH / CRITICAL |
| `reason` | TEXT | Human-readable detection reason |
| `processing_time_ms` | REAL | Gateway latency in ms |
| `sanitized_client_id` | TEXT | Hashed/truncated client IP |

### `security_rules`

| Column | Type | Description |
|:-------|:-----|:------------|
| `rule_id` | TEXT PK | e.g. `SQL-001` |
| `enabled` | INTEGER | `1` = active, `0` = disabled |
| `configuration_json` | TEXT | Rule-specific tuning params |
| `updated_at` | TEXT | Last modification |

### `audit_events`

| Column | Type | Description |
|:-------|:-----|:------------|
| `id` | INTEGER PK | Auto-increment |
| `action` | TEXT | `RULE_UPDATE` / `RULES_RESET` / `DEMO_RESET` |
| `actor` | TEXT | Who made the change |
| `target` | TEXT | Affected rule/entity |

---

## 8. Local Development

### Prerequisites
- Docker Desktop with Compose v2
- Ports `5000` and `8501` free on localhost

### Run Locally

```bash
# Clone the repo
git clone https://github.com/Pegasus2005/acc_ia.git sentinelshield
cd sentinelshield

# Start all 3 services (builds Docker images on first run ~3-5 min)
docker compose up --build

# Open in browser
# Dashboard:  http://localhost:8501
# Gateway:    http://localhost:5000/health
```

```bash
# Stop (preserves SQLite data)
docker compose down

# Stop + wipe database
docker compose down -v
```

### Run Tests

```bash
# Unit tests (no Docker needed)
pip install -r gateway/requirements.txt
pytest tests/test_unit.py -v

# Integration tests (gateway must be running)
docker compose up -d
pytest tests/test_integration.py -v
```

---

## 9. Cloud Deployment (Render)

This project is deployed as **3 free Web Services** on Render (no Blueprint, no paid disk):

### Service 1 — `sentinelshield-protected-app`

| Setting | Value |
|:--------|:------|
| Runtime | Docker |
| Dockerfile | `./protected_app/Dockerfile` |
| Docker Context | `./protected_app` |
| Plan | Free |

**Environment Variables:**
| Key | Value |
|:----|:------|
| `PYTHONUNBUFFERED` | `1` |

---

### Service 2 — `sentinelshield-gateway`

| Setting | Value |
|:--------|:------|
| Runtime | Docker |
| Dockerfile | `./gateway/Dockerfile` |
| Docker Context | `./gateway` |
| Plan | Free |

**Environment Variables:**
| Key | Value |
|:----|:------|
| `PROTECTED_APP_URL` | `https://sentinelshield-protected-app.onrender.com` |
| `DB_PATH` | `/tmp/sentinelshield.db` |
| `API_SECRET` | `<your-secret-string>` |
| `PYTHONUNBUFFERED` | `1` |

> ⚠️ `/tmp` is ephemeral on free tier — event history resets on each deploy/restart. Upgrade to a paid plan with a Persistent Disk for durability.

---

### Service 3 — `sentinelshield-dashboard`

| Setting | Value |
|:--------|:------|
| Runtime | Docker |
| Dockerfile | `./dashboard/Dockerfile` |
| Docker Context | `./dashboard` |
| Plan | Free |

**Environment Variables:**
| Key | Value |
|:----|:------|
| `GATEWAY_URL` | `https://sentinelshield-gateway.onrender.com` |
| `API_SECRET` | `<same secret as gateway>` |
| `PYTHONUNBUFFERED` | `1` |

---

## 10. Security Limitations

This is an **educational tool**, not a production-grade WAF. Known limitations:

1. **Pattern-based detection has false negatives.** Novel encodings and obfuscated payloads can evade regex rules.
2. **Rate limiting is in-memory.** Resets on container restart. Not suitable for distributed or multi-worker deployments.
3. **IP identification is unreliable.** Clients behind NAT or shared proxies share an IP address.
4. **No TLS termination.** HTTPS is handled by Render's edge; the gateway itself speaks HTTP internally.
5. **Rule coverage is limited.** Only common, well-known OWASP Top 10 patterns are covered.
6. **Second-order injection not detected.** Payloads stored and later rendered are not re-inspected at output.
7. **API key is a demo credential.** Change `API_SECRET` before any non-trivial use.

---

## 11. Demo Script (2.5 minutes)

### Before Recording
- Open the dashboard URL in an **incognito browser tab** for a clean UI.
- Run the Attack Simulator a few times first so charts already have data.
- Use **OBS**, **Loom**, or Windows **Xbox Game Bar** (`Win + G`) to capture.

---

### `[0:00–0:25]` Home Page — Command Center

> *"SentinelShield is a cloud-deployed Web Application Firewall. Every request on the internet passes through the Gateway before touching the backend. Here on the home page we can see real-time telemetry: total requests inspected, how many threats were blocked, the block rate, and legitimate traffic forwarded."*

👉 Hover over the **4 KPI cards** → point to the **green GATEWAY ONLINE pill**.

---

### `[0:25–0:45]` Home Page — Live 1-Click Smoke Test

> *"Let me show you the WAF in action — I'll fire a legitimate request and a SQL injection probe."*

👉
1. Click **🟢 Send Legitimate Request** → show `Decision: ALLOW`
2. Click **🔴 Send SQL Injection Probe** → show `Decision: BLOCK`

> *"That SQL injection — quote OR one-equals-one — was caught in milliseconds at the firewall layer. The backend never saw it."*

---

### `[0:45–1:30]` Attack Simulator — Live Attack Demo

> *"Now let's go to the full penetration-testing sandbox."*

👉
1. Sidebar → **Attack Simulator**
2. Select **XSS Script Injection** preset → click **Launch Attack** → show red `BLOCKED` card with rule `XSS-001`
3. Switch to **Path Traversal** → **Launch** → show `BLOCKED` with rule `PT-001`

> *"Script tags, dot-dot-slash directory traversal — all intercepted and logged in milliseconds before the backend processes a single byte."*

---

### `[1:30–1:55]` Security Overview — Live Analytics

> *"Every blocked and allowed request is logged with forensic metadata. The Overview shows trends over time."*

👉
1. Sidebar → **Security Overview**
2. Point to the **ALLOW/BLOCK donut chart** → hover the **hourly timeline** to show tooltips

> *"This is live data from the SQLite event store. You can see the attack spike from our simulation just now."*

---

### `[1:55–2:25]` Security Logs — Forensics

> *"For incident response, the Security Logs page gives a full audit trail."*

👉
1. Sidebar → **Security Logs**
2. Filter dropdown → select **BLOCK** decisions only
3. Point to matched rule IDs, attack category, latency, and timestamp columns

> *"Every event has a unique Request ID, matched rule IDs, attack category, processing latency in milliseconds, and a sanitized client fingerprint — ready for compliance or incident reporting."*

---

### `[2:25–2:50]` Rules Config — Live Rule Management

> *"Security teams can manage the rule engine in real time without restarting any service."*

👉
1. Sidebar → **Rules Config**
2. Show the rule list (SQL-001 through RL-001)
3. **Toggle OFF** a rule (e.g. Rate Limiter) → toggle it **back ON**

> *"Rules can be enabled, disabled, or tuned on the fly. The gateway picks up changes immediately."*

---

### `[2:50–3:00]` Wrap-Up

> *"SentinelShield is a fully cloud-deployed, production-realistic WAF — three containerized Docker services running on Render's free tier, with a real-time Security Operations Center. A transparent reverse proxy that protects any upstream service without modifying a single line of backend code."*

👉 Return to **Home page** to end on the clean command center view.

---

## Project Structure

```
sentinelshield/
├── gateway/                    # WAF reverse proxy
│   ├── app.py                  # Flask app, proxy handler, all API endpoints
│   ├── rules_engine.py         # Regex detection rules + rate limiter
│   ├── database.py             # SQLite schema, logging, rule management
│   ├── requirements.txt
│   └── Dockerfile
│
├── protected_app/              # Mock backend (no public port)
│   ├── app.py                  # 6 safe endpoints with static sample data
│   ├── requirements.txt
│   └── Dockerfile
│
├── dashboard/                  # Streamlit SOC dashboard
│   ├── Home.py                 # Landing page + command center
│   ├── api_client.py           # Shared HTTP client for all pages
│   ├── pages/
│   │   ├── 1_Overview.py       # KPI cards + 5 live Plotly charts
│   │   ├── 2_Attack_Simulator.py # Pen-testing sandbox
│   │   ├── 3_Security_Logs.py  # Filterable forensic log
│   │   ├── 4_Rules_Config.py   # Rule enable/disable + reset
│   │   ├── 5_Reports.py        # Analytics export
│   │   └── 6_System_Info.py    # Health checks + architecture
│   ├── requirements.txt
│   └── Dockerfile
│
├── tests/                      # Unit + integration tests (pytest)
├── compose.yaml                # Docker Compose for local development
├── render.yaml                 # Render cloud deployment config
└── README.md
```

---

*SentinelShield — Built with Flask, Streamlit, SQLite, Docker, and deployed on Render.*
