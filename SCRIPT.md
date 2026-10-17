# 🎬 SentinelShield Demo Script
**Target Duration:** 2.5 – 3 minutes  
**Format:** Screen recording with voiceover  
**Tools:** OBS / Loom / Xbox Game Bar (`Win + G`)

---

## ✅ Pre-Recording Checklist

Before you hit record:

- [ ] Open the **Dashboard URL** in an **incognito/private browser** tab (clean UI, no cached state)
- [ ] Open the **Attack Simulator** page and run a few attacks first so the charts are already populated
- [ ] Zoom browser to **110%** so text is readable on screen
- [ ] Close all other browser tabs and notifications
- [ ] Set your screen resolution to at least **1280 × 720**
- [ ] Do a **full dry run** once before the real recording

---

## 🎙️ Full Narration Script

---

### `[0:00 – 0:25]` — Home Page · Command Center

**🖥️ What to show:**
1. The page loads — scroll slowly to let viewer absorb the layout
2. Point your cursor to the **green "● GATEWAY ONLINE (PROTECTION ACTIVE)" pill** in the top-right of the hero banner
3. Slowly hover over each of the **4 KPI cards** (total inspected, threats blocked, block rate %, legitimate traffic)

**🎙️ Say this:**
> *"This is SentinelShield — a cloud-deployed Web Application Firewall.
> Every request on the internet passes through the Gateway before touching
> the backend application. Here on the home page we can see live telemetry:
> total requests inspected, how many threats were blocked, the block rate,
> and legitimate traffic forwarded to the protected app."*

---

### `[0:25 – 0:45]` — Home Page · 1-Click WAF Smoke Test

**🖥️ What to show:**
1. Scroll down to the **"⚡ Instant WAF Smoke Test"** section
2. Click **🟢 Send Legitimate Request** — pause 1 second — show the result card: `Decision: ALLOW`, green text
3. Click **🔴 Send SQL Injection Probe** — pause 1 second — show the result card: `Decision: BLOCK`, red text, show the latency value

**🎙️ Say this:**
> *"Let me show the WAF in action. A legitimate request is forwarded normally —
> decision: ALLOW. Now I'll fire a SQL injection probe — quote, OR, one equals one —
> a classic authentication bypass attack. Decision: BLOCK.
> The backend never received this request. It was intercepted and rejected
> at the firewall layer in under ten milliseconds."*

---

### `[0:45 – 1:30]` — Attack Simulator Page

**🖥️ What to show:**
1. Click **"⚔️ Attack Simulator"** in the left sidebar
2. From the scenario dropdown, select **"XSS Script Injection"**
3. Click **Launch Attack** — show the red `BLOCKED` result card
4. Point to: **Rule ID** (`XSS-001`), **HTTP Status** (`403`), **Processing time**
5. Now change the dropdown to **"Path Traversal"**
6. Click **Launch Attack** — show `BLOCKED` with `PT-001`

**🎙️ Say this:**
> *"Now let's go to the built-in penetration testing sandbox.
> I'll fire an XSS script tag injection — blocked by rule XSS-001.
> The script never reached the application.
> Let me try a directory traversal attack next — using dot-dot-slash sequences
> to escape the web root and read server files. Blocked by rule PT-001.
> All attack categories — SQL injection, XSS, path traversal, rate limiting —
> are evaluated in sequence for every single request."*

---

### `[1:30 – 1:55]` — Security Overview Page

**🖥️ What to show:**
1. Click **"📊 Security Overview"** in the left sidebar
2. Point to the **ALLOW vs BLOCK donut/pie chart** — hover over segments to show tooltips
3. Point to the **hourly timeline bar chart** — hover over bars to show request counts per hour
4. Point to the **Attack Category bar chart**

**🎙️ Say this:**
> *"Every single decision is logged with full forensic metadata.
> The Security Overview page shows live analytics — the ALLOW to BLOCK ratio,
> the attack category breakdown — SQL injection, XSS, traversal —
> and an hourly traffic timeline. These charts are not hardcoded.
> They update in real time as new events come in."*

---

### `[1:55 – 2:25]` — Security Logs Page

**🖥️ What to show:**
1. Click **"📜 Security Logs"** in the left sidebar
2. Open the **Decision filter** dropdown → select **`BLOCK`** → let table refresh
3. Slowly scroll through the filtered table
4. Point to key columns: **Matched Rule IDs**, **Attack Category**, **Processing Time (ms)**, **Timestamp**

**🎙️ Say this:**
> *"For incident response and forensics, the Security Logs page is the audit trail.
> I can filter by decision, severity, category, and time range.
> Here I'm filtering for blocked requests only.
> Each row shows the matched rule IDs, the attack category, exactly how long
> the gateway took to evaluate it, and the sanitized client identifier.
> This is exportable to CSV — values are sanitized against formula injection."*

---

### `[2:25 – 2:50]` — Rules Configuration Page

**🖥️ What to show:**
1. Click **"⚙️ Rules Config"** in the left sidebar
2. Show the full list of 10 rules — scroll slowly so all are visible
3. Find a rule (e.g. **Rate Limiter — RL-001**) and **toggle it OFF** using the toggle/checkbox
4. Show the UI update (rule greyed out or marked disabled)
5. **Toggle it back ON**

**🎙️ Say this:**
> *"Security teams can manage the rule engine in real time —
> no restarts, no redeployments required.
> Here I can see all ten active rules with their categories and severities.
> I'll disable the Rate Limiter temporarily to show how the system responds —
> and re-enable it immediately. Every toggle is recorded in the audit trail
> in the database. This is how a real SOC team would tune a WAF
> during an incident or a planned maintenance window."*

---

### `[2:50 – 3:00]` — Wrap-Up · Back to Home

**🖥️ What to show:**
1. Click the **SentinelShield logo / Home** in the sidebar to return to the home page
2. Let the command center layout sit on screen for 3–4 seconds as you deliver the closing line

**🎙️ Say this:**
> *"SentinelShield is a fully cloud-deployed, production-realistic WAF —
> three containerized Docker services running on Render's free tier,
> with a real-time Security Operations Center.
> A transparent reverse proxy that protects any upstream application
> without modifying a single line of backend code."*

---

## 🗺️ Page-by-Page Exploration Guide

### 🏠 Home — Command Center
| Element | What It Shows | Tip |
|:--------|:-------------|:----|
| Hero banner pill | Live gateway status (ONLINE/OFFLINE) | Should be green — if red, check Render logs |
| 4 KPI cards | Total, blocked, block rate %, allowed | Hover for subtle lift animation |
| Module nav cards | Links to all 6 dashboard sections | Use the page link buttons to navigate |
| Smoke test buttons | Send real live requests right from home | Great for opening demo shot |

---

### ⚔️ Attack Simulator
| Element | What It Shows | Tip |
|:--------|:-------------|:----|
| Scenario dropdown | 10 pre-built attack payloads | Start with XSS, then Path Traversal |
| Launch Attack button | Fires the request through the live WAF | Click and wait ~1–2s for response |
| Result card (red) | Rule ID, 403 status, processing latency | Point to "Rule XSS-001" text |
| Result card (green) | ALLOW decision for safe payloads | Run "Normal Request" scenario |

---

### 📊 Security Overview
| Element | What It Shows | Tip |
|:--------|:-------------|:----|
| ALLOW/BLOCK donut chart | Overall traffic split | Hover segments for tooltips |
| Hourly timeline bar chart | Requests per hour today | Hover bars for exact counts |
| Attack category chart | Which attack types appeared | Populated after Attack Simulator runs |
| Top triggered rule card | Most-fired rule ID today | Shows impact of your demo attacks |

---

### 📜 Security Logs
| Element | What It Shows | Tip |
|:--------|:-------------|:----|
| Filter: Decision | Show only BLOCK / ALLOW / RATE_LIMITED | Filter to BLOCK for best demo impact |
| Filter: Category | Show only SQL_INJECTION / XSS / etc. | Combine with Decision filter |
| Table rows | Full forensic record per request | Scroll to show Rule IDs column |
| Export button | Downloads filtered events as CSV | Good to click even if not showing the file |

---

### ⚙️ Rules Config
| Element | What It Shows | Tip |
|:--------|:-------------|:----|
| Rule list | All 10 rules with category + severity | Scroll slowly — all should be visible |
| Enable/Disable toggle | Controls active rule set at runtime | Toggle RL-001 OFF then back ON |
| Reset to Defaults button | Restores all rules if you broke anything | Use at end of demo if needed |
| Last updated timestamp | Audit timestamp for each rule | Shows change is logged |

---

### 📋 Reports · ℹ️ System Info *(bonus exploration)*
| Page | What to Show |
|:-----|:-------------|
| Reports | Click "Generate Report" and show the threat trend summary — looks impressive |
| System Info | Shows the architecture diagram, live gateway version, SQLite WAL status, and upstream connectivity check |

---

## ⏱️ Timing Summary

| Time | Page | Action |
|:-----|:-----|:-------|
| 0:00 – 0:25 | Home | KPI cards + gateway status |
| 0:25 – 0:45 | Home | Smoke test (ALLOW then BLOCK) |
| 0:45 – 1:30 | Attack Simulator | XSS + Path Traversal attacks |
| 1:30 – 1:55 | Security Overview | Charts and timeline |
| 1:55 – 2:25 | Security Logs | Filter, forensic trail |
| 2:25 – 2:50 | Rules Config | Toggle rule + audit |
| 2:50 – 3:00 | Home | Closing shot |

---

*SentinelShield — Intelligent Web Application Firewall & Security Operations Platform*
