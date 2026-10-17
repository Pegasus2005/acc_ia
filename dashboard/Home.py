"""
SentinelShield Security Dashboard
Multi-page Streamlit application for monitoring, analytics, and attack simulation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import streamlit as st
from api_client import get_stats, get_gateway_health, get_rules, send_test_request

st.set_page_config(
    page_title="SentinelShield WAF Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Base ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: #020817;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a0f1e 0%, #0d1530 100%);
    border-right: 1px solid #1e2d4a;
}
[data-testid="stSidebar"] .stMarkdown h3 {
    color: #06b6d4;
    font-size: 0.75rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
}

/* ── Hero Banner ── */
.hero-box {
    background: linear-gradient(135deg, rgba(6, 182, 212, 0.08) 0%, rgba(15, 23, 42, 0.8) 100%);
    border: 1px solid #1e3a5f;
    border-radius: 14px;
    padding: 1.8rem 2rem;
    margin-bottom: 1.8rem;
    position: relative;
    overflow: hidden;
}
.hero-box::after {
    content: '';
    position: absolute;
    top: 0; right: 0; width: 300px; height: 100%;
    background: radial-gradient(circle, rgba(6, 182, 212, 0.12) 0%, transparent 70%);
    pointer-events: none;
}
.hero-title {
    font-size: 2.2rem;
    font-weight: 800;
    color: #f8fafc;
    letter-spacing: -0.02em;
    margin: 0 0 0.4rem;
}
.hero-subtitle {
    font-size: 1rem;
    color: #94a3b8;
    margin-bottom: 1rem;
    max-width: 800px;
    line-height: 1.5;
}

/* ── KPI Cards ── */
.kpi-card {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 1.25rem 1.2rem;
    text-align: center;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.kpi-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(6, 182, 212, 0.15);
}
.kpi-value {
    font-size: 2.2rem;
    font-weight: 700;
    color: #06b6d4;
    line-height: 1;
    margin: 0.5rem 0 0.25rem;
}
.kpi-label {
    font-size: 0.75rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 500;
}

.kpi-cyan .kpi-value   { color: #06b6d4; }
.kpi-red .kpi-value    { color: #ef4444; }
.kpi-amber .kpi-value  { color: #f59e0b; }
.kpi-green .kpi-value  { color: #22c55e; }

/* ── Feature Cards ── */
.nav-card {
    background: #0f172a;
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 1.25rem 1.4rem;
    margin-bottom: 1rem;
    transition: border-color 0.2s ease, transform 0.2s ease;
}
.nav-card:hover {
    border-color: #06b6d4;
    transform: translateY(-2px);
}
.nav-card h4 {
    margin: 0 0 0.3rem 0;
    font-size: 1.05rem;
    color: #f1f5f9;
}
.nav-card p {
    color: #94a3b8;
    font-size: 0.85rem;
    margin: 0 0 0.8rem 0;
    line-height: 1.4;
}

/* ── Status Pill ── */
.status-pill-ok {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    background: rgba(34, 197, 94, 0.12);
    color: #4ade80;
    border: 1px solid rgba(34, 197, 94, 0.3);
    padding: 0.3rem 0.8rem;
    border-radius: 9999px;
    font-size: 0.82rem;
    font-weight: 600;
}
.status-pill-bad {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    background: rgba(239, 68, 68, 0.12);
    color: #f87171;
    border: 1px solid rgba(239, 68, 68, 0.3);
    padding: 0.3rem 0.8rem;
    border-radius: 9999px;
    font-size: 0.82rem;
    font-weight: 600;
}

/* ── Section header ── */
.section-header {
    color: #06b6d4;
    font-size: 0.95rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 0.4rem;
    margin: 1.8rem 0 1rem;
}

/* ── Quick test result ── */
.quick-test-box {
    background: #0d1527;
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 1rem 1.25rem;
    margin-top: 0.8rem;
}
</style>
""", unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ SentinelShield WAF")
    st.caption("Active Protection Gateway")
    st.markdown("---")
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()

# ── Fetch Telemetry & Health ───────────────────────────────────────────────────
health = get_gateway_health()
stats = get_stats()
gateway_online = bool(health and health.get("status") in ("healthy", "ok", "degraded"))

# ── Hero Banner ────────────────────────────────────────────────────────────────
status_html = (
    '<span class="status-pill-ok">● GATEWAY ONLINE (PROTECTION ACTIVE)</span>'
    if gateway_online else
    '<span class="status-pill-bad">● GATEWAY CONNECTING / OFFLINE</span>'
)

st.markdown(f"""
<div class="hero-box">
    <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:10px;">
        <div>
            <div class="hero-title">🛡️ SentinelShield WAF</div>
            <div class="hero-subtitle">
                Cloud-native intelligent Web Application Firewall protecting upstream microservices
                against SQL Injection, XSS, Path Traversal, and volumetric attacks with millisecond latency.
            </div>
        </div>
        <div>{status_html}</div>
    </div>
</div>
""", unsafe_allow_html=True)

if not gateway_online:
    st.warning("⚠️ Could not connect to the Gateway API. Verify `GATEWAY_URL` in your dashboard environment variables.")

# ── KPI Telemetry Row ──────────────────────────────────────────────────────────
total_req = stats.get("total", 0) if stats else 0
allowed = stats.get("allowed", 0) if stats else 0
blocked = stats.get("blocked", 0) if stats else 0
rate_limited = stats.get("rate_limited", 0) if stats else 0
block_pct = stats.get("block_percentage", 0.0) if stats else 0.0
total_threats = blocked + rate_limited

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""
    <div class="kpi-card kpi-cyan">
        <div class="kpi-label">Total Inspected</div>
        <div class="kpi-value">{total_req:,}</div>
        <div style="color:#64748b;font-size:0.75rem;">Processed requests</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="kpi-card kpi-red">
        <div class="kpi-label">Threats Blocked</div>
        <div class="kpi-value">{total_threats:,}</div>
        <div style="color:#64748b;font-size:0.75rem;">{blocked} blocked + {rate_limited} rate-limited</div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="kpi-card kpi-amber">
        <div class="kpi-label">Block Rate</div>
        <div class="kpi-value">{block_pct:.1f}%</div>
        <div style="color:#64748b;font-size:0.75rem;">Filtered malicious traffic</div>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class="kpi-card kpi-green">
        <div class="kpi-label">Legitimate Traffic</div>
        <div class="kpi-value">{allowed:,}</div>
        <div style="color:#64748b;font-size:0.75rem;">Forwarded to protected app</div>
    </div>
    """, unsafe_allow_html=True)

# ── Navigation Hub ─────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">🧭 Security Operations Center Modules</div>', unsafe_allow_html=True)

col_a, col_b = st.columns(2)

with col_a:
    st.markdown("""
    <div class="nav-card">
        <h4>📊 Security Overview</h4>
        <p>Live threat distribution, attack category analytics, status code charts, and top rule triggers.</p>
    </div>
    """, unsafe_allow_html=True)
    st.page_link("pages/1_Overview.py", label="Open Security Overview →", icon="📊")

    st.markdown("""
    <div class="nav-card" style="margin-top:1.2rem;">
        <h4>📜 Security Logs & Forensics</h4>
        <p>Full audit trail of all inspected requests, decision status, attack signatures, and timing breakdown.</p>
    </div>
    """, unsafe_allow_html=True)
    st.page_link("pages/3_Security_Logs.py", label="Open Security Logs →", icon="📜")

    st.markdown("""
    <div class="nav-card" style="margin-top:1.2rem;">
        <h4>📋 Executive Reports</h4>
        <p>Generate compliance reports, incident summaries, and export threat data for security stakeholders.</p>
    </div>
    """, unsafe_allow_html=True)
    st.page_link("pages/5_Reports.py", label="Generate Reports →", icon="📋")

with col_b:
    st.markdown("""
    <div class="nav-card">
        <h4>⚔️ Attack Simulator</h4>
        <p>Interactive penetration testing sandbox to fire live SQLi, XSS, Path Traversal, and DDoS attack payloads.</p>
    </div>
    """, unsafe_allow_html=True)
    st.page_link("pages/2_Attack_Simulator.py", label="Launch Attack Simulator →", icon="⚔️")

    st.markdown("""
    <div class="nav-card" style="margin-top:1.2rem;">
        <h4>⚙️ Rules Configuration</h4>
        <p>Manage and customize 10+ built-in WAF rules, toggle inspection filters, and tune rate limit thresholds.</p>
    </div>
    """, unsafe_allow_html=True)
    st.page_link("pages/4_Rules_Config.py", label="Configure Rules →", icon="⚙️")

    st.markdown("""
    <div class="nav-card" style="margin-top:1.2rem;">
        <h4>ℹ️ System & Diagnostics</h4>
        <p>Inspect gateway proxy topology, upstream connectivity, SQLite WAL status, and HTTP security headers.</p>
    </div>
    """, unsafe_allow_html=True)
    st.page_link("pages/6_System_Info.py", label="System Diagnostics →", icon="ℹ️")

# ── Live WAF Smoke Test ────────────────────────────────────────────────────────
st.markdown('<div class="section-header">⚡ Instant WAF Smoke Test</div>', unsafe_allow_html=True)
st.caption("Send live test requests directly through the WAF Gateway to verify protection rules in real time:")

tc1, tc2, tc3 = st.columns(3)

with tc1:
    if st.button("🟢 Send Legitimate Request", use_container_width=True):
        res = send_test_request("GET", "/items")
        st.session_state["quick_test"] = {
            "type": "Safe Request (`GET /items`)",
            "decision": res.get("decision"),
            "status": res.get("status_code"),
            "time": res.get("processing_time_ms"),
            "request_id": res.get("request_id"),
        }

with tc2:
    if st.button("🔴 Send SQL Injection Probe", use_container_width=True):
        res = send_test_request("GET", "/items", params={"search": "' OR '1'='1"})
        st.session_state["quick_test"] = {
            "type": "SQL Injection (`' OR '1'='1`)",
            "decision": res.get("decision"),
            "status": res.get("status_code"),
            "time": res.get("processing_time_ms"),
            "request_id": res.get("request_id"),
        }

with tc3:
    if st.button("🔴 Send XSS Script Probe", use_container_width=True):
        res = send_test_request("GET", "/items", params={"search": "<script>alert(1)</script>"})
        st.session_state["quick_test"] = {
            "type": "XSS Probe (`<script>alert(1)</script>`)",
            "decision": res.get("decision"),
            "status": res.get("status_code"),
            "time": res.get("processing_time_ms"),
            "request_id": res.get("request_id"),
        }

if "quick_test" in st.session_state:
    qt = st.session_state["quick_test"]
    dec = qt.get("decision", "UNKNOWN")
    color = "#22c55e" if dec == "ALLOW" else "#ef4444"
    st.markdown(f"""
    <div class="quick-test-box">
        <strong>Test:</strong> {qt.get('type')}<br>
        <strong>Decision:</strong> <span style="color:{color};font-weight:700;">{dec}</span> &nbsp;|&nbsp;
        <strong>HTTP Status:</strong> <code>{qt.get('status')}</code> &nbsp;|&nbsp;
        <strong>Latency:</strong> <code>{qt.get('time')} ms</code> &nbsp;|&nbsp;
        <strong>Request ID:</strong> <code>{qt.get('request_id')}</code>
    </div>
    """, unsafe_allow_html=True)
