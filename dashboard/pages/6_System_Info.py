"""
Page 6: System Information
Gateway health, DB stats, architecture summary.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
import requests as req_lib

from api_client import get_gateway_health, get_db_stats, get_rules, GATEWAY_URL

st.set_page_config(page_title="System Info | SentinelShield", page_icon="🖥️", layout="wide")

st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
.stApp{background:#020817;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0a0f1e,#0d1530);border-right:1px solid #1e2d4a;}
.health-ok{background:#052e16;border:1px solid #16a34a;color:#86efac;padding:0.6rem 1rem;border-radius:6px;font-weight:600;}
.health-err{background:#450a0a;border:1px solid #991b1b;color:#f87171;padding:0.6rem 1rem;border-radius:6px;font-weight:600;}
.health-unk{background:#1c1917;border:1px solid #78716c;color:#a8a29e;padding:0.6rem 1rem;border-radius:6px;font-weight:600;}
.info-card{background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;padding:1.25rem;margin:0.5rem 0;}
</style>""", unsafe_allow_html=True)

st.markdown("# 🖥️ System Information")

VERSION = "1.0.0"

# ── Health Checks ──────────────────────────────────────────────────────────────
st.markdown("## 🩺 Service Health")

col1, col2, col3 = st.columns(3)

# Gateway
with col1:
    try:
        gw = get_gateway_health()
        status = gw.get("status", "unknown")
        is_ok = status == "healthy"
        cls = "health-ok" if is_ok else "health-err"
        icon = "✅" if is_ok else "❌"
        st.markdown(f"""<div class="{cls}">
          {icon} WAF Gateway<br>
          <small>Status: {status} | DB: {'✅' if gw.get('db_connected') else '❌'}</small>
        </div>""", unsafe_allow_html=True)
    except Exception:
        st.markdown('<div class="health-err">❌ WAF Gateway — Unreachable</div>', unsafe_allow_html=True)

# Protected App (through gateway proxy)
with col2:
    try:
        r = req_lib.get(f"{GATEWAY_URL}/health", timeout=5)
        data = r.json()
        is_ok = r.ok
        cls = "health-ok" if is_ok else "health-err"
        icon = "✅" if is_ok else "❌"
        # Get protected app health
        r2 = req_lib.get(f"{GATEWAY_URL}/health-proxy-check", timeout=5)
        papp_status = "reachable via gateway"
        st.markdown(f"""<div class="{cls}">
          {icon} Protected App<br>
          <small>Accessible through gateway only</small>
        </div>""", unsafe_allow_html=True)
    except Exception:
        st.markdown('<div class="health-unk">⚠️ Protected App — Status unknown</div>', unsafe_allow_html=True)

# Dashboard self
with col3:
    st.markdown("""<div class="health-ok">
      ✅ Dashboard (this)<br>
      <small>Streamlit — Running</small>
    </div>""", unsafe_allow_html=True)

st.divider()

# ── DB Stats ───────────────────────────────────────────────────────────────────
st.markdown("## 🗄️ Database Statistics")
db = get_db_stats()
rules = get_rules()

if db:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events", f"{db.get('event_count', 0):,}")
    c2.metric("Total Rules", db.get("rule_count", 0))
    c3.metric("Enabled Rules", db.get("enabled_rules", 0))
    c4.metric("Audit Events", db.get("audit_count", 0))

    st.markdown(f"""
    <div class="info-card">
      <strong style="color:#06b6d4">Database Path:</strong> {db.get('db_path','N/A')}<br>
      <strong style="color:#06b6d4">Oldest Event:</strong> {db.get('oldest_event','N/A')}<br>
      <strong style="color:#06b6d4">Newest Event:</strong> {db.get('newest_event','N/A')}
    </div>
    """, unsafe_allow_html=True)

st.divider()

# ── Version info ───────────────────────────────────────────────────────────────
st.markdown("## ℹ️ Application Version")
st.markdown(f"""
<div class="info-card">
  <strong style="color:#06b6d4">SentinelShield Version:</strong> {VERSION}<br>
  <strong style="color:#06b6d4">Dashboard:</strong> Streamlit<br>
  <strong style="color:#06b6d4">Gateway:</strong> Flask + Gunicorn<br>
  <strong style="color:#06b6d4">Database:</strong> SQLite (WAL mode)<br>
  <strong style="color:#06b6d4">Containerisation:</strong> Docker Compose
</div>
""", unsafe_allow_html=True)

st.divider()

# ── Architecture ───────────────────────────────────────────────────────────────
st.markdown("## 🏗️ Architecture")
st.markdown("""
```
Browser / Demo Client (port 8501)
         │
         ▼
┌─────────────────────┐
│  Streamlit Dashboard │  ← Security overview, attack sim, logs, rules
└────────┬────────────┘
         │ HTTP API calls
         ▼
┌─────────────────────┐
│   Flask WAF Gateway  │  ← port 5000 (host-bound)
│  ┌────────────────┐  │
│  │ Rule Engine    │  │  ← SQL/XSS/PT/Validation/Rate-limit
│  │ Event Logger   │  │  ← SQLite (named Docker volume)
│  └────────────────┘  │
└────────┬────────────┘
         │ Docker internal network only
         ▼
┌─────────────────────┐
│  Protected Demo App  │  ← NOT exposed to host (internal only)
│  /search /items etc  │
└─────────────────────┘
```
""")

st.markdown("""
**Security Properties:**
- The protected app has **no host port binding** — unreachable directly from the browser.
- All traffic to the protected app passes through the WAF rule engine.
- Security events are stored in a named Docker volume (persists container restarts).
- Containers run as **non-root users**.
- Admin API endpoints require an `X-API-Key` header.
""")
