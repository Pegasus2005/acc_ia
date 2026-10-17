"""
Page 3: Security Logs
Searchable, filterable, exportable table of security events.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
import pandas as pd
import json
import re
from io import StringIO
from datetime import datetime, timedelta, timezone

from api_client import get_events

st.set_page_config(page_title="Security Logs | SentinelShield", page_icon="📋", layout="wide")

st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
.stApp{background:#020817;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0a0f1e,#0d1530);border-right:1px solid #1e2d4a;}
.stDataFrame{border:1px solid #1e3a5f;border-radius:8px;}
</style>""", unsafe_allow_html=True)

st.markdown("# 📋 Security Logs")
st.caption("Live event log from the WAF gateway SQLite database.")

# ── Filters ────────────────────────────────────────────────────────────────────
with st.expander("🔍 Filters", expanded=True):
    col1, col2, col3 = st.columns(3)
    with col1:
        decision_filter = st.selectbox(
            "Decision",
            ["All", "ALLOW", "BLOCK", "RATE_LIMITED", "VALIDATION_ERROR"],
        )
    with col2:
        severity_filter = st.selectbox(
            "Severity",
            ["All", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        )
    with col3:
        category_filter = st.selectbox(
            "Attack Category",
            ["All", "NONE", "SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "VALIDATION", "RATE_LIMIT"],
        )

    col4, col5, col6 = st.columns(3)
    with col4:
        days_back = st.slider("Show last N days", 1, 30, 7)
    with col5:
        page_size = st.selectbox("Rows per page", [25, 50, 100, 200], index=1)
    with col6:
        request_id_search = st.text_input("Search by Request ID")

if st.button("🔄 Refresh Logs"):
    st.rerun()

# ── Fetch ──────────────────────────────────────────────────────────────────────
from_ts = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()

# 'from' is a Python reserved word so we cannot use it as a keyword argument.
# Pass it through a plain dict and unpack with **.
params: dict = {"limit": page_size, "from": from_ts}
if decision_filter != "All":
    params["decision"] = decision_filter
if severity_filter != "All":
    params["severity"] = severity_filter
if category_filter != "All":
    params["category"] = category_filter
if request_id_search.strip():
    params["request_id"] = request_id_search.strip()

data = get_events(**params)
events = data.get("events", []) if data else []

st.caption(f"Showing {len(events)} events (last {days_back} days)")

if not events:
    st.info("No events match the current filters.")
    st.stop()

# ── Build DataFrame ────────────────────────────────────────────────────────────
df = pd.DataFrame(events)

# Parse matched_rule_ids from JSON string
def parse_rules(val):
    try:
        ids = json.loads(val) if isinstance(val, str) else val
        return ", ".join(ids) if ids else "—"
    except Exception:
        return str(val)

df["rules"] = df["matched_rule_ids"].apply(parse_rules) if "matched_rule_ids" in df.columns else "—"
df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], errors="coerce")
df["time"] = df["timestamp_utc"].dt.strftime("%Y-%m-%d %H:%M:%S")

display_cols = {
    "time": "Timestamp",
    "request_id": "Request ID",
    "method": "Method",
    "route": "Route",
    "decision": "Decision",
    "rules": "Matched Rules",
    "severity": "Severity",
    "status_code": "HTTP Status",
    "processing_time_ms": "Time (ms)",
    "attack_category": "Category",
}

display_df = df[[c for c in display_cols.keys() if c in df.columns]].rename(columns=display_cols)


def color_decision(val):
    colors = {
        "ALLOW": "color: #22c55e",
        "BLOCK": "color: #ef4444",
        "RATE_LIMITED": "color: #f59e0b",
        "VALIDATION_ERROR": "color: #a78bfa",
    }
    return colors.get(val, "")

styled = display_df.style.map(color_decision, subset=["Decision"])
st.dataframe(styled, use_container_width=True, hide_index=True, height=500)

# ── CSV Export ─────────────────────────────────────────────────────────────────
st.divider()
st.markdown("### 📥 Export")


def _sanitize_csv_value(val):
    """Prevent spreadsheet formula injection by escaping leading = + - @ chars."""
    s = str(val)
    if s and s[0] in ("=", "+", "-", "@", "|", "%"):
        return "'" + s
    return re.sub(r"[\r\n]", " ", s)


csv_df = display_df.copy()
for col in csv_df.columns:
    csv_df[col] = csv_df[col].apply(_sanitize_csv_value)

csv_buffer = StringIO()
csv_df.to_csv(csv_buffer, index=False)

st.download_button(
    label="⬇️ Download CSV",
    data=csv_buffer.getvalue(),
    file_name=f"sentinelshield_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
    mime="text/csv",
)
