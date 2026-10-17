"""
Page 1: Security Overview
Real-time KPI cards and charts from actual WAF event data.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json

from api_client import get_stats, get_chart_data

st.set_page_config(page_title="Overview | SentinelShield", page_icon="🛡️", layout="wide")

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
.stApp{background:#020817;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0a0f1e,#0d1530);border-right:1px solid #1e2d4a;}
.kpi-card{background:linear-gradient(135deg,#0f172a,#1e293b);border:1px solid #1e3a5f;border-radius:12px;padding:1.2rem 1rem;text-align:center;margin-bottom:0.5rem;}
.kpi-value{font-size:2rem;font-weight:700;line-height:1;margin:0.4rem 0 0.2rem;}
.kpi-label{font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;font-weight:500;}
.kpi-cyan .kpi-value{color:#06b6d4;}
.kpi-red .kpi-value{color:#ef4444;}
.kpi-green .kpi-value{color:#22c55e;}
.kpi-amber .kpi-value{color:#f59e0b;}
</style>""", unsafe_allow_html=True)

st.markdown("# 🛡️ SentinelShield — Security Overview")
st.caption("All metrics are derived from actual stored security events.")

auto_refresh = st.sidebar.checkbox("Auto-refresh (30s)", value=False)
if auto_refresh:
    import time
    time.sleep(0.1)
    st.rerun()

if st.sidebar.button("🔄 Refresh Now"):
    st.rerun()

# ── Fetch data ─────────────────────────────────────────────────────────────────
stats = get_stats()
chart_events = get_chart_data()

if not stats:
    st.warning("Could not load statistics. Ensure the WAF gateway is running.")
    st.stop()

total       = stats.get("total", 0)
allowed     = stats.get("allowed", 0)
blocked     = stats.get("blocked", 0)
rate_lim    = stats.get("rate_limited", 0)
block_pct   = stats.get("block_percentage", 0)
top_rule    = stats.get("top_rule_id", "N/A")

# ── KPI Row ────────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5, c6 = st.columns(6)

with c1:
    st.markdown(f"""<div class="kpi-card kpi-cyan">
        <div class="kpi-label">Total Inspected</div>
        <div class="kpi-value">{total:,}</div>
    </div>""", unsafe_allow_html=True)

with c2:
    st.markdown(f"""<div class="kpi-card kpi-green">
        <div class="kpi-label">Allowed</div>
        <div class="kpi-value">{allowed:,}</div>
    </div>""", unsafe_allow_html=True)

with c3:
    st.markdown(f"""<div class="kpi-card kpi-red">
        <div class="kpi-label">Blocked</div>
        <div class="kpi-value">{blocked:,}</div>
    </div>""", unsafe_allow_html=True)

with c4:
    st.markdown(f"""<div class="kpi-card kpi-amber">
        <div class="kpi-label">Rate Limited</div>
        <div class="kpi-value">{rate_lim:,}</div>
    </div>""", unsafe_allow_html=True)

with c5:
    st.markdown(f"""<div class="kpi-card kpi-red">
        <div class="kpi-label">Block Rate</div>
        <div class="kpi-value">{block_pct}%</div>
    </div>""", unsafe_allow_html=True)

with c6:
    st.markdown(f"""<div class="kpi-card kpi-amber">
        <div class="kpi-label">Top Rule</div>
        <div class="kpi-value" style="font-size:1.1rem">{top_rule}</div>
    </div>""", unsafe_allow_html=True)

st.divider()

# ── Charts ─────────────────────────────────────────────────────────────────────
if not chart_events:
    st.info("No security events yet. Run the Attack Simulator to generate data.")
    st.stop()

df = pd.DataFrame(chart_events)
df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], utc=True, errors="coerce")
df = df.dropna(subset=["timestamp_utc"])

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(15,23,42,0.8)",
    font=dict(color="#94a3b8", family="Inter"),
    title_font=dict(color="#06b6d4", size=14),
    margin=dict(l=20, r=20, t=40, b=20),
    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#94a3b8")),
)

col_left, col_right = st.columns([1, 1])

with col_left:
    # Donut: Allow vs Block
    counts = df["decision"].value_counts().reset_index()
    counts.columns = ["Decision", "Count"]
    COLOR_MAP = {
        "ALLOW": "#22c55e", "BLOCK": "#ef4444",
        "RATE_LIMITED": "#f59e0b", "VALIDATION_ERROR": "#8b5cf6",
    }
    fig_donut = go.Figure(go.Pie(
        labels=counts["Decision"],
        values=counts["Count"],
        hole=0.55,
        marker_colors=[COLOR_MAP.get(d, "#64748b") for d in counts["Decision"]],
        textinfo="label+percent",
        textfont=dict(color="#e2e8f0"),
    ))
    fig_donut.update_layout(title_text="Allow vs Block Distribution", **PLOTLY_LAYOUT)
    st.plotly_chart(fig_donut, use_container_width=True)

with col_right:
    # Bar: Category
    cat_counts = df["attack_category"].value_counts().reset_index()
    cat_counts.columns = ["Category", "Count"]
    fig_bar = px.bar(
        cat_counts, x="Count", y="Category",
        orientation="h",
        color="Count",
        color_continuous_scale=["#0e4f6e", "#06b6d4"],
        labels={"Count": "Events", "Category": ""},
    )
    fig_bar.update_layout(title_text="Events by Attack Category",
                          coloraxis_showscale=False, **PLOTLY_LAYOUT)
    st.plotly_chart(fig_bar, use_container_width=True)

col3, col4 = st.columns([2, 1])

with col3:
    # Time series
    df_ts = df.copy()
    df_ts["hour"] = df_ts["timestamp_utc"].dt.floor("h")
    ts = df_ts.groupby(["hour", "decision"]).size().reset_index(name="count")
    fig_ts = px.area(
        ts, x="hour", y="count", color="decision",
        color_discrete_map=COLOR_MAP,
        labels={"hour": "Time", "count": "Requests", "decision": "Decision"},
    )
    fig_ts.update_traces(line_width=1.5)
    fig_ts.update_layout(title_text="Requests Over Time", **PLOTLY_LAYOUT)
    st.plotly_chart(fig_ts, use_container_width=True)

with col4:
    # Severity distribution
    sev_map = {"INFO": "#64748b", "LOW": "#22c55e", "MEDIUM": "#f59e0b",
               "HIGH": "#ef4444", "CRITICAL": "#dc2626"}
    sev_counts = df["severity"].value_counts().reset_index()
    sev_counts.columns = ["Severity", "Count"]
    fig_sev = px.pie(
        sev_counts, names="Severity", values="Count",
        color="Severity",
        color_discrete_map=sev_map,
        hole=0.4,
    )
    fig_sev.update_layout(title_text="Severity Distribution", **PLOTLY_LAYOUT)
    st.plotly_chart(fig_sev, use_container_width=True)

# Top rules bar
from collections import Counter
rule_counter: Counter = Counter()
for ev in chart_events:
    try:
        ids = json.loads(ev.get("matched_rule_ids", "[]"))
        rule_counter.update(ids)
    except Exception:
        pass

if rule_counter:
    top_rules_df = pd.DataFrame(rule_counter.most_common(8), columns=["Rule ID", "Hits"])
    fig_rules = px.bar(
        top_rules_df, x="Hits", y="Rule ID",
        orientation="h",
        color="Hits",
        color_continuous_scale=["#1e40af", "#ef4444"],
        labels={"Hits": "Times Triggered", "Rule ID": ""},
    )
    fig_rules.update_layout(title_text="Top Triggered Security Rules",
                            coloraxis_showscale=False, **PLOTLY_LAYOUT)
    st.plotly_chart(fig_rules, use_container_width=True)
