"""
Page 5: Reports & Analytics
Aggregate analytics with CSV export and concise text summary.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
from collections import Counter
from io import StringIO
from datetime import datetime, timezone

from api_client import get_stats, get_chart_data, get_rules

st.set_page_config(page_title="Reports | SentinelShield", page_icon="📊", layout="wide")

st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
.stApp{background:#020817;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0a0f1e,#0d1530);border-right:1px solid #1e2d4a;}
</style>""", unsafe_allow_html=True)

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(15,23,42,0.8)",
    font=dict(color="#94a3b8", family="Inter"),
    title_font=dict(color="#06b6d4", size=14),
    margin=dict(l=20, r=20, t=40, b=20),
    legend=dict(bgcolor="rgba(0,0,0,0)"),
)

st.markdown("# 📊 Reports & Analytics")
st.caption("Aggregate analysis of all security events.")

stats = get_stats()
chart_events = get_chart_data()
rules = get_rules()

if not stats or not chart_events:
    st.info("No data yet — run the Attack Simulator to generate events.")
    st.stop()

df = pd.DataFrame(chart_events)
df["timestamp_utc"] = pd.to_datetime(df["timestamp_utc"], utc=True, errors="coerce")
df = df.dropna(subset=["timestamp_utc"])

# ── Summary Stats ──────────────────────────────────────────────────────────────
st.markdown("## 📈 Summary Statistics")
col1, col2, col3, col4 = st.columns(4)

total = stats.get("total", 0)
blocked = stats.get("total_blocked", 0)
block_pct = stats.get("block_percentage", 0)
enabled_rules = sum(1 for r in rules if r.get("enabled", 1))

col1.metric("Total Requests", f"{total:,}")
col2.metric("Total Blocked", f"{blocked:,}")
col3.metric("Block Rate", f"{block_pct}%")
col4.metric("Active Rules", f"{enabled_rules} / {len(rules)}")

st.divider()

# ── Category breakdown ─────────────────────────────────────────────────────────
col_a, col_b = st.columns(2)

with col_a:
    cat_counts = df["attack_category"].value_counts().reset_index()
    cat_counts.columns = ["Category", "Count"]
    fig1 = px.pie(cat_counts, names="Category", values="Count",
                  title="Attack Category Distribution",
                  color_discrete_sequence=px.colors.sequential.Blues_r)
    fig1.update_layout(**PLOTLY_LAYOUT)
    st.plotly_chart(fig1, use_container_width=True)

with col_b:
    rule_counter: Counter = Counter()
    for ev in chart_events:
        try:
            ids = json.loads(ev.get("matched_rule_ids", "[]"))
            rule_counter.update(ids)
        except Exception:
            pass

    if rule_counter:
        top_df = pd.DataFrame(rule_counter.most_common(10), columns=["Rule ID", "Hits"])
        fig2 = px.bar(top_df, x="Hits", y="Rule ID", orientation="h",
                      title="Rule Trigger Frequency",
                      color="Hits",
                      color_continuous_scale=["#0e4f6e", "#06b6d4"])
        fig2.update_layout(coloraxis_showscale=False, **PLOTLY_LAYOUT)
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No rule matches recorded yet.")

# ── Time trend ─────────────────────────────────────────────────────────────────
df["day"] = df["timestamp_utc"].dt.date
daily = df.groupby(["day", "decision"]).size().reset_index(name="count")
COLOR_MAP = {"ALLOW": "#22c55e", "BLOCK": "#ef4444",
             "RATE_LIMITED": "#f59e0b", "VALIDATION_ERROR": "#a78bfa"}
fig3 = px.bar(daily, x="day", y="count", color="decision",
              color_discrete_map=COLOR_MAP,
              title="Daily Request Trend by Decision",
              labels={"day": "Date", "count": "Requests", "decision": "Decision"})
fig3.update_layout(**PLOTLY_LAYOUT)
st.plotly_chart(fig3, use_container_width=True)

# ── Disclaimer ─────────────────────────────────────────────────────────────────
st.divider()
st.markdown("""
> **⚠️ Important Limitation:** These statistics reflect requests processed by this educational WAF gateway only.
> A high block percentage against known test payloads does **not** imply protection against all real-world attacks.
> Pattern-based rules have known false-positive and false-negative rates.
> This is an academic demonstration tool, not a production security control.
""")

# ── CSV & Text Report Export ───────────────────────────────────────────────────
st.divider()
st.markdown("## 📥 Export")

# CSV export
export_df = df[["timestamp_utc", "decision", "attack_category", "severity", "matched_rule_ids"]].copy()
export_df["timestamp_utc"] = export_df["timestamp_utc"].astype(str)
csv_buf = StringIO()
export_df.to_csv(csv_buf, index=False)

col_csv, col_txt = st.columns(2)
with col_csv:
    st.download_button(
        "⬇️ Download Event CSV",
        data=csv_buf.getvalue(),
        file_name=f"sentinelshield_analytics_{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv",
    )

# Text summary report
report_lines = [
    "SentinelShield WAF — Security Summary Report",
    "=" * 50,
    f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
    "",
    f"Total Requests Inspected : {total:,}",
    f"Requests Allowed         : {stats.get('allowed', 0):,}",
    f"Requests Blocked         : {stats.get('blocked', 0):,}",
    f"Rate Limited             : {stats.get('rate_limited', 0):,}",
    f"Block Rate               : {block_pct}%",
    f"Active Rules             : {enabled_rules} / {len(rules)}",
    f"Top Triggered Rule       : {stats.get('top_rule_id', 'N/A')}",
    "",
    "Attack Category Breakdown:",
]
for _, row in cat_counts.iterrows():
    report_lines.append(f"  {row['Category']:20s}: {row['Count']:,}")

if rule_counter:
    report_lines += ["", "Top 5 Rule Triggers:"]
    for rule_id, count in rule_counter.most_common(5):
        report_lines.append(f"  {rule_id:12s}: {count:,} times")

report_lines += [
    "",
    "IMPORTANT: This report reflects educational WAF test data only.",
    "Pattern-based detection has known false-positive and false-negative rates.",
]

with col_txt:
    st.download_button(
        "⬇️ Download Text Report",
        data="\n".join(report_lines),
        file_name=f"sentinelshield_report_{datetime.now().strftime('%Y%m%d')}.txt",
        mime="text/plain",
    )
