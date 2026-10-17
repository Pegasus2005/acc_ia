"""
SentinelShield Security Dashboard
Multi-page Streamlit application for monitoring, analytics, and attack simulation.
"""

import streamlit as st

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

/* ── KPI Cards ── */
.kpi-card {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
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
.kpi-icon {
    font-size: 1.5rem;
}

/* Colour variants */
.kpi-danger .kpi-value  { color: #ef4444; }
.kpi-warning .kpi-value { color: #f59e0b; }
.kpi-success .kpi-value { color: #22c55e; }
.kpi-info .kpi-value    { color: #06b6d4; }

/* ── Section headers ── */
.section-header {
    color: #06b6d4;
    font-size: 1rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 0.5rem;
    margin: 1.5rem 0 1rem;
}

/* ── Alert badges ── */
.badge-block   { background:#450a0a; color:#f87171; border:1px solid #991b1b; padding:0.15rem 0.5rem; border-radius:4px; font-size:0.75rem; }
.badge-allow   { background:#052e16; color:#86efac; border:1px solid #166534; padding:0.15rem 0.5rem; border-radius:4px; font-size:0.75rem; }
.badge-rate    { background:#431407; color:#fb923c; border:1px solid #9a3412; padding:0.15rem 0.5rem; border-radius:4px; font-size:0.75rem; }
.badge-info    { background:#0c1a2e; color:#7dd3fc; border:1px solid #1e40af; padding:0.15rem 0.5rem; border-radius:4px; font-size:0.75rem; }

/* ── Scenario result card ── */
.scenario-result {
    background: #0f172a;
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 1.25rem;
    margin: 0.75rem 0;
}
.scenario-pass { border-left: 4px solid #22c55e; }
.scenario-fail { border-left: 4px solid #ef4444; }
.scenario-info { border-left: 4px solid #06b6d4; }

/* ── Streamlit overrides ── */
.stSelectbox > div > div {
    background: #1e293b;
    border-color: #1e3a5f;
}
.stButton > button {
    background: linear-gradient(135deg, #0e7490, #0891b2);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    transition: all 0.2s;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #0891b2, #06b6d4);
    box-shadow: 0 4px 15px rgba(6, 182, 212, 0.3);
}
div[data-testid="stMetric"] {
    background: #0f172a;
    border: 1px solid #1e3a5f;
    border-radius: 10px;
    padding: 1rem;
}
div[data-testid="stMetricValue"] { color: #06b6d4; }
</style>
""", unsafe_allow_html=True)
