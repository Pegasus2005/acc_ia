"""
Page 4: Rules & Configuration
View, toggle, and manage WAF security rules with audit trail.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
import pandas as pd

from api_client import get_rules, update_rule, reset_rules

st.set_page_config(page_title="Rules | SentinelShield", page_icon="⚙️", layout="wide")

st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
.stApp{background:#020817;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0a0f1e,#0d1530);border-right:1px solid #1e2d4a;}
.rule-card{background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;padding:1rem;margin:0.5rem 0;}
.rule-enabled{border-left:4px solid #22c55e;}
.rule-disabled{border-left:4px solid #ef4444;opacity:0.75;}
.sev-high{color:#ef4444;}
.sev-medium{color:#f59e0b;}
.sev-low{color:#22c55e;}
.sev-info{color:#64748b;}
</style>""", unsafe_allow_html=True)

st.markdown("# ⚙️ Security Rules & Configuration")
st.caption("Changes are persisted to the database and take effect immediately.")

# ── Load rules ─────────────────────────────────────────────────────────────────
rules = get_rules()
if not rules:
    st.warning("Could not load rules. Is the gateway running?")
    st.stop()

enabled_count = sum(1 for r in rules if r.get("enabled", 1))
st.info(f"**{enabled_count} / {len(rules)}** rules currently enabled.")

if enabled_count < 3:
    st.warning("⚠️ Many rules are disabled. Your WAF protection is significantly reduced.")

# ── Category filter ────────────────────────────────────────────────────────────
categories = sorted(set(r["category"] for r in rules))
selected_cat = st.selectbox("Filter by category:", ["All"] + categories)

filtered = rules if selected_cat == "All" else [r for r in rules if r["category"] == selected_cat]

sev_colors = {"HIGH": "sev-high", "MEDIUM": "sev-medium", "LOW": "sev-low", "INFO": "sev-info"}

# ── Rule cards ─────────────────────────────────────────────────────────────────
st.divider()

for rule in filtered:
    is_enabled = bool(rule.get("enabled", 1))
    card_cls = "rule-enabled" if is_enabled else "rule-disabled"
    sev_cls = sev_colors.get(rule["severity"], "")

    with st.container():
        col_info, col_toggle = st.columns([5, 1])

        with col_info:
            st.markdown(f"""
            <div class="rule-card {card_cls}">
              <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
                <code style="background:#1e293b;padding:0.2rem 0.5rem;border-radius:4px;color:#06b6d4">
                  {rule['rule_id']}
                </code>
                <strong style="color:#e2e8f0">{rule['name']}</strong>
                <span class="{sev_cls}" style="font-size:0.75rem;font-weight:600">{rule['severity']}</span>
                <span style="color:#64748b;font-size:0.75rem">[{rule['category']}]</span>
              </div>
              <div style="color:#94a3b8;font-size:0.85rem">{rule['description']}</div>
              <div style="color:#64748b;font-size:0.75rem;margin-top:0.4rem">
                Last updated: {(rule.get('updated_at') or 'N/A')[:19]}
              </div>
            </div>
            """, unsafe_allow_html=True)

        with col_toggle:
            st.markdown("<div style='height:1.5rem'></div>", unsafe_allow_html=True)
            new_state = st.toggle(
                "Enabled",
                value=is_enabled,
                key=f"toggle_{rule['rule_id']}",
            )
            if new_state != is_enabled:
                if not new_state and enabled_count <= 1:
                    st.error("Cannot disable the last active rule.")
                else:
                    result = update_rule(rule["rule_id"], new_state)
                    if result.get("success"):
                        action = "enabled" if new_state else "disabled"
                        st.success(f"Rule {rule['rule_id']} {action}.")
                        st.rerun()
                    else:
                        st.error("Failed to update rule.")

st.divider()

# ── Reset to defaults ──────────────────────────────────────────────────────────
st.markdown("### 🔄 Reset to Secure Defaults")
st.caption("Re-enables all rules. Changes are logged in the audit trail.")

col_warn, col_btn = st.columns([3, 1])
with col_warn:
    st.warning("This will re-enable ALL rules including any you have disabled during testing.")
with col_btn:
    if st.button("🔄 Reset All Rules", type="secondary"):
        st.session_state["confirm_reset"] = True

if st.session_state.get("confirm_reset"):
    confirm = st.checkbox("✅ Confirm reset — check this box then click Apply")
    if confirm:
        result = reset_rules()
        if result.get("success"):
            st.success("All rules restored to secure defaults.")
            st.session_state.pop("confirm_reset", None)
            st.rerun()
        else:
            st.error("Reset failed.")

# ── Rules summary table ────────────────────────────────────────────────────────
st.divider()
st.markdown("### 📊 Rules Summary")

summary_df = pd.DataFrame([{
    "Rule ID": r["rule_id"],
    "Name": r["name"],
    "Category": r["category"],
    "Severity": r["severity"],
    "Enabled": "✅ Yes" if r.get("enabled", 1) else "❌ No",
} for r in rules])

st.dataframe(summary_df, use_container_width=True, hide_index=True)
