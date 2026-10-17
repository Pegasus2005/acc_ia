"""
Page 2: Attack Simulator
Sends real requests through the WAF gateway and displays outcomes.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import streamlit as st
import time
import json
import requests as req_lib

from api_client import send_test_request, update_rule, reset_rules, get_rules, GATEWAY_URL

st.set_page_config(page_title="Attack Simulator | SentinelShield", page_icon="⚔️", layout="wide")

st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html,body,[class*="css"]{font-family:'Inter',sans-serif;}
.stApp{background:#020817;}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0a0f1e,#0d1530);border-right:1px solid #1e2d4a;}
.result-card{background:#0f172a;border:1px solid #1e3a5f;border-radius:10px;padding:1.25rem;margin:0.75rem 0;}
.pass{border-left:4px solid #22c55e;}
.fail{border-left:4px solid #ef4444;}
.neutral{border-left:4px solid #06b6d4;}
.badge{padding:0.2rem 0.6rem;border-radius:4px;font-size:0.75rem;font-weight:600;}
.badge-block{background:#450a0a;color:#f87171;border:1px solid #991b1b;}
.badge-allow{background:#052e16;color:#86efac;border:1px solid #166534;}
.badge-rate{background:#431407;color:#fb923c;border:1px solid #9a3412;}
.badge-val{background:#2e1065;color:#c4b5fd;border:1px solid #6d28d9;}
</style>""", unsafe_allow_html=True)

st.markdown("# ⚔️ Attack Simulator")
st.caption("All requests are sent through the WAF gateway — never directly to the protected app.")

# ── Scenario definitions ───────────────────────────────────────────────────────
SCENARIOS = {
    "1. Normal Search Request": {
        "description": "A legitimate search query that should pass all security checks.",
        "method": "GET",
        "path": "search",
        "params": {"q": "firewall security best practices"},
        "expected": "ALLOW",
        "category": "Baseline",
    },
    "2. SQL Injection Pattern": {
        "description": "Classic SQL tautology (' OR '1'='1) — should be blocked by SQL-001.",
        "method": "GET",
        "path": "search",
        "params": {"q": "' OR '1'='1' --"},
        "expected": "BLOCK",
        "category": "SQL_INJECTION",
    },
    "3. UNION SELECT Injection": {
        "description": "UNION SELECT data extraction attempt — should be blocked by SQL-002.",
        "method": "GET",
        "path": "search",
        "params": {"q": "test' UNION SELECT username,password FROM users--"},
        "expected": "BLOCK",
        "category": "SQL_INJECTION",
    },
    "4. XSS Script Tag": {
        "description": "Script tag injection — detected but never executed. Blocked by XSS-001.",
        "method": "GET",
        "path": "search",
        "params": {"q": "<script>alert('xss')</script>"},
        "expected": "BLOCK",
        "category": "XSS",
    },
    "5. XSS Event Handler": {
        "description": "Event handler injection pattern. Blocked by XSS-003.",
        "method": "GET",
        "path": "search",
        "params": {"q": "<img src=x onerror=alert(1)>"},
        "expected": "BLOCK",
        "category": "XSS",
    },
    "6. Path Traversal": {
        "description": "Directory traversal attempt with ../ sequences. Blocked by PT-001.",
        "method": "GET",
        "path": "search",
        "params": {"q": "../../etc/passwd"},
        "expected": "BLOCK",
        "category": "PATH_TRAVERSAL",
    },
    "7. Rate Limit Test": {
        "description": "Sends 35 rapid requests to trigger rate limiting (RL-001).",
        "method": "GET",
        "path": "search",
        "params": {"q": "rate-limit-test"},
        "expected": "RATE_LIMITED",
        "category": "RATE_LIMIT",
        "repeat": 35,
    },
    "8. Oversized Request": {
        "description": "POST with body exceeding the configured size limit (VAL-002).",
        "method": "POST",
        "path": "feedback",
        "body_size_kb": 200,
        "expected": "BLOCK",
        "category": "VALIDATION",
    },
    "9. Rule Toggle Test (SQL-001)": {
        "description": "Disable SQL-001, re-test the tautology — expect ALLOW. Then restore.",
        "method": "GET",
        "path": "search",
        "params": {"q": "' OR '1'='1"},
        "expected": "ALLOW_THEN_BLOCK",
        "category": "RULE_MANAGEMENT",
        "toggle_rule": "SQL-001",
    },
    "10. Custom Safe Input": {
        "description": "Enter your own safe search term below.",
        "method": "GET",
        "path": "search",
        "expected": "ALLOW",
        "category": "Custom",
        "custom": True,
    },
}

# ── UI ─────────────────────────────────────────────────────────────────────────
selected = st.selectbox("Select scenario:", list(SCENARIOS.keys()))
scenario = SCENARIOS[selected]

st.markdown(f"""
<div style="background:#0f172a;border:1px solid #1e3a5f;border-radius:8px;padding:1rem;margin:0.5rem 0">
  <strong style="color:#06b6d4">📋 Scenario:</strong> {scenario['description']}<br>
  <strong style="color:#06b6d4">Method:</strong> {scenario.get('method','GET')} &nbsp;
  <strong style="color:#06b6d4">Path:</strong> /{scenario.get('path','search')} &nbsp;
  <strong style="color:#06b6d4">Expected:</strong> {scenario.get('expected','?')}
</div>
""", unsafe_allow_html=True)

custom_input = ""
if scenario.get("custom"):
    custom_input = st.text_input("Your search term:", value="network security audit")

run_btn = st.button("🚀 Run Scenario", type="primary", use_container_width=False)

if run_btn:
    result_placeholder = st.empty()

    # ── Rate limit test (multi-request) ────────────────────────────────────────
    if scenario.get("repeat"):
        with st.spinner(f"Sending {scenario['repeat']} requests..."):
            results_list = []
            progress = st.progress(0)
            for i in range(scenario["repeat"]):
                r = send_test_request(
                    method=scenario["method"],
                    path=scenario["path"],
                    params=scenario.get("params", {}),
                )
                results_list.append(r)
                progress.progress((i + 1) / scenario["repeat"])
                time.sleep(0.05)

        decisions = [r.get("decision","?") for r in results_list]
        rate_limited = [d for d in decisions if d == "RATE_LIMITED"]
        allowed = [d for d in decisions if d == "ALLOW"]

        passed = len(rate_limited) > 0

        st.markdown(f"""
        <div class="result-card {'pass' if passed else 'fail'}">
          <strong style="color:{'#22c55e' if passed else '#ef4444'}">
            {'✅ PASS' if passed else '❌ FAIL'} — Rate Limit Test
          </strong><br><br>
          Total requests sent: <strong>{len(results_list)}</strong><br>
          Allowed: <strong style="color:#22c55e">{len(allowed)}</strong> &nbsp;
          Rate Limited: <strong style="color:#f59e0b">{len(rate_limited)}</strong><br>
          Last decision: <strong>{decisions[-1]}</strong><br>
          <em style="color:#64748b;font-size:0.8rem">Rate limiting activated after configured threshold.</em>
        </div>
        """, unsafe_allow_html=True)

    # ── Oversized request ───────────────────────────────────────────────────────
    elif scenario.get("body_size_kb"):
        size_kb = scenario["body_size_kb"]
        payload = {"message": "A" * (size_kb * 1024), "name": "TestUser"}
        with st.spinner("Sending oversized request..."):
            t0 = time.perf_counter()
            try:
                r = req_lib.post(
                    f"{GATEWAY_URL}/feedback",
                    json=payload,
                    timeout=15,
                )
                elapsed = (time.perf_counter() - t0) * 1000
                decision = r.headers.get("X-SentinelShield-Decision", "UNKNOWN")
                request_id = r.headers.get("X-SentinelShield-Request-ID", "N/A")
                try:
                    body = r.json()
                except Exception:
                    body = {"raw": r.text[:200]}
            except Exception as e:
                decision = "ERROR"
                elapsed = 0
                request_id = "N/A"
                body = {"error": str(e)}

        passed = r.status_code in (400, 403) if "r" in dir() else False
        badge_cls = "badge-block" if passed else "badge-allow"

        st.markdown(f"""
        <div class="result-card {'pass' if passed else 'fail'}">
          <strong style="color:{'#22c55e' if passed else '#ef4444'}">
            {'✅ PASS' if passed else '❌ FAIL'} — Oversized Request
          </strong><br><br>
          Body size sent: <strong>{size_kb} KB</strong><br>
          HTTP Status: <strong>{r.status_code if "r" in dir() else "N/A"}</strong><br>
          Decision: <span class="badge {badge_cls}">{decision}</span><br>
          Request ID: <code>{request_id}</code><br>
          Processing: <strong>{elapsed:.1f} ms</strong><br>
        </div>
        """, unsafe_allow_html=True)

    # ── Rule toggle test ────────────────────────────────────────────────────────
    elif scenario.get("toggle_rule"):
        rule_id = scenario["toggle_rule"]
        with st.spinner("Running rule toggle test..."):
            # Step 1: Disable rule
            update_rule(rule_id, False)
            time.sleep(0.3)

            # Step 2: Send payload — should now be ALLOWED
            r_disabled = send_test_request(
                method=scenario["method"],
                path=scenario["path"],
                params=scenario.get("params", {}),
            )
            time.sleep(0.2)

            # Step 3: Re-enable rule
            update_rule(rule_id, True)
            time.sleep(0.3)

            # Step 4: Send same payload — should now be BLOCKED
            r_enabled = send_test_request(
                method=scenario["method"],
                path=scenario["path"],
                params=scenario.get("params", {}),
            )

        passed = (
            r_disabled.get("decision") == "ALLOW"
            and r_enabled.get("decision") == "BLOCK"
        )

        st.markdown(f"""
        <div class="result-card {'pass' if passed else 'fail'}">
          <strong style="color:{'#22c55e' if passed else '#ef4444'}">
            {'✅ PASS' if passed else '❌ FAIL'} — Rule Toggle Test ({rule_id})
          </strong><br><br>
          <b>Step 1:</b> Rule {rule_id} DISABLED → Decision: 
          <span class="badge badge-{'allow' if r_disabled.get('decision')=='ALLOW' else 'block'}">
            {r_disabled.get('decision','?')}
          </span><br>
          <b>Step 2:</b> Rule {rule_id} RE-ENABLED → Decision: 
          <span class="badge badge-{'block' if r_enabled.get('decision')=='BLOCK' else 'allow'}">
            {r_enabled.get('decision','?')}
          </span><br><br>
          ✅ Rule {rule_id} restored to enabled state.<br>
          <em style="color:#64748b;font-size:0.8rem">
            Disabling a rule allows previously blocked payloads through — 
            demonstrating why rule management is security-critical.
          </em>
        </div>
        """, unsafe_allow_html=True)

    # ── Standard request ────────────────────────────────────────────────────────
    else:
        params = scenario.get("params", {})
        if scenario.get("custom"):
            params = {"q": custom_input}

        with st.spinner("Sending request through gateway..."):
            result = send_test_request(
                method=scenario.get("method", "GET"),
                path=scenario.get("path", "search"),
                params=params,
            )

        decision    = result.get("decision", "UNKNOWN")
        expected    = scenario.get("expected", "")
        status_code = result.get("status_code", 0)
        request_id  = result.get("request_id", "N/A")
        proc_time   = result.get("processing_time_ms", 0)
        resp        = result.get("response", {})
        matched     = resp.get("matched_rule_ids", []) if isinstance(resp, dict) else []
        reason      = resp.get("reason", "") if isinstance(resp, dict) else ""
        mitigation  = resp.get("mitigation", "") if isinstance(resp, dict) else ""

        # Pass/fail check
        if expected == "ALLOW":
            passed = decision == "ALLOW"
        elif expected == "BLOCK":
            passed = decision in ("BLOCK", "RATE_LIMITED", "VALIDATION_ERROR")
        else:
            passed = True  # unknown expected

        badge_map = {
            "ALLOW": "badge-allow",
            "BLOCK": "badge-block",
            "RATE_LIMITED": "badge-rate",
            "VALIDATION_ERROR": "badge-val",
        }
        badge_cls = badge_map.get(decision, "badge-block")

        st.markdown(f"""
        <div class="result-card {'pass' if passed else 'fail'}">
          <strong style="color:{'#22c55e' if passed else '#ef4444'}">
            {'✅ PASS' if passed else '❌ FAIL'} — {selected.split('. ',1)[-1]}
          </strong><br><br>

          <table style="width:100%;font-size:0.875rem;border-collapse:collapse">
            <tr><td style="color:#64748b;padding:0.2rem 0.5rem 0.2rem 0;width:40%">HTTP Status</td>
                <td><strong>{status_code}</strong></td></tr>
            <tr><td style="color:#64748b;padding:0.2rem 0.5rem 0.2rem 0">Gateway Decision</td>
                <td><span class="badge {badge_cls}">{decision}</span></td></tr>
            <tr><td style="color:#64748b;padding:0.2rem 0.5rem 0.2rem 0">Expected</td>
                <td><strong>{expected}</strong></td></tr>
            <tr><td style="color:#64748b;padding:0.2rem 0.5rem 0.2rem 0">Request ID</td>
                <td><code style="font-size:0.75rem">{request_id}</code></td></tr>
            <tr><td style="color:#64748b;padding:0.2rem 0.5rem 0.2rem 0">Processing Time</td>
                <td><strong>{proc_time} ms</strong></td></tr>
            {'<tr><td style="color:#64748b;padding:0.2rem 0.5rem 0.2rem 0">Matched Rules</td><td><code>' + ", ".join(matched) + '</code></td></tr>' if matched else ''}
            {'<tr><td style="color:#64748b;padding:0.2rem 0.5rem 0.2rem 0">Reason</td><td>' + str(reason)[:200] + '</td></tr>' if reason else ''}
            {'<tr><td style="color:#64748b;padding:0.2rem 0.5rem 0.2rem 0">Mitigation</td><td style="color:#86efac">' + str(mitigation)[:200] + '</td></tr>' if mitigation else ''}
          </table>
        </div>
        """, unsafe_allow_html=True)

        if request_id and request_id != "N/A":
            st.caption(f"💡 Find this event in **Security Logs** by searching for request ID: `{request_id}`")

st.divider()
st.markdown("""
<div style="background:#0c1a2e;border:1px solid #1e3a5f;border-radius:8px;padding:1rem;font-size:0.82rem;color:#64748b">
  ⚠️ <strong>Educational Disclaimer:</strong> This simulator uses harmless, predefined test payloads against 
  a local demo application only. It cannot target external systems. The payloads are detected but never executed.
</div>
""", unsafe_allow_html=True)
