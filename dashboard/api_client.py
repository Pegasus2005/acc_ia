"""
Dashboard utility: shared API client for communicating with the WAF gateway.
"""

import os
import requests
import streamlit as st

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:5000")
# Render injects hostname only without scheme; ensure we always have a scheme
if GATEWAY_URL and not GATEWAY_URL.startswith(("http://", "https://")):
    GATEWAY_URL = "https://" + GATEWAY_URL
API_SECRET = os.environ.get("API_SECRET", "sentinelshield-demo-secret")

_HEADERS = {"X-API-Key": API_SECRET, "Content-Type": "application/json"}
_TIMEOUT = 10


def _get(endpoint: str, params: dict = None) -> dict:
    try:
        r = requests.get(
            f"{GATEWAY_URL}{endpoint}", params=params,
            headers=_HEADERS, timeout=_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Cannot connect to the WAF gateway. Is it running?")
        return {}
    except Exception as e:
        st.error(f"API error: {e}")
        return {}


def _post(endpoint: str, json_data: dict = None) -> dict:
    try:
        r = requests.post(
            f"{GATEWAY_URL}{endpoint}", json=json_data,
            headers=_HEADERS, timeout=_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API error: {e}")
        return {}


def _patch(endpoint: str, json_data: dict = None) -> dict:
    try:
        r = requests.patch(
            f"{GATEWAY_URL}{endpoint}", json=json_data,
            headers=_HEADERS, timeout=_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API error: {e}")
        return {}


def get_stats() -> dict:
    return _get("/api/stats")


def get_events(**kwargs) -> dict:
    return _get("/api/events", params={k: v for k, v in kwargs.items() if v is not None})


def get_chart_data() -> list:
    data = _get("/api/charts")
    return data.get("events", [])


def get_rules() -> list:
    data = _get("/api/rules")
    return data.get("rules", [])


def update_rule(rule_id: str, enabled: bool) -> dict:
    return _patch(f"/api/rules/{rule_id}", {"enabled": enabled})


def reset_rules() -> dict:
    return _post("/api/rules/reset")


def reset_demo() -> dict:
    return _post("/api/demo/reset")


def get_db_stats() -> dict:
    return _get("/api/db-stats")


def get_gateway_health() -> dict:
    return _get("/health")


def get_protected_health() -> dict:
    """Check protected app health through the gateway proxy."""
    try:
        r = requests.get(f"{GATEWAY_URL}/health", timeout=5)
        return r.json() if r.ok else {"status": "unknown"}
    except Exception:
        return {"status": "unknown"}


def send_test_request(method: str, path: str, params: dict = None, body: dict = None) -> dict:
    """
    Send a test request through the gateway and return timing + response details.
    """
    import time
    url = f"{GATEWAY_URL}/{path.lstrip('/')}"
    t_start = time.perf_counter()
    try:
        if method.upper() == "GET":
            r = requests.get(url, params=params, timeout=15)
        elif method.upper() == "POST":
            r = requests.post(url, json=body, params=params, timeout=15)
        else:
            r = requests.request(method, url, params=params, json=body, timeout=15)

        elapsed = (time.perf_counter() - t_start) * 1000
        try:
            resp_json = r.json()
        except Exception:
            resp_json = {"raw": r.text[:500]}

        return {
            "status_code": r.status_code,
            "decision": r.headers.get("X-SentinelShield-Decision", "UNKNOWN"),
            "request_id": r.headers.get("X-SentinelShield-Request-ID", ""),
            "processing_time_ms": round(elapsed, 1),
            "response": resp_json,
            "headers": dict(r.headers),
        }
    except requests.exceptions.Timeout:
        return {"status_code": 504, "decision": "TIMEOUT", "error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"status_code": 0, "decision": "ERROR", "error": "Cannot connect to gateway"}
    except Exception as e:
        return {"status_code": 0, "decision": "ERROR", "error": str(e)}
