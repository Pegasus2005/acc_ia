"""
SentinelShield - Integration Tests
Tests that send real HTTP requests through the running WAF gateway.
Requires the gateway to be running (docker compose up).

Run: pytest tests/test_integration.py -v
Or with gateway URL: GATEWAY_URL=http://localhost:5000 pytest tests/test_integration.py -v
"""

import os
import json
import time
import pytest
import requests

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:5000")
API_SECRET  = os.environ.get("API_SECRET", "sentinelshield-demo-secret")
HEADERS     = {"X-API-Key": API_SECRET}
TIMEOUT     = 10


def gateway_is_running() -> bool:
    """Check if the gateway is reachable."""
    try:
        r = requests.get(f"{GATEWAY_URL}/health", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not gateway_is_running(),
    reason="WAF gateway is not running — start with 'docker compose up'"
)


# ── Helper ────────────────────────────────────────────────────────────────────

def get_request_id(response: requests.Response) -> str:
    return response.headers.get("X-SentinelShield-Request-ID", "")


def get_decision(response: requests.Response) -> str:
    return response.headers.get("X-SentinelShield-Decision", "UNKNOWN")


# ── Gateway health ────────────────────────────────────────────────────────────

class TestGatewayHealth:

    def test_gateway_health_endpoint(self):
        r = requests.get(f"{GATEWAY_URL}/health", timeout=TIMEOUT)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert data["service"] == "sentinelshield-gateway"

    def test_gateway_returns_request_id_header(self):
        r = requests.get(f"{GATEWAY_URL}/search?q=test", timeout=TIMEOUT)
        assert "X-SentinelShield-Request-ID" in r.headers
        assert len(r.headers["X-SentinelShield-Request-ID"]) > 0

    def test_gateway_returns_decision_header(self):
        r = requests.get(f"{GATEWAY_URL}/search?q=test", timeout=TIMEOUT)
        assert "X-SentinelShield-Decision" in r.headers


# ── Legitimate traffic ────────────────────────────────────────────────────────

class TestLegitimateTraffic:

    def test_normal_search_is_allowed(self):
        r = requests.get(f"{GATEWAY_URL}/search", params={"q": "firewall"}, timeout=TIMEOUT)
        assert get_decision(r) == "ALLOW"
        assert r.status_code == 200

    def test_empty_search_is_allowed(self):
        r = requests.get(f"{GATEWAY_URL}/search", timeout=TIMEOUT)
        assert get_decision(r) == "ALLOW"

    def test_items_endpoint_is_allowed(self):
        r = requests.get(f"{GATEWAY_URL}/items", timeout=TIMEOUT)
        assert get_decision(r) == "ALLOW"
        assert r.status_code == 200

    def test_item_detail_is_allowed(self):
        r = requests.get(f"{GATEWAY_URL}/items/1", timeout=TIMEOUT)
        assert get_decision(r) == "ALLOW"
        assert r.status_code == 200

    def test_home_page_is_allowed(self):
        r = requests.get(f"{GATEWAY_URL}/", timeout=TIMEOUT)
        assert get_decision(r) == "ALLOW"
        assert r.status_code == 200

    def test_feedback_post_is_allowed(self):
        r = requests.post(
            f"{GATEWAY_URL}/feedback",
            json={"message": "Great system!", "name": "Test User"},
            timeout=TIMEOUT,
        )
        assert get_decision(r) == "ALLOW"
        assert r.status_code == 200


# ── SQL Injection blocking ────────────────────────────────────────────────────

class TestSQLInjectionBlocking:

    def test_tautology_is_blocked(self):
        r = requests.get(
            f"{GATEWAY_URL}/search",
            params={"q": "' OR '1'='1' --"},
            timeout=TIMEOUT,
        )
        assert r.status_code in (400, 403)
        assert get_decision(r) in ("BLOCK", "VALIDATION_ERROR")
        body = r.json()
        assert body.get("blocked") is True
        assert "SQL-001" in body.get("matched_rule_ids", [])

    def test_union_select_is_blocked(self):
        r = requests.get(
            f"{GATEWAY_URL}/search",
            params={"q": "' UNION SELECT password FROM users--"},
            timeout=TIMEOUT,
        )
        assert r.status_code in (400, 403)
        assert get_decision(r) == "BLOCK"

    def test_drop_table_is_blocked(self):
        r = requests.get(
            f"{GATEWAY_URL}/search",
            params={"q": "'; DROP TABLE users;--"},
            timeout=TIMEOUT,
        )
        assert r.status_code in (400, 403)

    def test_sql_response_has_request_id(self):
        r = requests.get(
            f"{GATEWAY_URL}/search",
            params={"q": "' OR '1'='1"},
            timeout=TIMEOUT,
        )
        assert get_request_id(r) != ""


# ── XSS blocking ──────────────────────────────────────────────────────────────

class TestXSSBlocking:

    def test_script_tag_is_blocked(self):
        r = requests.get(
            f"{GATEWAY_URL}/search",
            params={"q": "<script>alert('xss')</script>"},
            timeout=TIMEOUT,
        )
        assert r.status_code in (400, 403)
        assert get_decision(r) == "BLOCK"

    def test_javascript_uri_is_blocked(self):
        r = requests.get(
            f"{GATEWAY_URL}/search",
            params={"q": "javascript:alert(1)"},
            timeout=TIMEOUT,
        )
        assert r.status_code in (400, 403)

    def test_event_handler_is_blocked(self):
        r = requests.get(
            f"{GATEWAY_URL}/search",
            params={"q": "<img src=x onerror=alert(1)>"},
            timeout=TIMEOUT,
        )
        assert r.status_code in (400, 403)


# ── Path traversal blocking ───────────────────────────────────────────────────

class TestPathTraversalBlocking:

    def test_dotdot_slash_blocked(self):
        r = requests.get(
            f"{GATEWAY_URL}/search",
            params={"q": "../../etc/passwd"},
            timeout=TIMEOUT,
        )
        assert r.status_code in (400, 403)
        assert get_decision(r) == "BLOCK"


# ── Validation blocking ───────────────────────────────────────────────────────

class TestValidationBlocking:

    def test_oversized_body_is_rejected(self):
        big_body = {"message": "A" * 200_000, "name": "Test"}
        r = requests.post(f"{GATEWAY_URL}/feedback", json=big_body, timeout=TIMEOUT)
        assert r.status_code in (400, 403)

    def test_trace_method_is_rejected(self):
        r = requests.request("TRACE", f"{GATEWAY_URL}/search", timeout=TIMEOUT)
        assert r.status_code in (400, 403, 405)


# ── Rate limiting ─────────────────────────────────────────────────────────────

class TestRateLimiting:

    def test_rate_limiting_activates(self):
        """Send enough requests to hit the rate limit."""
        # Reset demo first
        requests.post(f"{GATEWAY_URL}/api/demo/reset", headers=HEADERS, timeout=TIMEOUT)
        time.sleep(0.5)

        decisions = []
        for _ in range(40):
            r = requests.get(
                f"{GATEWAY_URL}/search",
                params={"q": "rate-test"},
                timeout=TIMEOUT,
            )
            decisions.append(get_decision(r))

        assert "RATE_LIMITED" in decisions, \
            f"Expected RATE_LIMITED in decisions, got: {set(decisions)}"


# ── API Endpoints ─────────────────────────────────────────────────────────────

class TestAPI:

    def test_stats_endpoint(self):
        r = requests.get(f"{GATEWAY_URL}/api/stats", timeout=TIMEOUT)
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "allowed" in data
        assert "blocked" in data

    def test_events_endpoint(self):
        r = requests.get(f"{GATEWAY_URL}/api/events", params={"limit": 10}, timeout=TIMEOUT)
        assert r.status_code == 200
        data = r.json()
        assert "events" in data

    def test_rules_endpoint(self):
        r = requests.get(f"{GATEWAY_URL}/api/rules", timeout=TIMEOUT)
        assert r.status_code == 200
        data = r.json()
        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_rule_update_requires_api_key(self):
        """Updating a rule without API key should return 401."""
        r = requests.patch(
            f"{GATEWAY_URL}/api/rules/SQL-001",
            json={"enabled": False},
            timeout=TIMEOUT,
        )
        assert r.status_code == 401

    def test_rule_update_with_api_key(self):
        # Disable
        r = requests.patch(
            f"{GATEWAY_URL}/api/rules/XSS-003",
            json={"enabled": False},
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        assert r.status_code == 200
        assert r.json().get("success") is True

        # Re-enable
        r2 = requests.patch(
            f"{GATEWAY_URL}/api/rules/XSS-003",
            json={"enabled": True},
            headers=HEADERS,
            timeout=TIMEOUT,
        )
        assert r2.status_code == 200

    def test_stats_reflect_events(self):
        """After sending a blocked request, stats should update."""
        stats_before = requests.get(f"{GATEWAY_URL}/api/stats", timeout=TIMEOUT).json()
        total_before = stats_before.get("total", 0)

        # Send a blocked request
        requests.get(f"{GATEWAY_URL}/search", params={"q": "' OR '1'='1"}, timeout=TIMEOUT)
        time.sleep(0.5)

        stats_after = requests.get(f"{GATEWAY_URL}/api/stats", timeout=TIMEOUT).json()
        assert stats_after.get("total", 0) > total_before

    def test_event_lookup_by_request_id(self):
        """A logged event should be retrievable by its request ID."""
        r = requests.get(
            f"{GATEWAY_URL}/search",
            params={"q": "test-lookup"},
            timeout=TIMEOUT,
        )
        request_id = get_request_id(r)
        assert request_id, "No request ID in response headers"

        time.sleep(0.3)

        r2 = requests.get(f"{GATEWAY_URL}/api/events/{request_id}", timeout=TIMEOUT)
        assert r2.status_code == 200
        event = r2.json()
        assert event["request_id"] == request_id


# ── Protected app isolation ───────────────────────────────────────────────────

class TestProtectedAppIsolation:

    def test_protected_app_not_on_host_port_5001(self):
        """
        The protected app must not be reachable directly from the host.
        This test verifies that port 5001 is not bound on the host.
        """
        try:
            r = requests.get("http://localhost:5001/health", timeout=3)
            # If we get here, the port is open — this is a failure
            pytest.fail(
                f"Protected app is directly accessible on port 5001 (HTTP {r.status_code}). "
                "It must only be reachable through the gateway."
            )
        except requests.exceptions.ConnectionError:
            pass  # Expected: port not open
        except requests.exceptions.Timeout:
            pass  # Expected: no listener
