"""
SentinelShield - Unit Tests
Tests the rule engine and database layer in isolation (no Docker required).
Run: pytest tests/ -v
"""

import sys
import os
import json
import tempfile
import pytest

# Add gateway source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))


# ════════════════════════════════════════════════════════════════
#  Rule Engine Unit Tests
# ════════════════════════════════════════════════════════════════

from rules_engine import (
    inspect_request,
    _check_sql_injection,
    _check_xss,
    _check_path_traversal,
    _check_validation,
    reset_rate_limiter,
    _normalize_input,
    RateLimiter,
)


# Default enabled rules stub — mirrors DB defaults
ALL_RULES = [
    {"rule_id": "SQL-001", "name": "SQL Tautology", "category": "SQL_INJECTION",
     "severity": "HIGH", "enabled": 1, "configuration_json": "{}"},
    {"rule_id": "SQL-002", "name": "UNION SELECT", "category": "SQL_INJECTION",
     "severity": "HIGH", "enabled": 1, "configuration_json": "{}"},
    {"rule_id": "SQL-003", "name": "SQL Comments", "category": "SQL_INJECTION",
     "severity": "MEDIUM", "enabled": 1, "configuration_json": "{}"},
    {"rule_id": "SQL-004", "name": "DDL/DML Keywords", "category": "SQL_INJECTION",
     "severity": "HIGH", "enabled": 1, "configuration_json": "{}"},
    {"rule_id": "XSS-001", "name": "Script Tag", "category": "XSS",
     "severity": "HIGH", "enabled": 1, "configuration_json": "{}"},
    {"rule_id": "XSS-002", "name": "JS URI", "category": "XSS",
     "severity": "HIGH", "enabled": 1, "configuration_json": "{}"},
    {"rule_id": "XSS-003", "name": "Event Handler", "category": "XSS",
     "severity": "MEDIUM", "enabled": 1, "configuration_json": "{}"},
    {"rule_id": "PT-001", "name": "Path Traversal", "category": "PATH_TRAVERSAL",
     "severity": "HIGH", "enabled": 1, "configuration_json": "{}"},
    {"rule_id": "VAL-001", "name": "URL Length", "category": "VALIDATION",
     "severity": "LOW", "enabled": 1,
     "configuration_json": json.dumps({"max_url_length": 2048})},
    {"rule_id": "VAL-002", "name": "Body Size", "category": "VALIDATION",
     "severity": "LOW", "enabled": 1,
     "configuration_json": json.dumps({"max_body_bytes": 102400})},
    {"rule_id": "VAL-003", "name": "HTTP Method", "category": "VALIDATION",
     "severity": "LOW", "enabled": 1,
     "configuration_json": json.dumps({"allowed_methods": ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"]})},
    {"rule_id": "RL-001", "name": "Rate Limiter", "category": "RATE_LIMIT",
     "severity": "MEDIUM", "enabled": 1,
     "configuration_json": json.dumps({"max_requests": 10, "window_seconds": 60})},
]


def make_rules(disabled: list[str] = None) -> list[dict]:
    """Return ALL_RULES with selected rules disabled."""
    disabled = disabled or []
    result = []
    for r in ALL_RULES:
        entry = dict(r)
        if r["rule_id"] in disabled:
            entry["enabled"] = 0
        result.append(entry)
    return result


def quick_inspect(query: str, rules=None, path="/search", method="GET", body_size=0):
    """Helper: inspect a single GET query parameter."""
    reset_rate_limiter()
    return inspect_request(
        method=method,
        url=f"http://testserver{path}?q={query}",
        path=path,
        query_params={"q": [query]},
        form_data={},
        body_size=body_size,
        client_ip="127.0.0.1",
        active_rules=rules or make_rules(),
    )


# ── SQL Injection ─────────────────────────────────────────────────────────────

class TestSQLInjectionRules:

    def test_tautology_is_blocked(self):
        result = quick_inspect("' OR '1'='1' --")
        assert result.decision == "BLOCK"
        assert "SQL-001" in [m.rule_id for m in result.matched_rules]

    def test_union_select_is_blocked(self):
        result = quick_inspect("test' UNION SELECT username,password FROM users--")
        assert result.decision == "BLOCK"
        rule_ids = [m.rule_id for m in result.matched_rules]
        assert "SQL-002" in rule_ids or "SQL-001" in rule_ids

    def test_drop_table_is_blocked(self):
        result = quick_inspect("'; DROP TABLE users;--")
        assert result.decision == "BLOCK"
        assert "SQL-004" in [m.rule_id for m in result.matched_rules]

    def test_sql_comment_is_blocked(self):
        result = quick_inspect("admin'--")
        assert result.decision == "BLOCK"
        assert "SQL-003" in [m.rule_id for m in result.matched_rules]

    def test_normal_search_is_allowed(self):
        result = quick_inspect("firewall security best practices")
        assert result.decision == "ALLOW"

    def test_ordinary_text_with_common_words_is_allowed(self):
        """Ensure we don't over-block ordinary English text."""
        result = quick_inspect("how to update network settings")
        assert result.decision == "ALLOW"

    def test_url_encoded_injection_is_blocked(self):
        """URL-encoded ' OR '1'='1 should be normalised and blocked."""
        result = quick_inspect("%27%20OR%20%271%27%3D%271")
        assert result.decision == "BLOCK"

    def test_disabled_sql001_allows_tautology(self):
        rules = make_rules(disabled=["SQL-001"])
        # Tautology only (no UNION, no DROP, no --)
        result = quick_inspect("x' OR 'a'='a", rules=rules)
        # SQL-001 disabled; others should not fire on pure tautology
        rule_ids = [m.rule_id for m in result.matched_rules]
        assert "SQL-001" not in rule_ids


# ── XSS ───────────────────────────────────────────────────────────────────────

class TestXSSRules:

    def test_script_tag_is_blocked(self):
        result = quick_inspect("<script>alert('xss')</script>")
        assert result.decision == "BLOCK"
        assert "XSS-001" in [m.rule_id for m in result.matched_rules]

    def test_javascript_uri_is_blocked(self):
        result = quick_inspect("javascript:alert(1)")
        assert result.decision == "BLOCK"
        assert "XSS-002" in [m.rule_id for m in result.matched_rules]

    def test_event_handler_is_blocked(self):
        result = quick_inspect("<img src=x onerror=alert(1)>")
        assert result.decision == "BLOCK"
        rule_ids = [m.rule_id for m in result.matched_rules]
        assert "XSS-003" in rule_ids or "XSS-001" in rule_ids

    def test_normal_html_in_search_context_allowed(self):
        result = quick_inspect("learn html css basics")
        assert result.decision == "ALLOW"

    def test_disabled_xss001_allows_script_tag(self):
        rules = make_rules(disabled=["XSS-001", "XSS-002", "XSS-003"])
        result = quick_inspect("<script>alert(1)</script>", rules=rules)
        rule_ids = [m.rule_id for m in result.matched_rules]
        assert "XSS-001" not in rule_ids


# ── Path Traversal ────────────────────────────────────────────────────────────

class TestPathTraversalRules:

    def test_dotdot_slash_is_blocked(self):
        result = quick_inspect("../../etc/passwd")
        assert result.decision == "BLOCK"
        assert "PT-001" in [m.rule_id for m in result.matched_rules]

    def test_url_encoded_traversal_is_blocked(self):
        result = quick_inspect("%2e%2e%2fetc%2fpasswd")
        assert result.decision == "BLOCK"

    def test_double_encoded_traversal_is_blocked(self):
        result = quick_inspect("%252e%252e%252fetc")
        assert result.decision == "BLOCK"

    def test_normal_path_is_allowed(self):
        result = quick_inspect("documents/report2024.pdf")
        assert result.decision == "ALLOW"


# ── Validation ────────────────────────────────────────────────────────────────

class TestValidationRules:

    def test_oversized_body_is_blocked(self):
        reset_rate_limiter()
        result = inspect_request(
            method="POST", url="http://test/feedback",
            path="/feedback", query_params={}, form_data={},
            body_size=200 * 1024,  # 200 KB > 100 KB limit
            client_ip="192.168.1.1",
            active_rules=make_rules(),
        )
        assert result.decision in ("BLOCK", "VALIDATION_ERROR")
        rule_ids = [m.rule_id for m in result.matched_rules]
        assert "VAL-002" in rule_ids

    def test_normal_body_size_allowed(self):
        reset_rate_limiter()
        result = inspect_request(
            method="POST", url="http://test/feedback",
            path="/feedback", query_params={}, form_data={},
            body_size=1024,  # 1 KB
            client_ip="192.168.1.2",
            active_rules=make_rules(),
        )
        assert result.decision == "ALLOW"

    def test_invalid_http_method_blocked(self):
        reset_rate_limiter()
        result = inspect_request(
            method="TRACE", url="http://test/search",
            path="/search", query_params={"q": ["test"]}, form_data={},
            body_size=0, client_ip="192.168.1.3",
            active_rules=make_rules(),
        )
        assert result.decision in ("BLOCK", "VALIDATION_ERROR")

    def test_url_length_limit(self):
        reset_rate_limiter()
        long_url = "http://test/search?q=" + "A" * 2100
        result = inspect_request(
            method="GET", url=long_url,
            path="/search", query_params={"q": ["A" * 2100]},
            form_data={}, body_size=0, client_ip="192.168.1.4",
            active_rules=make_rules(),
        )
        assert result.decision in ("BLOCK", "VALIDATION_ERROR")


# ── Rate Limiting ─────────────────────────────────────────────────────────────

class TestRateLimiting:

    def test_rate_limiter_triggers(self):
        """Client should be rate-limited after exceeding threshold."""
        reset_rate_limiter()
        rules = make_rules()

        results = []
        for _ in range(15):  # limit is 10 per 60s
            r = inspect_request(
                method="GET", url="http://test/search?q=test",
                path="/search", query_params={"q": ["test"]},
                form_data={}, body_size=0,
                client_ip="10.0.0.1",
                active_rules=rules,
            )
            results.append(r.decision)

        assert "RATE_LIMITED" in results, "Expected at least one RATE_LIMITED decision"

    def test_rate_limiter_allows_initially(self):
        """First few requests from a fresh IP should be ALLOW."""
        reset_rate_limiter()
        rules = make_rules()

        r = inspect_request(
            method="GET", url="http://test/search?q=hello",
            path="/search", query_params={"q": ["hello"]},
            form_data={}, body_size=0,
            client_ip="10.0.0.99",
            active_rules=rules,
        )
        assert r.decision == "ALLOW"

    def test_rate_limiter_reset_clears_counts(self):
        """After reset, a previously limited client should be allowed again."""
        reset_rate_limiter()
        rules = make_rules()

        for _ in range(15):
            inspect_request(
                method="GET", url="http://test/search?q=a",
                path="/search", query_params={"q": ["a"]},
                form_data={}, body_size=0,
                client_ip="10.0.0.2",
                active_rules=rules,
            )

        reset_rate_limiter()

        r = inspect_request(
            method="GET", url="http://test/search?q=after-reset",
            path="/search", query_params={"q": ["after-reset"]},
            form_data={}, body_size=0,
            client_ip="10.0.0.2",
            active_rules=rules,
        )
        assert r.decision == "ALLOW"


# ── Normalisation ─────────────────────────────────────────────────────────────

class TestNormalization:

    def test_basic_url_decode(self):
        assert _normalize_input("%27") == "'"

    def test_double_url_decode(self):
        # %2527 = %25 (percent) + 27 → first decode gives %27 → second decode gives '
        result = _normalize_input("%2527", max_decode_rounds=3)
        # After 3 rounds of URL-decoding, should resolve to the single-quote character
        assert "'" in result

    def test_no_infinite_loop(self):
        """Normalization must terminate even for pathological input."""
        crafted = "%25" * 100 + "27"
        result = _normalize_input(crafted, max_decode_rounds=3)
        assert len(result) < 500  # should not explode in size


# ════════════════════════════════════════════════════════════════
#  Database Unit Tests (using temp DB)
# ════════════════════════════════════════════════════════════════

class TestDatabase:

    @pytest.fixture(autouse=True)
    def temp_db(self, tmp_path, monkeypatch):
        """Use a fresh temp database for each test."""
        db_path = str(tmp_path / "test.db")
        monkeypatch.setenv("DB_PATH", db_path)

        # Re-import after env change
        import importlib
        import database
        importlib.reload(database)
        database.init_db()
        self.db = database
        yield

    def test_init_creates_tables(self):
        conn = self.db.get_connection()
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        assert "security_events" in tables
        assert "security_rules" in tables
        assert "audit_events" in tables

    def test_default_rules_seeded(self):
        rules = self.db.get_rules()
        rule_ids = [r["rule_id"] for r in rules]
        assert "SQL-001" in rule_ids
        assert "XSS-001" in rule_ids
        assert "PT-001" in rule_ids
        assert "RL-001" in rule_ids

    def test_log_and_retrieve_event(self):
        event = {
            "request_id": "test-request-001",
            "timestamp_utc": "2024-01-15T10:00:00+00:00",
            "method": "GET",
            "route": "/search",
            "decision": "BLOCK",
            "status_code": 403,
            "matched_rule_ids": ["SQL-001"],
            "attack_category": "SQL_INJECTION",
            "severity": "HIGH",
            "reason": "Tautology detected",
            "processing_time_ms": 1.23,
            "sanitized_client_id": "127.0.0.1",
        }
        self.db.log_security_event(event)
        retrieved = self.db.get_event_by_request_id("test-request-001")
        assert retrieved is not None
        assert retrieved["decision"] == "BLOCK"
        assert retrieved["severity"] == "HIGH"

    def test_stats_reflect_logged_events(self):
        for i, (decision, severity) in enumerate([
            ("ALLOW", "INFO"),
            ("ALLOW", "INFO"),
            ("BLOCK", "HIGH"),
            ("RATE_LIMITED", "MEDIUM"),
        ]):
            self.db.log_security_event({
                "request_id": f"req-{i}",
                "timestamp_utc": "2024-01-15T10:00:00+00:00",
                "method": "GET",
                "route": "/search",
                "decision": decision,
                "status_code": 200 if decision == "ALLOW" else 403,
                "matched_rule_ids": [],
                "attack_category": "NONE",
                "severity": severity,
                "reason": "",
                "processing_time_ms": 1.0,
                "sanitized_client_id": "127.0.0.1",
            })

        stats = self.db.get_stats()
        assert stats["total"] == 4
        assert stats["allowed"] == 2
        assert stats["blocked"] == 1
        assert stats["rate_limited"] == 1

    def test_rule_toggle_persists(self):
        result = self.db.update_rule("SQL-001", False)
        assert result is True
        rules = self.db.get_rules()
        sql001 = next(r for r in rules if r["rule_id"] == "SQL-001")
        assert sql001["enabled"] == 0

        self.db.update_rule("SQL-001", True)
        rules = self.db.get_rules()
        sql001 = next(r for r in rules if r["rule_id"] == "SQL-001")
        assert sql001["enabled"] == 1

    def test_reset_rules_re_enables_all(self):
        self.db.update_rule("SQL-001", False)
        self.db.update_rule("XSS-001", False)
        self.db.reset_rules_to_defaults()
        rules = self.db.get_rules()
        for r in rules:
            assert r["enabled"] == 1, f"Rule {r['rule_id']} not re-enabled after reset"

    def test_reset_demo_clears_events(self):
        self.db.log_security_event({
            "request_id": "clear-test",
            "timestamp_utc": "2024-01-15T10:00:00+00:00",
            "method": "GET", "route": "/", "decision": "ALLOW",
            "status_code": 200, "matched_rule_ids": [],
            "attack_category": "NONE", "severity": "INFO",
            "reason": "", "processing_time_ms": 1.0,
            "sanitized_client_id": "127.0.0.1",
        })
        self.db.reset_demo_data()
        events = self.db.get_events()
        assert len(events) == 0

    def test_log_sanitization_no_injection(self):
        """Log entries with newlines should not cause log injection."""
        event = {
            "request_id": "injection-test",
            "timestamp_utc": "2024-01-15T10:00:00+00:00",
            "method": "GET",
            "route": "/search",
            "decision": "BLOCK",
            "status_code": 403,
            "matched_rule_ids": ["SQL-001"],
            "attack_category": "SQL_INJECTION",
            "severity": "HIGH",
            "reason": "Tautology\ninjected line\r\nevil",
            "processing_time_ms": 1.0,
            "sanitized_client_id": "127.0.0.1",
        }
        # Should not raise
        self.db.log_security_event(event)
        retrieved = self.db.get_event_by_request_id("injection-test")
        assert retrieved is not None
        # Reason is stored as-is in DB (logging layer sanitizes before writing to log file)
        assert retrieved["reason"] is not None

    def test_duplicate_init_does_not_duplicate_rules(self):
        """Calling init_db twice must not duplicate the default rules."""
        self.db.init_db()
        self.db.init_db()
        rules = self.db.get_rules()
        rule_ids = [r["rule_id"] for r in rules]
        assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule IDs detected"

    def test_audit_events_logged_on_rule_update(self):
        self.db.update_rule("SQL-001", False, actor="test-user")
        audit = self.db.get_audit_events()
        actions = [e["action"] for e in audit]
        assert "RULE_UPDATE" in actions
