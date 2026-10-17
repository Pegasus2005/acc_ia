"""
SentinelShield WAF Gateway - Database Layer
Handles SQLite schema initialization, event logging, rule management, and audit trails.
"""

import sqlite3
import json
import logging
import os
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/data/sentinelshield.db")


def get_connection() -> sqlite3.Connection:
    """Create a database connection with safe settings."""
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,          # busy timeout in seconds
        check_same_thread=False,
        isolation_level=None  # autocommit; we manage transactions manually
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@contextmanager
def db_transaction():
    """
    Context manager for atomic database transactions.
    Uses isolation_level='' (deferred) so SQLite manages BEGIN/COMMIT.
    """
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False,
        isolation_level="",  # manual transaction mode without autocommit conflict
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        conn.execute("BEGIN")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Initialize schema and seed default security rules."""
    # executescript() issues an implicit COMMIT before running, so we use
    # a plain connection here instead of db_transaction().
    conn = get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS security_events (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id              TEXT    NOT NULL,
                timestamp_utc           TEXT    NOT NULL,
                method                  TEXT    NOT NULL,
                route                   TEXT    NOT NULL,
                decision                TEXT    NOT NULL,
                status_code             INTEGER NOT NULL,
                matched_rule_ids        TEXT    NOT NULL DEFAULT '[]',
                attack_category         TEXT    NOT NULL DEFAULT 'NONE',
                severity                TEXT    NOT NULL DEFAULT 'INFO',
                reason                  TEXT    NOT NULL DEFAULT '',
                processing_time_ms      REAL    NOT NULL DEFAULT 0,
                sanitized_client_id     TEXT    NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON security_events(timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_events_decision   ON security_events(decision);
            CREATE INDEX IF NOT EXISTS idx_events_request_id ON security_events(request_id);
            CREATE INDEX IF NOT EXISTS idx_events_severity   ON security_events(severity);

            CREATE TABLE IF NOT EXISTS security_rules (
                rule_id             TEXT    PRIMARY KEY,
                name                TEXT    NOT NULL,
                category            TEXT    NOT NULL,
                description         TEXT    NOT NULL,
                severity            TEXT    NOT NULL,
                enabled             INTEGER NOT NULL DEFAULT 1,
                configuration_json  TEXT    NOT NULL DEFAULT '{}',
                updated_at          TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc       TEXT    NOT NULL,
                actor               TEXT    NOT NULL DEFAULT 'system',
                action              TEXT    NOT NULL,
                target              TEXT    NOT NULL DEFAULT '',
                sanitized_details   TEXT    NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp_utc);
        """)
    finally:
        conn.close()

    _seed_default_rules()


def _seed_default_rules() -> None:
    """Insert default security rules if they don't already exist."""
    default_rules = [
        {
            "rule_id": "SQL-001",
            "name": "SQL Tautology Detection",
            "category": "SQL_INJECTION",
            "description": "Detects classic SQL tautologies such as ' OR '1'='1 used to bypass authentication.",
            "severity": "HIGH",
            "enabled": 1,
            "configuration_json": json.dumps({"patterns": ["tautology", "or_equals"]}),
        },
        {
            "rule_id": "SQL-002",
            "name": "UNION SELECT Detection",
            "category": "SQL_INJECTION",
            "description": "Detects UNION SELECT constructions commonly used to extract database information.",
            "severity": "HIGH",
            "enabled": 1,
            "configuration_json": json.dumps({"patterns": ["union_select"]}),
        },
        {
            "rule_id": "SQL-003",
            "name": "SQL Comment Injection",
            "category": "SQL_INJECTION",
            "description": "Detects SQL comment sequences (-- and /*) used to truncate or modify queries.",
            "severity": "MEDIUM",
            "enabled": 1,
            "configuration_json": json.dumps({"patterns": ["comments"]}),
        },
        {
            "rule_id": "SQL-004",
            "name": "SQL Keyword Manipulation",
            "category": "SQL_INJECTION",
            "description": "Detects attempts to manipulate SQL conditions using DROP, INSERT, UPDATE, DELETE.",
            "severity": "HIGH",
            "enabled": 1,
            "configuration_json": json.dumps({"patterns": ["ddl_dml"]}),
        },
        {
            "rule_id": "XSS-001",
            "name": "Script Tag Detection",
            "category": "XSS",
            "description": "Detects <script> tags and similar constructs in user input.",
            "severity": "HIGH",
            "enabled": 1,
            "configuration_json": json.dumps({}),
        },
        {
            "rule_id": "XSS-002",
            "name": "JavaScript URI Detection",
            "category": "XSS",
            "description": "Detects javascript: URI schemes used in attribute injection attacks.",
            "severity": "HIGH",
            "enabled": 1,
            "configuration_json": json.dumps({}),
        },
        {
            "rule_id": "XSS-003",
            "name": "Event Handler Injection",
            "category": "XSS",
            "description": "Detects HTML event-handler attributes (onerror, onload, onclick, etc.).",
            "severity": "MEDIUM",
            "enabled": 1,
            "configuration_json": json.dumps({}),
        },
        {
            "rule_id": "PT-001",
            "name": "Path Traversal Detection",
            "category": "PATH_TRAVERSAL",
            "description": "Detects ../ and URL-encoded path traversal sequences.",
            "severity": "HIGH",
            "enabled": 1,
            "configuration_json": json.dumps({}),
        },
        {
            "rule_id": "VAL-001",
            "name": "URL Length Limit",
            "category": "VALIDATION",
            "description": "Rejects requests with URLs longer than the configured maximum.",
            "severity": "LOW",
            "enabled": 1,
            "configuration_json": json.dumps({"max_url_length": 2048}),
        },
        {
            "rule_id": "VAL-002",
            "name": "Request Body Size Limit",
            "category": "VALIDATION",
            "description": "Rejects requests whose body exceeds the configured maximum size.",
            "severity": "LOW",
            "enabled": 1,
            "configuration_json": json.dumps({"max_body_bytes": 102400}),
        },
        {
            "rule_id": "VAL-003",
            "name": "Invalid HTTP Method",
            "category": "VALIDATION",
            "description": "Rejects HTTP methods not in the allowed list.",
            "severity": "LOW",
            "enabled": 1,
            "configuration_json": json.dumps({"allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]}),
        },
        {
            "rule_id": "RL-001",
            "name": "Rate Limiter",
            "category": "RATE_LIMIT",
            "description": "Limits requests per client within a sliding window.",
            "severity": "MEDIUM",
            "enabled": 1,
            "configuration_json": json.dumps({"max_requests": 30, "window_seconds": 60}),
        },
    ]

    now = datetime.now(timezone.utc).isoformat()
    with db_transaction() as conn:
        for rule in default_rules:
            conn.execute(
                """
                INSERT OR IGNORE INTO security_rules
                    (rule_id, name, category, description, severity, enabled, configuration_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule["rule_id"],
                    rule["name"],
                    rule["category"],
                    rule["description"],
                    rule["severity"],
                    rule["enabled"],
                    rule["configuration_json"],
                    now,
                ),
            )


# ── Event logging ──────────────────────────────────────────────────────────────

def log_security_event(event: Dict[str, Any]) -> None:
    """Persist a security event to the database."""
    with db_transaction() as conn:
        conn.execute(
            """
            INSERT INTO security_events
                (request_id, timestamp_utc, method, route, decision, status_code,
                 matched_rule_ids, attack_category, severity, reason,
                 processing_time_ms, sanitized_client_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["request_id"],
                event["timestamp_utc"],
                event["method"],
                event["route"],
                event["decision"],
                event["status_code"],
                json.dumps(event.get("matched_rule_ids", [])),
                event.get("attack_category", "NONE"),
                event.get("severity", "INFO"),
                event.get("reason", ""),
                event.get("processing_time_ms", 0),
                event.get("sanitized_client_id", ""),
            ),
        )


def get_stats() -> Dict[str, Any]:
    """Return aggregate statistics for the overview dashboard."""
    conn = get_connection()
    try:
        row = conn.execute("""
            SELECT
                COUNT(*)                                        AS total,
                SUM(CASE WHEN decision='ALLOW'        THEN 1 ELSE 0 END) AS allowed,
                SUM(CASE WHEN decision='BLOCK'        THEN 1 ELSE 0 END) AS blocked,
                SUM(CASE WHEN decision='RATE_LIMITED' THEN 1 ELSE 0 END) AS rate_limited,
                SUM(CASE WHEN decision='BLOCK' OR decision='RATE_LIMITED' THEN 1 ELSE 0 END) AS total_blocked
            FROM security_events
        """).fetchone()

        top_rule = conn.execute("""
            SELECT matched_rule_ids FROM security_events
            WHERE matched_rule_ids != '[]'
        """).fetchall()

        # Parse JSON arrays and count rule hits
        from collections import Counter
        rule_counter: Counter = Counter()
        for r in top_rule:
            try:
                ids = json.loads(r["matched_rule_ids"])
                rule_counter.update(ids)
            except Exception:
                pass

        most_common = rule_counter.most_common(1)
        top_rule_id = most_common[0][0] if most_common else "N/A"

        total = row["total"] or 0
        blocked = row["total_blocked"] or 0
        block_pct = round((blocked / total * 100), 1) if total > 0 else 0

        return {
            "total": total,
            "allowed": row["allowed"] or 0,
            "blocked": row["blocked"] or 0,
            "rate_limited": row["rate_limited"] or 0,
            "total_blocked": blocked,
            "block_percentage": block_pct,
            "top_rule_id": top_rule_id,
        }
    finally:
        conn.close()


def get_events(
    limit: int = 200,
    offset: int = 0,
    decision: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    request_id: Optional[str] = None,
) -> List[Dict]:
    """Fetch security events with optional filters."""
    clauses = []
    params: List[Any] = []

    if decision:
        clauses.append("decision = ?")
        params.append(decision)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if category:
        clauses.append("attack_category = ?")
        params.append(category)
    if from_ts:
        clauses.append("timestamp_utc >= ?")
        params.append(from_ts)
    if to_ts:
        clauses.append("timestamp_utc <= ?")
        params.append(to_ts)
    if request_id:
        clauses.append("request_id = ?")
        params.append(request_id)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    # Limit and offset are integers — safe to interpolate
    query = f"SELECT * FROM security_events {where} ORDER BY timestamp_utc DESC LIMIT {int(limit)} OFFSET {int(offset)}"
    conn = get_connection()
    try:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_event_by_request_id(request_id: str) -> Optional[Dict]:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM security_events WHERE request_id = ? LIMIT 1", (request_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_events_for_charts() -> List[Dict]:
    """Return all events needed for dashboard charts (lightweight fields only)."""
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT timestamp_utc, decision, attack_category, severity, matched_rule_ids
            FROM security_events
            ORDER BY timestamp_utc ASC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ── Rule management ────────────────────────────────────────────────────────────

def get_rules() -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM security_rules ORDER BY rule_id").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def update_rule(rule_id: str, enabled: bool, actor: str = "api") -> bool:
    """Enable or disable a rule and log the audit event."""
    now = datetime.now(timezone.utc).isoformat()
    with db_transaction() as conn:
        result = conn.execute(
            "UPDATE security_rules SET enabled = ?, updated_at = ? WHERE rule_id = ?",
            (1 if enabled else 0, now, rule_id),
        )
        if result.rowcount == 0:
            return False
        conn.execute(
            """INSERT INTO audit_events (timestamp_utc, actor, action, target, sanitized_details)
               VALUES (?, ?, ?, ?, ?)""",
            (now, actor[:64], "RULE_UPDATE", rule_id[:32],
             f"enabled={enabled}"),
        )
    return True


def reset_rules_to_defaults() -> None:
    """Re-enable all rules and log the reset."""
    now = datetime.now(timezone.utc).isoformat()
    with db_transaction() as conn:
        conn.execute("UPDATE security_rules SET enabled = 1, updated_at = ?", (now,))
        conn.execute(
            """INSERT INTO audit_events (timestamp_utc, actor, action, target, sanitized_details)
               VALUES (?, ?, ?, ?, ?)""",
            (now, "api", "RULES_RESET", "all", "Reset all rules to secure defaults"),
        )


def reset_demo_data() -> None:
    """Delete all security events for a clean demonstration restart."""
    now = datetime.now(timezone.utc).isoformat()
    with db_transaction() as conn:
        conn.execute("DELETE FROM security_events")
        conn.execute(
            """INSERT INTO audit_events (timestamp_utc, actor, action, target, sanitized_details)
               VALUES (?, ?, ?, ?, ?)""",
            (now, "api", "DEMO_RESET", "security_events", "All demo events cleared"),
        )


def get_audit_events(limit: int = 100) -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY timestamp_utc DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_db_stats() -> Dict[str, Any]:
    conn = get_connection()
    try:
        event_count = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        rule_count = conn.execute("SELECT COUNT(*) FROM security_rules").fetchone()[0]
        enabled_rules = conn.execute("SELECT COUNT(*) FROM security_rules WHERE enabled=1").fetchone()[0]
        audit_count = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        oldest = conn.execute("SELECT MIN(timestamp_utc) FROM security_events").fetchone()[0]
        newest = conn.execute("SELECT MAX(timestamp_utc) FROM security_events").fetchone()[0]
        return {
            "event_count": event_count,
            "rule_count": rule_count,
            "enabled_rules": enabled_rules,
            "audit_count": audit_count,
            "oldest_event": oldest,
            "newest_event": newest,
            "db_path": DB_PATH,
        }
    finally:
        conn.close()
