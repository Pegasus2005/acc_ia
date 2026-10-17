"""
SentinelShield WAF Gateway - Security Rule Engine
Implements modular, pattern-based detection for SQL injection, XSS,
path traversal, request validation, and rate limiting.

IMPORTANT LIMITATIONS (for academic documentation):
- Pattern-based rules cannot catch every possible attack variant.
- Encoding normalization is limited to common encodings; deeply nested
  or novel encodings may bypass detection.
- Rate limiting is in-memory and resets on container restart.
- This is an educational tool, not a production-grade WAF.
"""

import re
import time
import logging
import json
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Compiled regex patterns ────────────────────────────────────────────────────

# SQL Injection patterns — contextual, not keyword-only
_SQL_TAUTOLOGY = re.compile(
    r"""(
        '\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+   # ' OR '1'='1
      | '\s*(or|and)\s+'?\w+'?\s*=\s*'?\w+    # ' OR a=a
      | '\s*(or|and)\s+1\s*=\s*1              # ' OR 1=1
      | "\s*(or|and)\s*"\d+"\s*=\s*"\d+       # " OR "1"="1
    )""",
    re.IGNORECASE | re.VERBOSE,
)

_SQL_UNION_SELECT = re.compile(
    r"union\s+(?:all\s+)?select\b",
    re.IGNORECASE,
)

_SQL_COMMENTS = re.compile(
    r"""(
        --\s*$          # inline comment at end
      | --[^\w]         # -- followed by non-word
      | /\*.*?\*/       # block comment
      | ;\s*--          # statement end + comment
    )""",
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)

_SQL_DDL_DML = re.compile(
    r"""\b(
        drop\s+table
      | drop\s+database
      | delete\s+from
      | insert\s+into
      | update\s+\w+\s+set
      | exec\s*\(
      | execute\s*\(
      | xp_cmdshell
    )\b""",
    re.IGNORECASE | re.VERBOSE,
)

# XSS patterns
_XSS_SCRIPT_TAG = re.compile(
    r"<\s*script[\s>\/]",
    re.IGNORECASE,
)

_XSS_JS_URI = re.compile(
    r"javascript\s*:",
    re.IGNORECASE,
)

_XSS_EVENT_HANDLER = re.compile(
    r"""\bon(
        error|load|click|mouseover|mouseout|focus|blur|change|submit
      | keydown|keyup|keypress|dblclick|contextmenu|input|invalid
      | message|hashchange|pagehide|pageshow|popstate|resize|scroll
      | unload|animationend|transitionend
    )\s*=""",
    re.IGNORECASE | re.VERBOSE,
)

_XSS_HTML_INJECT = re.compile(
    r"<\s*(iframe|object|embed|img|svg|math|form|input|button|link|meta|base|style|noscript)\b",
    re.IGNORECASE,
)

# Path traversal patterns
_PATH_TRAVERSAL = re.compile(
    r"""(
        \.\.[\/\\]          # ../  or ..\
      | \.\.[\/\\]          # repeated
      | %2e%2e[%2f%5c]      # url-encoded
      | %252e%252e          # double-encoded
      | \.\.%2f             # partial encode
      | \.\.%5c
    )""",
    re.IGNORECASE | re.VERBOSE,
)


# ── Normalisation helpers ──────────────────────────────────────────────────────

def _normalize_input(value: str, max_decode_rounds: int = 3) -> str:
    """
    URL-decode input up to max_decode_rounds times to detect encoded payloads.
    Stops early if an additional decode round produces no change.
    """
    current = value
    for _ in range(max_decode_rounds):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current.lower()


def _safe_truncate(value: str, max_len: int = 512) -> str:
    """Truncate a string to prevent log injection via very long values."""
    if len(value) > max_len:
        return value[:max_len] + "…[truncated]"
    return value


def _sanitize_for_log(value: str) -> str:
    """Remove newline/carriage-return characters to prevent log injection."""
    return re.sub(r"[\r\n\t]", " ", _safe_truncate(value))


# ── Rate limiter ───────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Simple sliding-window rate limiter.
    Stored in memory — resets on process restart.
    For a demo: identifies clients by IP only (does NOT trust X-Forwarded-For).
    """

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # client_id -> list of request timestamps
        self._store: Dict[str, List[float]] = defaultdict(list)

    def is_rate_limited(self, client_id: str) -> Tuple[bool, int]:
        """
        Returns (is_limited, remaining_requests).
        Cleans up expired timestamps.
        """
        now = time.time()
        window_start = now - self.window_seconds
        timestamps = self._store[client_id]
        # Remove expired entries
        self._store[client_id] = [t for t in timestamps if t > window_start]
        count = len(self._store[client_id])
        if count >= self.max_requests:
            return True, 0
        self._store[client_id].append(now)
        return False, self.max_requests - count - 1

    def reset(self) -> None:
        """Clear all rate-limit counters (for demo reset)."""
        self._store.clear()

    def update_limits(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds


# Singleton rate limiter
_rate_limiter = RateLimiter()


# ── Rule result ────────────────────────────────────────────────────────────────

@dataclass
class RuleMatch:
    rule_id: str
    name: str
    category: str
    severity: str
    reason: str
    mitigation: str


@dataclass
class InspectionResult:
    decision: str                          # ALLOW | BLOCK | RATE_LIMITED | VALIDATION_ERROR
    status_code: int
    matched_rules: List[RuleMatch] = field(default_factory=list)
    attack_category: str = "NONE"
    severity: str = "INFO"
    reason: str = ""
    mitigation: str = ""

    def is_blocked(self) -> bool:
        return self.decision in ("BLOCK", "RATE_LIMITED", "VALIDATION_ERROR")


# ── Rule implementations ───────────────────────────────────────────────────────

def _check_sql_injection(inputs: List[str], enabled_rules: Dict[str, dict]) -> List[RuleMatch]:
    matches: List[RuleMatch] = []
    for val in inputs:
        norm = _normalize_input(val)

        if "SQL-001" in enabled_rules and _SQL_TAUTOLOGY.search(norm):
            matches.append(RuleMatch(
                rule_id="SQL-001",
                name="SQL Tautology Detection",
                category="SQL_INJECTION",
                severity="HIGH",
                reason=f"SQL tautology pattern detected in input: {_sanitize_for_log(val[:80])}",
                mitigation="Use parameterized queries. Validate and escape all user input.",
            ))

        if "SQL-002" in enabled_rules and _SQL_UNION_SELECT.search(norm):
            matches.append(RuleMatch(
                rule_id="SQL-002",
                name="UNION SELECT Detection",
                category="SQL_INJECTION",
                severity="HIGH",
                reason=f"UNION SELECT pattern detected: {_sanitize_for_log(val[:80])}",
                mitigation="Implement parameterized queries and restrict column counts.",
            ))

        if "SQL-003" in enabled_rules and _SQL_COMMENTS.search(norm):
            matches.append(RuleMatch(
                rule_id="SQL-003",
                name="SQL Comment Injection",
                category="SQL_INJECTION",
                severity="MEDIUM",
                reason=f"SQL comment sequence detected: {_sanitize_for_log(val[:80])}",
                mitigation="Strip or escape SQL comment sequences before query execution.",
            ))

        if "SQL-004" in enabled_rules and _SQL_DDL_DML.search(norm):
            matches.append(RuleMatch(
                rule_id="SQL-004",
                name="SQL DDL/DML Keyword Detection",
                category="SQL_INJECTION",
                severity="HIGH",
                reason=f"Dangerous SQL keyword detected: {_sanitize_for_log(val[:80])}",
                mitigation="Use an ORM or stored procedures. Enforce least-privilege DB accounts.",
            ))

    return matches


def _check_xss(inputs: List[str], enabled_rules: Dict[str, dict]) -> List[RuleMatch]:
    matches: List[RuleMatch] = []
    for val in inputs:
        norm = _normalize_input(val)

        if "XSS-001" in enabled_rules and _XSS_SCRIPT_TAG.search(norm):
            matches.append(RuleMatch(
                rule_id="XSS-001",
                name="Script Tag Detection",
                category="XSS",
                severity="HIGH",
                reason=f"<script> tag detected in input: {_sanitize_for_log(val[:80])}",
                mitigation="HTML-encode all user output. Use a strict Content-Security-Policy.",
            ))

        if "XSS-002" in enabled_rules and _XSS_JS_URI.search(norm):
            matches.append(RuleMatch(
                rule_id="XSS-002",
                name="JavaScript URI Detection",
                category="XSS",
                severity="HIGH",
                reason=f"javascript: URI detected: {_sanitize_for_log(val[:80])}",
                mitigation="Validate and whitelist URL schemes. Never allow javascript: in hrefs.",
            ))

        if "XSS-003" in enabled_rules and _XSS_EVENT_HANDLER.search(norm):
            matches.append(RuleMatch(
                rule_id="XSS-003",
                name="Event Handler Injection",
                category="XSS",
                severity="MEDIUM",
                reason=f"HTML event handler detected: {_sanitize_for_log(val[:80])}",
                mitigation="Use a strict Content-Security-Policy. Strip event handlers from input.",
            ))

        if "XSS-001" not in [m.rule_id for m in matches] and _XSS_HTML_INJECT.search(norm):
            # Only flag if not already caught by script tag rule
            if any(tag in norm for tag in ["<iframe", "<object", "<embed", "<svg", "<form"]):
                matches.append(RuleMatch(
                    rule_id="XSS-003",
                    name="HTML Tag Injection",
                    category="XSS",
                    severity="MEDIUM",
                    reason=f"Dangerous HTML tag detected: {_sanitize_for_log(val[:80])}",
                    mitigation="Use server-side HTML sanitisation libraries.",
                ))

    return matches


def _check_path_traversal(url_path: str, inputs: List[str], enabled_rules: Dict[str, dict]) -> List[RuleMatch]:
    matches: List[RuleMatch] = []
    if "PT-001" not in enabled_rules:
        return matches

    all_targets = [url_path] + inputs
    for val in all_targets:
        norm = _normalize_input(val)
        if _PATH_TRAVERSAL.search(norm):
            matches.append(RuleMatch(
                rule_id="PT-001",
                name="Path Traversal Detection",
                category="PATH_TRAVERSAL",
                severity="HIGH",
                reason=f"Path traversal sequence detected: {_sanitize_for_log(val[:80])}",
                mitigation="Resolve paths server-side, restrict to allowed directories, never trust user-supplied paths.",
            ))
            break  # one match is enough per request

    return matches


def _check_validation(
    method: str,
    url: str,
    body_size: int,
    enabled_rules: Dict[str, dict],
) -> List[RuleMatch]:
    matches: List[RuleMatch] = []

    # VAL-003: HTTP method
    if "VAL-003" in enabled_rules:
        cfg = json.loads(enabled_rules["VAL-003"].get("configuration_json", "{}"))
        allowed = cfg.get("allowed_methods", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        if method.upper() not in allowed:
            matches.append(RuleMatch(
                rule_id="VAL-003",
                name="Invalid HTTP Method",
                category="VALIDATION",
                severity="LOW",
                reason=f"HTTP method '{_sanitize_for_log(method[:16])}' is not in the allowed list.",
                mitigation="Configure your server to accept only the HTTP methods required.",
            ))

    # VAL-001: URL length
    if "VAL-001" in enabled_rules:
        cfg = json.loads(enabled_rules["VAL-001"].get("configuration_json", "{}"))
        max_url = cfg.get("max_url_length", 2048)
        if len(url) > max_url:
            matches.append(RuleMatch(
                rule_id="VAL-001",
                name="URL Length Limit",
                category="VALIDATION",
                severity="LOW",
                reason=f"URL length {len(url)} exceeds maximum {max_url}.",
                mitigation="Reject oversized URLs at the load balancer or WAF.",
            ))

    # VAL-002: body size
    if "VAL-002" in enabled_rules:
        cfg = json.loads(enabled_rules["VAL-002"].get("configuration_json", "{}"))
        max_body = cfg.get("max_body_bytes", 102400)
        if body_size > max_body:
            matches.append(RuleMatch(
                rule_id="VAL-002",
                name="Request Body Size Limit",
                category="VALIDATION",
                severity="LOW",
                reason=f"Request body {body_size} bytes exceeds maximum {max_body} bytes.",
                mitigation="Configure server-side content-length limits.",
            ))

    return matches


# ── Main inspection entry point ────────────────────────────────────────────────

def inspect_request(
    method: str,
    url: str,
    path: str,
    query_params: Dict[str, List[str]],
    form_data: Dict[str, List[str]],
    body_size: int,
    client_ip: str,
    active_rules: List[Dict],
) -> InspectionResult:
    """
    Evaluate a request against all enabled security rules.
    Returns an InspectionResult with the allow/block decision.
    """
    # Build lookup dict for enabled rules (rule_id -> rule dict)
    enabled: Dict[str, dict] = {
        r["rule_id"]: r for r in active_rules if r.get("enabled", 1)
    }

    # Collect all user-controlled string inputs
    user_inputs: List[str] = []
    for values in query_params.values():
        user_inputs.extend(values)
    for values in form_data.values():
        user_inputs.extend(values)

    all_matches: List[RuleMatch] = []

    # 1. Validation checks (fast-fail candidates)
    all_matches += _check_validation(method, url, body_size, enabled)

    # 2. Path traversal
    all_matches += _check_path_traversal(path, user_inputs, enabled)

    # 3. SQL injection
    all_matches += _check_sql_injection(user_inputs, enabled)

    # 4. XSS
    all_matches += _check_xss(user_inputs, enabled)

    # 5. Rate limiting
    if "RL-001" in enabled:
        cfg = json.loads(enabled["RL-001"].get("configuration_json", "{}"))
        _rate_limiter.update_limits(
            cfg.get("max_requests", 30),
            cfg.get("window_seconds", 60),
        )
        is_limited, _ = _rate_limiter.is_rate_limited(client_ip)
        if is_limited:
            return InspectionResult(
                decision="RATE_LIMITED",
                status_code=429,
                matched_rules=[RuleMatch(
                    rule_id="RL-001",
                    name="Rate Limiter",
                    category="RATE_LIMIT",
                    severity="MEDIUM",
                    reason=f"Client exceeded rate limit ({cfg.get('max_requests',30)} req/{cfg.get('window_seconds',60)}s).",
                    mitigation="Implement client-side back-off. Deploy CAPTCHA for human verification.",
                )],
                attack_category="RATE_LIMIT",
                severity="MEDIUM",
                reason="Rate limit exceeded.",
                mitigation="Reduce request frequency.",
            )
    else:
        # Still track even if rule disabled — just don't block
        _rate_limiter.is_rate_limited(client_ip)

    if not all_matches:
        return InspectionResult(
            decision="ALLOW",
            status_code=200,
            attack_category="NONE",
            severity="INFO",
            reason="Request passed all security checks.",
        )

    # Determine overall severity from worst match
    severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    worst = max(all_matches, key=lambda m: severity_order.get(m.severity, 0))

    # Determine decision type
    validation_matches = [m for m in all_matches if m.category == "VALIDATION"]
    attack_matches = [m for m in all_matches if m.category != "VALIDATION"]

    if attack_matches:
        decision = "BLOCK"
        primary = attack_matches[0]
    else:
        decision = "VALIDATION_ERROR"
        primary = validation_matches[0]

    return InspectionResult(
        decision=decision,
        status_code=403 if decision == "BLOCK" else 400,
        matched_rules=all_matches,
        attack_category=primary.category,
        severity=worst.severity,
        reason=primary.reason,
        mitigation=primary.mitigation,
    )


def reset_rate_limiter() -> None:
    """Reset all rate limit counters (for demo reset)."""
    _rate_limiter.reset()
