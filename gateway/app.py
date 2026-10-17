"""
SentinelShield WAF Gateway - Flask Application
Receives incoming HTTP requests, runs the security rule engine,
logs events, and forwards allowed requests to the protected application.
"""

import os
import uuid
import time
import logging
import json
import requests
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, Response
from flask_cors import CORS

from database import (
    init_db, log_security_event, get_stats, get_events,
    get_event_by_request_id, get_events_for_charts, get_rules,
    update_rule, reset_rules_to_defaults, reset_demo_data,
    get_audit_events, get_db_stats,
)
from rules_engine import inspect_request, reset_rate_limiter

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelshield.gateway")

# ── App configuration ──────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})  # dashboard is same-network

PROTECTED_APP_URL = os.environ.get("PROTECTED_APP_URL", "http://protected-app:5001")
# Handle schemes for Render and local URLs; strip any trailing slashes
if PROTECTED_APP_URL and not PROTECTED_APP_URL.startswith(("http://", "https://")):
    if "onrender.com" in PROTECTED_APP_URL:
        PROTECTED_APP_URL = "https://" + PROTECTED_APP_URL
    else:
        PROTECTED_APP_URL = "http://" + PROTECTED_APP_URL
PROTECTED_APP_URL = PROTECTED_APP_URL.rstrip("/")
API_SECRET = os.environ.get("API_SECRET", "sentinelshield-demo-secret")
VERSION = "1.0.0"

# Max body size the gateway will inspect (bytes); requests larger than this
# are rejected without forwarding.
MAX_BODY_INSPECT = int(os.environ.get("MAX_BODY_INSPECT", 512 * 1024))  # 512 KB

# ── Helpers ────────────────────────────────────────────────────────────────────

def _require_api_key(f):
    """Simple API key guard for administrative endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if key != API_SECRET:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def _get_client_ip() -> str:
    """
    Return the client's remote address.
    Does NOT trust X-Forwarded-For to prevent IP spoofing in this demo.
    """
    return request.remote_addr or "unknown"


def _sanitize_route(path: str) -> str:
    """Return only the path portion, stripped of query string, truncated."""
    return path[:256] if path else "/"


def _blocked_response(result, request_id: str) -> Response:
    """Build a structured error response for blocked requests."""
    rule_ids = [m.rule_id for m in result.matched_rules]
    body = {
        "blocked": True,
        "request_id": request_id,
        "decision": result.decision,
        "matched_rule_ids": rule_ids,
        "reason": result.reason,
        "mitigation": result.mitigation,
        "message": "Request blocked by SentinelShield WAF",
    }
    resp = jsonify(body)
    resp.status_code = result.status_code
    resp.headers["X-SentinelShield-Decision"] = result.decision
    resp.headers["X-SentinelShield-Request-ID"] = request_id
    return resp


def _add_security_headers(resp: Response) -> Response:
    """Add security response headers to all outbound responses."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-XSS-Protection", "1; mode=block")
    return resp


# ── Main proxy / inspection handler ───────────────────────────────────────────

def _handle_request(path: str) -> Response:
    """
    Core request-inspection pipeline.
    1. Generate request ID and timestamp.
    2. Validate raw request properties.
    3. Run security rule engine.
    4. Log the decision.
    5. Forward or block.
    """
    request_id = str(uuid.uuid4())
    t_start = time.perf_counter()
    timestamp = datetime.now(timezone.utc).isoformat()
    client_ip = _get_client_ip()
    sanitized_route = _sanitize_route("/" + path)
    method = request.method.upper()
    full_url = request.url

    # Read body (with size guard)
    body_size = 0
    try:
        # Flask reads up to MAX_BODY_INSPECT bytes
        body = request.get_data(cache=True)
        body_size = len(body)
    except Exception:
        body = b""
        body_size = 0

    # Build parameter dicts for rule engine
    query_params = {k: request.args.getlist(k) for k in request.args}
    form_data = {k: request.form.getlist(k) for k in request.form}

    # Load current enabled rules from DB
    db_rules = get_rules()

    # Run inspection
    result = inspect_request(
        method=method,
        url=full_url,
        path=sanitized_route,
        query_params=query_params,
        form_data=form_data,
        body_size=body_size,
        client_ip=client_ip,
        active_rules=db_rules,
    )

    processing_ms = (time.perf_counter() - t_start) * 1000

    # Log event
    event = {
        "request_id": request_id,
        "timestamp_utc": timestamp,
        "method": method,
        "route": sanitized_route,
        "decision": result.decision,
        "status_code": result.status_code if result.is_blocked() else 200,
        "matched_rule_ids": [m.rule_id for m in result.matched_rules],
        "attack_category": result.attack_category,
        "severity": result.severity,
        "reason": result.reason[:512],
        "processing_time_ms": round(processing_ms, 2),
        "sanitized_client_id": client_ip,
    }

    try:
        log_security_event(event)
    except Exception as e:
        logger.error("Failed to log security event: %s", e)

    if result.is_blocked():
        logger.warning(
            "BLOCKED [%s] %s %s | rules=%s | reason=%s",
            request_id, method, sanitized_route,
            event["matched_rule_ids"], result.reason[:120],
        )
        resp = _blocked_response(result, request_id)
        return _add_security_headers(resp)

    # Forward to protected app
    logger.info("ALLOW [%s] %s %s", request_id, method, sanitized_route)
    try:
        target_url = f"{PROTECTED_APP_URL}/{path}"
        if request.query_string:
            target_url += "?" + request.query_string.decode("utf-8", errors="replace")

        fwd_headers = {
            k: v for k, v in request.headers
            if k.lower() not in ("host", "authorization", "cookie", "x-api-key")
        }
        fwd_headers["X-SentinelShield-Request-ID"] = request_id
        fwd_headers["X-SentinelShield-Decision"] = "ALLOW"

        upstream = requests.request(
            method=method,
            url=target_url,
            headers=fwd_headers,
            data=body,
            allow_redirects=False,
            timeout=10,
        )

        resp = Response(
            upstream.content,
            status=upstream.status_code,
            headers={
                k: v for k, v in upstream.headers.items()
                if k.lower() not in ("transfer-encoding", "connection")
            },
        )
        resp.headers["X-SentinelShield-Decision"] = "ALLOW"
        resp.headers["X-SentinelShield-Request-ID"] = request_id

        # Update log with real upstream status
        event["status_code"] = upstream.status_code
        try:
            log_security_event({**event, "processing_time_ms": round((time.perf_counter() - t_start) * 1000, 2)})
        except Exception:
            pass  # Already logged once; this is the updated version

        return _add_security_headers(resp)

    except requests.exceptions.Timeout:
        logger.error("Upstream timeout for request %s", request_id)
        return _add_security_headers(
            jsonify({"error": "Upstream timeout", "request_id": request_id}),
        ), 504
    except requests.exceptions.ConnectionError:
        logger.error("Cannot reach protected app for request %s", request_id)
        return _add_security_headers(
            jsonify({"error": "Protected application unavailable", "request_id": request_id}),
        ), 502


# ── Proxy routes ───────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def proxy_root():
    return _handle_request("")


@app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
def proxy_path(path: str):
    # Keep API and health routes internal to gateway
    if path.startswith("api/") or path == "health":
        return jsonify({"error": "Not found"}), 404
    return _handle_request(path)


# ── Gateway health ─────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def gateway_health():
    """Gateway liveness probe — does not expose sensitive config."""
    db_ok = True
    try:
        get_db_stats()
    except Exception:
        db_ok = False

    return jsonify({
        "status": "healthy" if db_ok else "degraded",
        "service": "sentinelshield-gateway",
        "version": VERSION,
        "db_connected": db_ok,
    }), 200 if db_ok else 503


# ── Statistics API ─────────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def api_stats():
    try:
        return jsonify(get_stats())
    except Exception as e:
        logger.error("stats error: %s", e)
        return jsonify({"error": "Internal error"}), 500


@app.route("/api/events", methods=["GET"])
def api_events():
    try:
        limit = min(int(request.args.get("limit", 200)), 1000)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify({"error": "Invalid pagination parameters"}), 400

    decision = request.args.get("decision")
    severity = request.args.get("severity")
    category = request.args.get("category")
    from_ts = request.args.get("from")
    to_ts = request.args.get("to")

    # Basic validation
    valid_decisions = {"ALLOW", "BLOCK", "RATE_LIMITED", "VALIDATION_ERROR", None}
    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO", None}
    if decision not in valid_decisions or severity not in valid_severities:
        return jsonify({"error": "Invalid filter value"}), 400

    try:
        events = get_events(
            limit=limit, offset=offset,
            decision=decision, severity=severity, category=category,
            from_ts=from_ts, to_ts=to_ts,
        )
        return jsonify({"events": events, "count": len(events)})
    except Exception as e:
        logger.error("events error: %s", e)
        return jsonify({"error": "Internal error"}), 500


@app.route("/api/events/<request_id>", methods=["GET"])
def api_event_detail(request_id: str):
    if not request_id or len(request_id) > 64:
        return jsonify({"error": "Invalid request ID"}), 400
    event = get_event_by_request_id(request_id)
    if not event:
        return jsonify({"error": "Not found"}), 404
    return jsonify(event)


@app.route("/api/charts", methods=["GET"])
def api_charts():
    """Return chart data for the dashboard."""
    try:
        return jsonify({"events": get_events_for_charts()})
    except Exception as e:
        logger.error("charts error: %s", e)
        return jsonify({"error": "Internal error"}), 500


# ── Rules API ──────────────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
def api_rules():
    try:
        return jsonify({"rules": get_rules()})
    except Exception as e:
        logger.error("rules error: %s", e)
        return jsonify({"error": "Internal error"}), 500


@app.route("/api/rules/<rule_id>", methods=["PATCH"])
@_require_api_key
def api_update_rule(rule_id: str):
    if not rule_id or len(rule_id) > 32:
        return jsonify({"error": "Invalid rule ID"}), 400
    data = request.get_json(silent=True)
    if not data or "enabled" not in data:
        return jsonify({"error": "Missing 'enabled' field"}), 400
    if not isinstance(data["enabled"], bool):
        return jsonify({"error": "'enabled' must be boolean"}), 400

    # Prevent disabling ALL rules at once
    if not data["enabled"]:
        rules = get_rules()
        enabled_count = sum(1 for r in rules if r["enabled"] and r["rule_id"] != rule_id)
        if enabled_count == 0:
            return jsonify({"error": "Cannot disable the last active rule"}), 409

    ok = update_rule(rule_id, data["enabled"], actor="api")
    if not ok:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify({"success": True, "rule_id": rule_id, "enabled": data["enabled"]})


@app.route("/api/rules/reset", methods=["POST"])
@_require_api_key
def api_reset_rules():
    try:
        reset_rules_to_defaults()
        return jsonify({"success": True, "message": "All rules restored to secure defaults"})
    except Exception as e:
        logger.error("reset_rules error: %s", e)
        return jsonify({"error": "Internal error"}), 500


# ── Demo reset ─────────────────────────────────────────────────────────────────

@app.route("/api/demo/reset", methods=["POST"])
@_require_api_key
def api_demo_reset():
    try:
        reset_demo_data()
        reset_rate_limiter()
        return jsonify({"success": True, "message": "Demo data cleared"})
    except Exception as e:
        logger.error("demo_reset error: %s", e)
        return jsonify({"error": "Internal error"}), 500


# ── DB stats ───────────────────────────────────────────────────────────────────

@app.route("/api/db-stats", methods=["GET"])
def api_db_stats():
    try:
        return jsonify(get_db_stats())
    except Exception as e:
        logger.error("db_stats error: %s", e)
        return jsonify({"error": "Internal error"}), 500


@app.route("/api/audit", methods=["GET"])
@_require_api_key
def api_audit():
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except ValueError:
        limit = 100
    return jsonify({"events": get_audit_events(limit)})


# ── Startup ────────────────────────────────────────────────────────────────────

def create_app():
    init_db()
    logger.info("SentinelShield Gateway v%s started. DB: %s", VERSION,
                os.environ.get("DB_PATH", "/data/sentinelshield.db"))
    return app


if __name__ == "__main__":
    create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)
