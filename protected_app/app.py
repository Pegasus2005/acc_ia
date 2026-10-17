"""
SentinelShield - Protected Demo Application
A deliberately simple Flask app that sits behind the WAF gateway.
All output is HTML-escaped. No SQL concatenation. Static sample data only.

IMPORTANT: This service is intentionally NOT exposed to the host.
It should only be reachable through the WAF gateway.
"""

import logging
from flask import Flask, jsonify, request, escape
from markupsafe import escape as html_escape
import json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelshield.protected")

app = Flask(__name__)

VERSION = "1.0.0"

# ── Static sample data (no real database needed for demo) ──────────────────────
SAMPLE_ITEMS = [
    {"id": 1, "name": "Firewall Ruleset Alpha", "category": "Network Security", "status": "Active"},
    {"id": 2, "name": "Intrusion Detection Config", "category": "Endpoint Security", "status": "Active"},
    {"id": 3, "name": "VPN Policy Document", "category": "Access Control", "status": "Review"},
    {"id": 4, "name": "Security Audit Report Q3", "category": "Compliance", "status": "Completed"},
    {"id": 5, "name": "Incident Response Playbook", "category": "Operations", "status": "Active"},
]

SEARCH_DATA = [
    "firewall configuration guide",
    "intrusion detection best practices",
    "network segmentation policy",
    "zero trust architecture overview",
    "vulnerability assessment checklist",
    "encryption standards documentation",
    "security awareness training module",
    "access control matrix template",
]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SentinelShield Demo App — {title}</title>
  <style>
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background:#0a0e1a; color:#e2e8f0; margin:0; padding:2rem; }}
    .container {{ max-width:900px; margin:0 auto; }}
    h1 {{ color:#06b6d4; font-size:1.8rem; margin-bottom:0.5rem; }}
    .badge {{ background:#1e293b; border:1px solid #06b6d4; color:#06b6d4; padding:0.2rem 0.6rem; border-radius:9999px; font-size:0.75rem; }}
    .card {{ background:#1e293b; border:1px solid #334155; border-radius:0.5rem; padding:1.5rem; margin:1rem 0; }}
    .protected-notice {{ background:#052e16; border:1px solid #16a34a; color:#86efac; padding:1rem; border-radius:0.5rem; margin:1rem 0; font-size:0.875rem; }}
    table {{ width:100%; border-collapse:collapse; }}
    th {{ background:#0f172a; color:#94a3b8; text-align:left; padding:0.75rem; font-size:0.8rem; text-transform:uppercase; }}
    td {{ padding:0.75rem; border-bottom:1px solid #1e293b; }}
    .result {{ color:#06b6d4; }}
    pre {{ background:#0f172a; padding:1rem; border-radius:0.4rem; overflow-x:auto; font-size:0.85rem; }}
  </style>
</head>
<body>
<div class="container">
  <h1>🛡️ Protected Demo Application</h1>
  <span class="badge">Secured by SentinelShield WAF</span>
  <div class="protected-notice">
    ✅ This application is protected behind the SentinelShield WAF Gateway.
       Direct access from the host is restricted.
  </div>
  {content}
</div>
</body>
</html>"""


def render(title: str, content: str) -> str:
    return HTML_TEMPLATE.format(title=title, content=content)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    content = """
    <div class="card">
      <h2>Welcome to the SentinelShield Demo</h2>
      <p>This is a deliberately simple web application for demonstrating WAF protection.</p>
      <p>Available endpoints:</p>
      <ul>
        <li><a href="/search?q=firewall" style="color:#06b6d4">/search?q=&lt;query&gt;</a> — Harmless search</li>
        <li><a href="/items" style="color:#06b6d4">/items</a> — Sample item list</li>
        <li><a href="/items/1" style="color:#06b6d4">/items/&lt;id&gt;</a> — Item detail</li>
        <li>/feedback (POST) — Submit feedback</li>
        <li><a href="/health" style="color:#06b6d4">/health</a> — Health check</li>
      </ul>
    </div>
    """
    return render("Home", content)


@app.route("/search", methods=["GET"])
def search():
    # User query is HTML-escaped before display — never executed or injected into SQL
    raw_query = request.args.get("q", "")
    safe_query = str(html_escape(raw_query))[:200]  # escape and limit

    results = [
        item for item in SEARCH_DATA
        if safe_query.lower() in item.lower()
    ] if safe_query else SEARCH_DATA[:5]

    result_html = "".join(f"<li class='result'>📄 {str(html_escape(r))}</li>" for r in results)
    content = f"""
    <div class="card">
      <h2>Search Results</h2>
      <p>Query: <strong>{safe_query if safe_query else '(none)'}</strong></p>
      <p>Found {len(results)} result(s):</p>
      <ul>{result_html if results else '<li>No results found.</li>'}</ul>
    </div>
    """
    return render("Search", content)


@app.route("/items", methods=["GET"])
def list_items():
    rows = ""
    for item in SAMPLE_ITEMS:
        rows += f"""<tr>
          <td>{item['id']}</td>
          <td>{str(html_escape(item['name']))}</td>
          <td>{str(html_escape(item['category']))}</td>
          <td>{str(html_escape(item['status']))}</td>
        </tr>"""

    content = f"""
    <div class="card">
      <h2>Security Resources</h2>
      <table>
        <thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Status</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    """
    return render("Items", content)


@app.route("/items/<int:item_id>", methods=["GET"])
def get_item(item_id: int):
    item = next((i for i in SAMPLE_ITEMS if i["id"] == item_id), None)
    if not item:
        return render("Not Found", "<div class='card'><h2>Item not found</h2></div>"), 404

    content = f"""
    <div class="card">
      <h2>{str(html_escape(item['name']))}</h2>
      <p><strong>ID:</strong> {item['id']}</p>
      <p><strong>Category:</strong> {str(html_escape(item['category']))}</p>
      <p><strong>Status:</strong> {str(html_escape(item['status']))}</p>
    </div>
    """
    return render(f"Item {item_id}", content)


@app.route("/feedback", methods=["POST"])
def feedback():
    data = request.get_json(silent=True) or {}
    message = str(html_escape(str(data.get("message", ""))[:500]))
    name = str(html_escape(str(data.get("name", "Anonymous"))[:100]))

    if not message.strip():
        return jsonify({"error": "Message is required"}), 400

    logger.info("Feedback received from %s (length %d)", name, len(message))
    return jsonify({
        "success": True,
        "message": "Thank you for your feedback!",
        "submitted_by": name,
        "char_count": len(message),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "sentinelshield-protected-app",
        "version": VERSION,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
