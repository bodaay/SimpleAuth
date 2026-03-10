"""
flask_app.py -- Flask application protected by SimpleAuth.

Demonstrates:
  - Setting up SimpleAuth with Flask using the flask_middleware decorator
  - Public and protected endpoints
  - Role-restricted endpoints
  - Login endpoint that proxies credentials to SimpleAuth
  - Blueprint-based route organization
  - Token refresh endpoint

Prerequisites:
  pip install flask simpleauth

Usage:
  flask --app flask_app run --port 5000 --reload
  # or: python flask_app.py
"""

from flask import Flask, Blueprint, g, jsonify, request

from simpleauth.client import SimpleAuth, AuthenticationError
from simpleauth.middleware import flask_middleware


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SIMPLEAUTH_URL = "https://auth.example.com"

auth = SimpleAuth(
    url=SIMPLEAUTH_URL,
    verify_ssl=True,
)


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Health check -- no authentication required."""
    return jsonify({"status": "ok", "service": "SimpleAuth Flask Example"})


# ---------------------------------------------------------------------------
# Authentication endpoints (login / refresh)
# ---------------------------------------------------------------------------

@app.route("/auth/login", methods=["POST"])
def login():
    """Proxy login to SimpleAuth and return tokens.

    Expects JSON body: {"username": "...", "password": "..."}
    Returns the token response from SimpleAuth.
    """
    body = request.get_json(silent=True)
    if not body or "username" not in body or "password" not in body:
        return jsonify({"error": "username and password are required"}), 400

    try:
        tokens = auth.login(body["username"], body["password"])
    except AuthenticationError as exc:
        return jsonify({
            "error": str(exc),
            "detail": exc.detail,
        }), exc.status_code or 401

    return jsonify({
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": tokens.token_type,
        "expires_in": tokens.expires_in,
    })


@app.route("/auth/refresh", methods=["POST"])
def refresh_token():
    """Exchange a refresh token for a new access token.

    Expects JSON body: {"refresh_token": "..."}
    """
    body = request.get_json(silent=True)
    if not body or "refresh_token" not in body:
        return jsonify({"error": "refresh_token is required"}), 400

    try:
        tokens = auth.refresh(body["refresh_token"])
    except AuthenticationError as exc:
        return jsonify({"error": str(exc)}), exc.status_code or 401

    return jsonify({
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "token_type": tokens.token_type,
        "expires_in": tokens.expires_in,
    })


# ---------------------------------------------------------------------------
# Protected endpoints -- any authenticated user
# ---------------------------------------------------------------------------

@app.route("/me")
@flask_middleware(auth)
def get_me():
    """Returns the authenticated user's profile.

    The @flask_middleware decorator verifies the Bearer token and places the
    User object on flask.g.user.
    """
    user = g.user
    return jsonify({
        "sub": user.sub,
        "name": user.name,
        "email": user.email,
        "username": user.preferred_username,
        "roles": user.roles,
        "permissions": user.permissions,
        "groups": user.groups,
    })


@app.route("/dashboard")
@flask_middleware(auth)
def dashboard():
    """Personalized dashboard."""
    user = g.user
    return jsonify({
        "message": f"Welcome, {user.name or user.preferred_username}!",
        "your_roles": user.roles,
    })


# ---------------------------------------------------------------------------
# Role-restricted endpoints
# ---------------------------------------------------------------------------

@app.route("/admin/settings")
@flask_middleware(auth, required_role="admin")
def admin_settings():
    """View admin settings. Requires the 'admin' role.

    Returns 403 automatically if the user lacks the role.
    """
    return jsonify({
        "settings": {
            "max_users": 1000,
            "mfa_enabled": True,
            "session_timeout_minutes": 30,
        },
        "modified_by": g.user.name,
    })


@app.route("/admin/settings", methods=["PUT"])
@flask_middleware(auth, required_role="admin")
def update_admin_settings():
    """Update admin settings. Requires the 'admin' role."""
    body = request.get_json(silent=True) or {}
    return jsonify({
        "updated": True,
        "settings": body,
        "modified_by": g.user.sub,
    })


# ---------------------------------------------------------------------------
# Permission-restricted endpoints
# ---------------------------------------------------------------------------

@app.route("/reports/export")
@flask_middleware(auth, required_permission="reports:export")
def export_report():
    """Export a report. Requires the 'reports:export' permission."""
    return jsonify({
        "report": "Q4 Sales Report",
        "format": "csv",
        "rows": 1234,
        "requested_by": g.user.name,
    })


# ---------------------------------------------------------------------------
# Blueprint example -- organizing related routes together
# ---------------------------------------------------------------------------

projects_bp = Blueprint("projects", __name__, url_prefix="/projects")


@projects_bp.route("/")
@flask_middleware(auth)
def list_projects():
    """List projects visible to the authenticated user."""
    user = g.user
    # In a real app you would filter by user's groups/permissions
    projects = [
        {"id": 1, "name": "Alpha", "department": "Engineering"},
        {"id": 2, "name": "Beta", "department": "Marketing"},
    ]

    # Filter to user's department if they are not admin
    if not user.has_role("admin") and user.department:
        projects = [p for p in projects if p["department"] == user.department]

    return jsonify({"projects": projects})


@projects_bp.route("/<int:project_id>")
@flask_middleware(auth)
def get_project(project_id: int):
    """Get a single project by ID."""
    return jsonify({
        "id": project_id,
        "name": "Alpha",
        "accessed_by": g.user.sub,
    })


@projects_bp.route("/", methods=["POST"])
@flask_middleware(auth, required_permission="projects:create")
def create_project():
    """Create a new project. Requires 'projects:create' permission."""
    body = request.get_json(silent=True) or {}
    return jsonify({
        "created": True,
        "project": body.get("name", "Untitled"),
        "owner": g.user.sub,
    }), 201


# Register the blueprint
app.register_blueprint(projects_bp)


# ---------------------------------------------------------------------------
# Error handler for SimpleAuth errors
# ---------------------------------------------------------------------------

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Authentication required"}), 401


@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Insufficient permissions"}), 403


# ---------------------------------------------------------------------------
# Run the app
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
