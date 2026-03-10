"""
fastapi_app.py -- FastAPI application protected by SimpleAuth.

Demonstrates:
  - Setting up SimpleAuth with FastAPI
  - Public endpoints (no auth required)
  - Protected endpoints via Depends(get_user)
  - Role-restricted endpoints via SimpleAuthDep(required_role=...)
  - Permission-restricted endpoints via SimpleAuthDep(required_permission=...)
  - Accessing user claims inside handlers
  - OpenAPI / Swagger integration with Bearer security scheme

Prerequisites:
  pip install fastapi uvicorn simpleauth

Usage:
  uvicorn fastapi_app:app --reload --port 8000
  # Then open http://localhost:8000/docs for interactive API docs
"""

from fastapi import Depends, FastAPI, HTTPException
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer

from simpleauth.client import SimpleAuth, User
from simpleauth.middleware import SimpleAuthDep


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SIMPLEAUTH_URL = "https://auth.example.com"

auth = SimpleAuth(
    url=SIMPLEAUTH_URL,
    verify_ssl=True,
)

# ---------------------------------------------------------------------------
# Dependencies -- create reusable dependency instances
# ---------------------------------------------------------------------------

# Basic auth: any valid token
get_user = SimpleAuthDep(auth)

# Role-restricted: user must have "admin" role
require_admin = SimpleAuthDep(auth, required_role="admin")

# Permission-restricted: user must have "reports:read" permission
require_reports = SimpleAuthDep(auth, required_permission="reports:read")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

# HTTPBearer makes the "Authorize" button appear in Swagger UI
bearer_scheme = HTTPBearer(auto_error=False)

app = FastAPI(
    title="SimpleAuth FastAPI Example",
    description="Demonstrates SimpleAuth integration with FastAPI.",
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# OpenAPI customization -- adds Bearer auth to all endpoints in Swagger
# ---------------------------------------------------------------------------

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Add security scheme
    schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Paste your SimpleAuth access token here.",
        }
    }

    # Apply globally to all operations
    schema["security"] = [{"BearerAuth": []}]

    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["Public"])
async def root():
    """Public health check -- no authentication required."""
    return {"status": "ok", "service": "SimpleAuth FastAPI Example"}


@app.get("/public/info", tags=["Public"])
async def public_info():
    """Returns general application info. No auth needed."""
    return {
        "auth_server": SIMPLEAUTH_URL,
        "docs": "/docs",
    }


# ---------------------------------------------------------------------------
# Protected endpoints -- any authenticated user
# ---------------------------------------------------------------------------

@app.get("/me", tags=["Protected"])
async def get_me(user: User = Depends(get_user)):
    """Returns the authenticated user's profile.

    Requires a valid Bearer token in the Authorization header.
    """
    return {
        "sub": user.sub,
        "name": user.name,
        "email": user.email,
        "username": user.preferred_username,
        "roles": user.roles,
        "permissions": user.permissions,
        "groups": user.groups,
        "department": user.department,
        "company": user.company,
        "job_title": user.job_title,
    }


@app.get("/dashboard", tags=["Protected"])
async def dashboard(user: User = Depends(get_user)):
    """Example dashboard endpoint -- personalized greeting."""
    return {
        "message": f"Welcome back, {user.name or user.preferred_username}!",
        "your_roles": user.roles,
    }


# ---------------------------------------------------------------------------
# Role-restricted endpoints
# ---------------------------------------------------------------------------

@app.get("/admin/users", tags=["Admin"])
async def list_users(user: User = Depends(require_admin)):
    """List all users. Requires the 'admin' role.

    Returns 403 if the authenticated user does not have the admin role.
    """
    return {
        "message": f"Admin {user.name} accessed user list.",
        "users": ["alice", "bob", "charlie"],  # placeholder
    }


@app.delete("/admin/users/{user_id}", tags=["Admin"])
async def delete_user(user_id: str, user: User = Depends(require_admin)):
    """Delete a user by ID. Requires the 'admin' role."""
    return {"deleted": user_id, "by": user.sub}


# ---------------------------------------------------------------------------
# Permission-restricted endpoints
# ---------------------------------------------------------------------------

@app.get("/reports/monthly", tags=["Reports"])
async def monthly_report(user: User = Depends(require_reports)):
    """Generate a monthly report. Requires 'reports:read' permission."""
    return {
        "report": "Monthly Sales Report",
        "generated_for": user.name,
        "data": [100, 200, 150, 300],
    }


# ---------------------------------------------------------------------------
# Inline role/permission checks (for finer-grained control)
# ---------------------------------------------------------------------------

@app.post("/documents", tags=["Documents"])
async def create_document(user: User = Depends(get_user)):
    """Create a document. Checks 'documents:write' permission inline.

    This pattern is useful when you need different permissions for different
    HTTP methods on the same resource, or conditional logic based on roles.
    """
    if not user.has_permission("documents:write"):
        raise HTTPException(
            status_code=403,
            detail="You need the 'documents:write' permission to create documents.",
        )

    return {"created": True, "author": user.sub}


@app.get("/team", tags=["Team"])
async def team_info(user: User = Depends(get_user)):
    """Returns different data depending on the user's role."""
    base = {"team": "Engineering", "member": user.name}

    if user.has_role("manager"):
        # Managers see salary info
        base["salaries"] = {"avg": 95000, "total": 950000}

    if user.has_any_role("admin", "hr"):
        # Admin and HR see PII
        base["employee_ssns"] = "***REDACTED***"  # just an example

    return base


# ---------------------------------------------------------------------------
# Run with: uvicorn fastapi_app:app --reload --port 8000
# ---------------------------------------------------------------------------
