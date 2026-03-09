"""
django_views.py -- Django views protected by SimpleAuth.

Demonstrates:
  - Django settings configuration for SimpleAuth middleware
  - Function-based views with @django_login_required
  - Class-based views with SimpleAuth
  - Role and permission checks
  - Accessing the authenticated user via request.simpleauth_user

Prerequisites:
  pip install django simpleauth

Setup:
  1. Add SimpleAuth settings to your settings.py (see SETTINGS CONFIGURATION below)
  2. Add the middleware to MIDDLEWARE
  3. Wire up these views in your urls.py

This file is meant to be included in a Django project -- it is not a
standalone runnable script.
"""

# ============================================================================
# SETTINGS CONFIGURATION -- add these to your project's settings.py
# ============================================================================
#
# # SimpleAuth configuration
# SIMPLEAUTH_URL = "https://auth.example.com"
# SIMPLEAUTH_APP_ID = "my-django-app"
# SIMPLEAUTH_APP_SECRET = "app-secret-key-here"  # optional
# SIMPLEAUTH_REALM = "simpleauth"                 # optional, default "simpleauth"
# SIMPLEAUTH_VERIFY_SSL = True                    # optional, default True
#
# MIDDLEWARE = [
#     "django.middleware.security.SecurityMiddleware",
#     "django.contrib.sessions.middleware.SessionMiddleware",
#     "django.middleware.common.CommonMiddleware",
#     # ... other middleware ...
#
#     # SimpleAuth middleware -- verifies Bearer tokens and sets
#     # request.simpleauth_user on every request. Place it after
#     # Django's built-in middleware.
#     "simpleauth.middleware.SimpleAuthMiddleware",
# ]
#
# ============================================================================
# URL CONFIGURATION -- add these to your project's urls.py
# ============================================================================
#
# from django.urls import path
# from . import django_views as views
#
# urlpatterns = [
#     path("", views.index),
#     path("me/", views.get_me),
#     path("dashboard/", views.dashboard),
#     path("admin/settings/", views.admin_settings),
#     path("reports/", views.reports),
#     path("projects/", views.ProjectListView.as_view()),
#     path("projects/<int:pk>/", views.ProjectDetailView.as_view()),
# ]
#
# ============================================================================

from django.http import JsonResponse
from django.views import View

from simpleauth.middleware import django_login_required


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

def index(request):
    """Health check -- no authentication required.

    The SimpleAuth middleware still runs (it sets request.simpleauth_user
    to None if no token is present), but we do not require a user here.
    """
    return JsonResponse({
        "status": "ok",
        "service": "SimpleAuth Django Example",
        "authenticated": request.simpleauth_user is not None,
    })


# ---------------------------------------------------------------------------
# Protected function-based views
# ---------------------------------------------------------------------------

@django_login_required()
def get_me(request):
    """Returns the authenticated user's profile.

    The @django_login_required() decorator returns a 401 JSON response
    if request.simpleauth_user is None.
    """
    user = request.simpleauth_user
    return JsonResponse({
        "sub": user.sub,
        "name": user.name,
        "email": user.email,
        "username": user.preferred_username,
        "roles": user.roles,
        "permissions": user.permissions,
        "groups": user.groups,
        "department": user.department,
        "company": user.company,
    })


@django_login_required()
def dashboard(request):
    """Personalized dashboard for the authenticated user."""
    user = request.simpleauth_user
    return JsonResponse({
        "message": f"Welcome, {user.name or user.preferred_username}!",
        "your_roles": user.roles,
        "your_groups": user.groups,
    })


# ---------------------------------------------------------------------------
# Role-restricted views
# ---------------------------------------------------------------------------

@django_login_required(required_role="admin")
def admin_settings(request):
    """View admin settings. Returns 403 if user lacks 'admin' role.

    The decorator handles the role check automatically -- if the user
    does not have the required role, a 403 JSON response is returned
    before this function body executes.
    """
    user = request.simpleauth_user

    if request.method == "GET":
        return JsonResponse({
            "settings": {
                "max_users": 1000,
                "mfa_enabled": True,
                "session_timeout_minutes": 30,
            },
            "accessed_by": user.name,
        })

    # For PUT/PATCH -- update settings
    import json
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    return JsonResponse({
        "updated": True,
        "settings": body,
        "modified_by": user.sub,
    })


# ---------------------------------------------------------------------------
# Permission-restricted views
# ---------------------------------------------------------------------------

@django_login_required(required_permission="reports:read")
def reports(request):
    """Generate a report. Requires 'reports:read' permission."""
    user = request.simpleauth_user
    return JsonResponse({
        "report": "Monthly Sales Summary",
        "generated_for": user.name,
        "data": [
            {"month": "January", "revenue": 50000},
            {"month": "February", "revenue": 62000},
            {"month": "March", "revenue": 58000},
        ],
    })


# ---------------------------------------------------------------------------
# Class-based views
# ---------------------------------------------------------------------------

class ProjectListView(View):
    """List and create projects using Django class-based views.

    For CBVs, apply the decorator manually or check request.simpleauth_user
    inside the method.
    """

    def get(self, request):
        """List all projects. Requires authentication."""
        user = request.simpleauth_user
        if user is None:
            return JsonResponse({"error": "Authentication required"}, status=401)

        projects = [
            {"id": 1, "name": "Alpha", "department": "Engineering"},
            {"id": 2, "name": "Beta", "department": "Marketing"},
            {"id": 3, "name": "Gamma", "department": "Engineering"},
        ]

        # Non-admins only see projects in their department
        if not user.has_role("admin") and user.department:
            projects = [p for p in projects if p["department"] == user.department]

        return JsonResponse({"projects": projects})

    def post(self, request):
        """Create a project. Requires 'projects:create' permission."""
        user = request.simpleauth_user
        if user is None:
            return JsonResponse({"error": "Authentication required"}, status=401)

        if not user.has_permission("projects:create"):
            return JsonResponse(
                {"error": "Required permission: projects:create"},
                status=403,
            )

        import json
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        return JsonResponse({
            "created": True,
            "project": body.get("name", "Untitled"),
            "owner": user.sub,
        }, status=201)


class ProjectDetailView(View):
    """Single project detail view."""

    def get(self, request, pk):
        user = request.simpleauth_user
        if user is None:
            return JsonResponse({"error": "Authentication required"}, status=401)

        return JsonResponse({
            "id": pk,
            "name": "Alpha",
            "description": "Main project",
            "accessed_by": user.sub,
        })

    def delete(self, request, pk):
        """Delete a project. Only admins or managers can delete."""
        user = request.simpleauth_user
        if user is None:
            return JsonResponse({"error": "Authentication required"}, status=401)

        if not user.has_any_role("admin", "manager"):
            return JsonResponse(
                {"error": "Only admins and managers can delete projects"},
                status=403,
            )

        return JsonResponse({"deleted": pk, "by": user.sub})
