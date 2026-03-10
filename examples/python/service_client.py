"""
service_client.py -- Service-to-service authentication with SimpleAuth.

Demonstrates:
  - Client credentials flow (machine-to-machine, no user involved)
  - Requests session with automatic Bearer token injection
  - Auto-refresh when the token is about to expire
  - Making authenticated calls to another internal service

Prerequisites:
  pip install simpleauth requests

Usage:
  python service_client.py
"""

import time
import threading

import requests

from simpleauth.client import SimpleAuth, AuthenticationError, TokenResponse


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SIMPLEAUTH_URL = "https://auth.example.com"
CLIENT_ID = "inventory-service"
CLIENT_SECRET = "service-secret-key-here"

# The downstream API this service needs to call
ORDERS_API_BASE = "https://api.internal.example.com/orders"


# ---------------------------------------------------------------------------
# ServiceAuthSession -- requests.Session with auto-refreshing Bearer token
# ---------------------------------------------------------------------------

class ServiceAuthSession(requests.Session):
    """A requests.Session that automatically obtains and refreshes a
    client-credentials token from SimpleAuth.

    Usage:
        session = ServiceAuthSession(
            auth_url="https://auth.example.com",
            client_id="my-service",
            client_secret="secret",
        )

        # Tokens are fetched and refreshed automatically
        resp = session.get("https://api.internal/orders")
    """

    # Refresh the token 60 seconds before it actually expires
    REFRESH_MARGIN_SECONDS = 60

    def __init__(
        self,
        auth_url: str,
        client_id: str,
        client_secret: str,
        verify_ssl: bool = True,
    ):
        super().__init__()

        self._auth_client = SimpleAuth(
            url=auth_url,
            client_id=client_id,
            client_secret=client_secret,
            verify_ssl=verify_ssl,
        )

        self._token: str | None = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    def _ensure_token(self) -> str:
        """Obtain or refresh the access token (thread-safe)."""
        with self._lock:
            if self._token and time.time() < self._expires_at:
                return self._token

            tokens: TokenResponse = self._auth_client.client_credentials()
            self._token = tokens.access_token
            self._expires_at = time.time() + tokens.expires_in - self.REFRESH_MARGIN_SECONDS

            return self._token

    def request(self, method, url, **kwargs):
        """Override to inject the Bearer token into every request."""
        token = self._ensure_token()

        headers = kwargs.pop("headers", {}) or {}
        headers["Authorization"] = f"Bearer {token}"
        kwargs["headers"] = headers

        return super().request(method, url, **kwargs)


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------

def main() -> None:
    # ------------------------------------------------------------------
    # Option 1: Quick one-off client credentials call
    # ------------------------------------------------------------------
    auth = SimpleAuth(
        url=SIMPLEAUTH_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )

    print("Obtaining service token via client_credentials grant...")
    try:
        tokens = auth.client_credentials()
    except AuthenticationError as exc:
        print(f"Failed to obtain service token: {exc}")
        return

    print(f"  Access token: {tokens.access_token[:40]}...")
    print(f"  Expires in:   {tokens.expires_in} seconds")
    print(f"  Scope:        {tokens.scope}")

    # Verify our own token to see its claims
    user = auth.verify(tokens.access_token)
    print(f"  Service sub:  {user.sub}")
    print(f"  Roles:        {user.roles}")

    # ------------------------------------------------------------------
    # Option 2: Long-lived session with auto-refresh (recommended)
    # ------------------------------------------------------------------
    print("\nCreating auto-refreshing service session...")
    session = ServiceAuthSession(
        auth_url=SIMPLEAUTH_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )

    # Every request through this session automatically includes a valid
    # Bearer token. The token is refreshed transparently when it nears
    # expiration.

    # Example: call the orders API
    print(f"Calling {ORDERS_API_BASE}...")
    try:
        resp = session.get(f"{ORDERS_API_BASE}", timeout=10)
        resp.raise_for_status()
        print(f"  Status: {resp.status_code}")
        print(f"  Body:   {resp.json()}")
    except requests.RequestException as exc:
        print(f"  Request failed (expected if server is not running): {exc}")

    # Example: create an order
    print(f"\nPOSTing to {ORDERS_API_BASE}...")
    try:
        resp = session.post(
            ORDERS_API_BASE,
            json={"item": "Widget", "quantity": 10},
            timeout=10,
        )
        print(f"  Status: {resp.status_code}")
    except requests.RequestException as exc:
        print(f"  Request failed (expected if server is not running): {exc}")

    # ------------------------------------------------------------------
    # Option 3: Using admin APIs to manage user roles
    # ------------------------------------------------------------------
    print("\nManaging user roles via admin API...")
    user_guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    try:
        roles = auth.get_user_roles(user_guid)
        print(f"  Current roles for {user_guid}: {roles}")

        auth.set_user_roles(user_guid, ["viewer", "analyst"])
        print("  Updated roles to: ['viewer', 'analyst']")

        permissions = auth.get_user_permissions(user_guid)
        print(f"  Current permissions: {permissions}")

        auth.set_user_permissions(user_guid, ["reports:read", "data:export"])
        print("  Updated permissions to: ['reports:read', 'data:export']")

    except Exception as exc:
        print(f"  Admin API call failed (expected if server is not running): {exc}")


if __name__ == "__main__":
    main()
