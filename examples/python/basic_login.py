"""
basic_login.py -- Simple login, token verification, and refresh flow.

Demonstrates:
  - Authenticating with username and password
  - Verifying an access token and inspecting user claims
  - Refreshing an expired access token
  - Fetching user info from the OIDC userinfo endpoint
  - Handling authentication errors gracefully

Prerequisites:
  pip install simpleauth

Usage:
  python basic_login.py
"""

import sys

from simpleauth.client import (
    SimpleAuth,
    AuthenticationError,
    TokenVerificationError,
)


# ---------------------------------------------------------------------------
# Configuration -- replace with your SimpleAuth server details
# ---------------------------------------------------------------------------

SIMPLEAUTH_URL = "https://auth.example.com/sauth"

# Create the client once and reuse it (thread-safe, caches JWKS keys)
auth = SimpleAuth(
    url=SIMPLEAUTH_URL,
    verify_ssl=True,  # set False for self-signed certs in development
)


def main() -> None:
    # ------------------------------------------------------------------
    # Step 1: Login with username and password
    # ------------------------------------------------------------------
    username = input("Username: ")
    password = input("Password: ")

    try:
        tokens = auth.login(username, password)
    except AuthenticationError as exc:
        print(f"Login failed: {exc}")
        print(f"  HTTP status: {exc.status_code}")
        print(f"  Detail:      {exc.detail}")
        sys.exit(1)

    print("\nLogin successful!")
    print(f"  Access token:  {tokens.access_token[:40]}...")
    print(f"  Token type:    {tokens.token_type}")
    print(f"  Expires in:    {tokens.expires_in} seconds")
    print(f"  Refresh token: {tokens.refresh_token[:40] if tokens.refresh_token else 'N/A'}...")

    if getattr(tokens, "force_password_change", False):
        print("\n  ** You must change your password before continuing. **")

    # ------------------------------------------------------------------
    # Step 2: Verify the access token and inspect user claims
    # ------------------------------------------------------------------
    try:
        user = auth.verify(tokens.access_token)
    except TokenVerificationError as exc:
        print(f"\nToken verification failed: {exc}")
        sys.exit(1)

    print("\nVerified user claims:")
    print(f"  Subject (sub):  {user.sub}")
    print(f"  Name:           {user.name}")
    print(f"  Email:          {user.email}")
    print(f"  Username:       {user.preferred_username}")
    print(f"  Roles:          {user.roles}")
    print(f"  Permissions:    {user.permissions}")
    print(f"  Groups:         {user.groups}")
    print(f"  Department:     {user.department}")
    print(f"  Company:        {user.company}")
    print(f"  Job title:      {user.job_title}")

    # Check specific roles / permissions
    if user.has_role("admin"):
        print("\n  ** This user is an admin **")

    if user.has_permission("documents:write"):
        print("  ** This user can write documents **")

    if user.has_any_role("admin", "manager"):
        print("  ** This user is an admin or manager **")

    # ------------------------------------------------------------------
    # Step 3: Fetch additional info from the OIDC userinfo endpoint
    # ------------------------------------------------------------------
    try:
        info = auth.userinfo(tokens.access_token)
        print("\nUserinfo endpoint response:")
        for key, value in info.items():
            print(f"  {key}: {value}")
    except Exception as exc:
        print(f"\nUserinfo fetch failed: {exc}")

    # ------------------------------------------------------------------
    # Step 4: Refresh the token
    # ------------------------------------------------------------------
    if tokens.refresh_token:
        print("\nRefreshing access token...")
        try:
            new_tokens = auth.refresh(tokens.refresh_token)
            print("  New access token obtained!")
            print(f"  Expires in: {new_tokens.expires_in} seconds")

            # The old refresh token is typically invalidated after use.
            # Always use the new refresh token for subsequent refreshes.
            if new_tokens.refresh_token:
                print("  New refresh token issued (rotate it in your storage).")
        except AuthenticationError as exc:
            print(f"  Refresh failed: {exc}")
    else:
        print("\nNo refresh token available (server did not issue one).")


if __name__ == "__main__":
    main()
