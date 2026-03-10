// ---------------------------------------------------------------------------
// SimpleAuth Example: Basic Login Flow
// ---------------------------------------------------------------------------
// Demonstrates the fundamental authentication lifecycle:
//   1. Login with username and password (Resource Owner Password Credentials)
//   2. Verify the returned access token
//   3. Fetch user info from the OIDC userinfo endpoint
//   4. Refresh the token when it expires
//   5. Logout
//
// Usage:
//   npx tsx basic-login.ts
// ---------------------------------------------------------------------------

import { createSimpleAuth, SimpleAuthError } from "@simpleauth/js";

// --- Configuration --------------------------------------------------------

const auth = createSimpleAuth({
  url: process.env.SIMPLEAUTH_URL ?? "https://auth.corp.local:9090",
});

// --- Helpers --------------------------------------------------------------

/** Returns true if the token expires within `windowSec` seconds. */
function isExpiringSoon(expiresIn: number, issuedAt: number, windowSec = 30): boolean {
  const expiresAt = issuedAt + expiresIn;
  const nowSec = Math.floor(Date.now() / 1000);
  return expiresAt - nowSec <= windowSec;
}

// --- Main flow ------------------------------------------------------------

async function main() {
  // -----------------------------------------------------------------------
  // Step 1: Login
  // -----------------------------------------------------------------------
  console.log("[1] Logging in...");

  const username = process.env.TEST_USERNAME ?? "admin";
  const password = process.env.TEST_PASSWORD ?? "admin123";

  let tokens = await auth.login(username, password);
  const loginTime = Math.floor(Date.now() / 1000);

  console.log("  Access token received (expires in %d seconds)", tokens.expires_in);
  console.log("  Token type:", tokens.token_type);
  console.log("  Refresh token present:", !!tokens.refresh_token);

  // -----------------------------------------------------------------------
  // Step 2: Verify the access token
  // -----------------------------------------------------------------------
  console.log("\n[2] Verifying access token...");

  const user = await auth.verify(tokens.access_token);

  console.log("  User ID (sub):", user.sub);
  console.log("  Name:", user.name ?? "(not set)");
  console.log("  Email:", user.email ?? "(not set)");
  console.log("  Roles:", user.roles.length > 0 ? user.roles.join(", ") : "(none)");
  console.log("  Permissions:", user.permissions.length > 0 ? user.permissions.join(", ") : "(none)");
  console.log("  Groups:", user.groups.length > 0 ? user.groups.join(", ") : "(none)");

  // Use the built-in role/permission check helpers
  console.log("\n  Role checks:");
  console.log("    Is admin?", user.hasRole("admin"));
  console.log("    Is editor?", user.hasRole("editor"));
  console.log("    Is admin or editor?", user.hasAnyRole("admin", "editor"));
  console.log("    Can delete users?", user.hasPermission("users:delete"));

  // -----------------------------------------------------------------------
  // Step 3: Fetch user info from the OIDC userinfo endpoint
  // -----------------------------------------------------------------------
  console.log("\n[3] Fetching user info from OIDC endpoint...");

  const info = await auth.userInfo(tokens.access_token);

  console.log("  Subject:", info.sub);
  console.log("  Preferred username:", info.preferred_username ?? "(not set)");
  console.log("  Email:", info.email ?? "(not set)");
  console.log("  Department:", info.department ?? "(not set)");
  console.log("  Company:", info.company ?? "(not set)");

  // -----------------------------------------------------------------------
  // Step 4: Refresh the token
  // -----------------------------------------------------------------------
  console.log("\n[4] Refreshing token...");

  if (!tokens.refresh_token) {
    console.log("  No refresh token available, skipping refresh.");
  } else {
    // In a real app you would check isExpiringSoon() before each API call:
    //   if (isExpiringSoon(tokens.expires_in, loginTime)) { ... }
    // For this example we refresh immediately to demonstrate the flow.

    const refreshed = await auth.refresh(tokens.refresh_token);
    tokens = refreshed;

    console.log("  New access token received (expires in %d seconds)", tokens.expires_in);

    // Verify the new token to confirm it is valid
    const refreshedUser = await auth.verify(tokens.access_token);
    console.log("  Verified refreshed token — user:", refreshedUser.sub);
  }

  // -----------------------------------------------------------------------
  // Step 5: Logout
  // -----------------------------------------------------------------------
  console.log("\n[5] Logging out...");

  await auth.logout(tokens.id_token);

  console.log("  Logged out successfully.");

  // After logout, the token should no longer be valid on the server.
  // Local verification may still pass (JWT is self-contained), but any
  // server-side session or refresh token is invalidated.
}

// --- Entry point ----------------------------------------------------------

main().catch((err) => {
  if (err instanceof SimpleAuthError) {
    console.error("SimpleAuth error:", err.message);
    console.error("  Status:", err.status);
    console.error("  Code:", err.code ?? "(none)");
    console.error("  Description:", err.description ?? "(none)");
  } else {
    console.error("Unexpected error:", err);
  }
  process.exit(1);
});
