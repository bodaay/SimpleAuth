# Active Directory Integration Guide

SimpleAuth was built for Active Directory. This guide covers everything from creating a service account to setting up transparent Kerberos login.

---

## Prerequisites

Before you start, you need:

- An Active Directory domain (Windows Server 2012+ or later)
- A service account in AD for SimpleAuth (or admin rights to create one)
- Network access from the SimpleAuth server to your domain controller(s) on:
  - LDAP: port 389 (or LDAPS: port 636)
  - Kerberos: port 88 (only if using SPNEGO)
- DNS resolution of your domain controller hostnames

---

## Step 1: Create a Service Account

Create a dedicated service account in AD for SimpleAuth. This account is used to search for users and read their attributes. It does NOT need admin privileges.

### Option A: Using Active Directory Users and Computers

1. Open Active Directory Users and Computers
2. Create a new user in an OU for service accounts (e.g., `OU=Service Accounts`)
3. Name: `svc-sauth-{deployment_name}` (e.g., `svc-sauth-sauth`; max 6 chars, letters only)
4. Set a strong password
5. Check "Password never expires"
6. Uncheck "User must change password at next logon"

### Option B: Using PowerShell

```powershell
New-ADUser -Name "svc-sauth-prod" `
  -SamAccountName "svc-sauth-prod" `
  -UserPrincipalName "svc-sauth-prod@corp.local" `
  -Path "OU=Service Accounts,DC=corp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "YourStrongPassword" -AsPlainText -Force) `
  -PasswordNeverExpires $true `
  -CannotChangePassword $true `
  -Enabled $true
```

> **Tip:** Use the server-side setup script instead — it handles all of this automatically including SPN registration and config export. Download it from the admin UI ("AD Script" button) or `GET /api/admin/setup-script`.

### Required Permissions

The service account needs **read access** to user objects. By default, all authenticated users in AD can read the attributes SimpleAuth needs. No special delegation is required.

If your AD has restricted read permissions, the service account needs:
- Read access to `sAMAccountName`, `displayName`, `mail`, `department`, `company`, `title`, `memberOf`, `objectGUID`

---

## Step 2: Configure the LDAP Provider

### Using the API

```bash
curl -k -X POST https://auth.corp.local:8080/api/admin/ldap \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Corporate Active Directory",
    "url": "ldaps://dc01.corp.local:636",
    "base_dn": "DC=corp,DC=local",
    "bind_dn": "CN=svc-sauth-prod,OU=Service Accounts,DC=corp,DC=local",
    "bind_password": "YourStrongPassword",
    "username_attr": "sAMAccountName",
    "use_tls": true,
    "skip_tls_verify": false,
    "display_name_attr": "displayName",
    "email_attr": "mail",
    "department_attr": "department",
    "company_attr": "company",
    "job_title_attr": "title",
    "groups_attr": "memberOf",
    "priority": 10
  }'
```

### Using the Admin UI

Navigate to `/admin` on your SimpleAuth instance in a browser and use the built-in admin UI to configure LDAP visually.

### Auto-Discovery

If your DNS is properly configured with SRV records, SimpleAuth can auto-discover your domain controllers:

```bash
curl -k -X POST https://auth.corp.local:8080/api/admin/ldap/auto-discover \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

---

## Step 3: Test the Connection

```bash
curl -k -X POST https://auth.corp.local:8080/api/admin/ldap/test \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

If successful, try logging in:

```bash
curl -k -X POST https://auth.corp.local:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jsmith",
    "password": "UserPassword123"
  }'
```

---

## LDAP Configuration Reference

### Connection Settings

| Field | Example | Description |
|---|---|---|
| `url` | `ldaps://dc01.corp.local:636` | LDAP server URL. Use `ldaps://` for LDAPS (port 636) or `ldap://` for StartTLS (port 389). |
| `base_dn` | `DC=corp,DC=local` | Base DN for user searches. Use your domain's DN. |
| `bind_dn` | `CN=svc-sauth-prod,OU=Service Accounts,DC=corp,DC=local` | Full DN of the service account. |
| `bind_password` | (string) | Service account password. |
| `use_tls` | `true` | Enable TLS. Should always be `true` in production. |
| `skip_tls_verify` | `false` | Skip TLS certificate verification. Only for testing. |

### User Search

| Field | Example | Description |
|---|---|---|
| `username_attr` | `sAMAccountName` | The LDAP attribute used to match the login username. |

Common values:
- **`sAMAccountName`** -- most common for AD (matches login name)
- **`mail`** -- useful for email-based login
- **`userPrincipalName`** -- for `user@domain` format

### Attribute Mapping

These map AD attributes to SimpleAuth user fields:

| Field | Default AD Attribute | Description |
|---|---|---|
| `display_name_attr` | `displayName` | User's full display name |
| `email_attr` | `mail` | User's email address |
| `department_attr` | `department` | Department name |
| `company_attr` | `company` | Company name |
| `job_title_attr` | `title` | Job title |
| `given_name_attr` | `givenName` | First name, emitted as the OIDC `given_name` claim |
| `family_name_attr` | `sn` | Last name, emitted as the OIDC `family_name` claim |
| `groups_attr` | `memberOf` | Group membership (multi-valued DN list) |

Left empty, `given_name_attr` and `family_name_attr` fall back to `givenName` and `sn`, so existing
configurations start emitting `given_name` / `family_name` without changes. OIDC clients such as
OpenProject use these claims for the user's first and last name.

### Priority

| Field | Default | Description |
|---|---|---|
| `priority` | `0` | Provider priority (reserved for future use). |

---

## Kerberos/SPNEGO Setup

Kerberos enables transparent single sign-on for domain-joined machines. Users access your app in their browser and are authenticated automatically -- no password prompt.

### How It Works

1. Browser requests a protected resource
2. Your app redirects to SimpleAuth's negotiate endpoint
3. SimpleAuth responds with `401 + WWW-Authenticate: Negotiate`
4. Browser obtains a Kerberos ticket from the KDC for SimpleAuth's SPN
5. Browser resends the request with the ticket
6. SimpleAuth validates the ticket using its keytab
7. SimpleAuth issues JWTs and redirects back to your app

### Setting Up Kerberos

SimpleAuth can set up Kerberos automatically using your AD admin credentials:

```bash
curl -k -X POST \
  https://auth.corp.local:8080/api/admin/kerberos/setup \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "admin_username": "admin@CORP.LOCAL",
    "admin_password": "AdminPassword"
  }'
```

This command:
1. Creates a Service Principal Name (SPN) `HTTP/auth.corp.local@CORP.LOCAL` in AD
2. Generates a keytab file in the data directory
3. Configures SimpleAuth to accept SPNEGO tokens

**Important:** The `hostname` in your SimpleAuth config must match the hostname users use in their browser. The SPN is `HTTP/{hostname}@{REALM}`.

### Manual Kerberos Setup

If you prefer to set things up manually:

**1. Create the SPN in AD:**

```powershell
# On a domain controller or machine with RSAT tools
setspn -S HTTP/auth.corp.local svc-sauth-prod
```

**2. Generate a keytab:**

```bash
# On Linux
ktutil
addent -password -p HTTP/auth.corp.local@CORP.LOCAL -k 0 -e aes256-cts-hmac-sha1-96
# (enter service account password)
wkt /etc/simpleauth/krb5.keytab
quit
```

**3. Configure SimpleAuth:**

```yaml
# In simpleauth.yaml
krb5_keytab: "/etc/simpleauth/krb5.keytab"
krb5_realm: "CORP.LOCAL"
```

Or via environment variables:

```bash
AUTH_KRB5_KEYTAB=/etc/simpleauth/krb5.keytab
AUTH_KRB5_REALM=CORP.LOCAL
```

### Check Kerberos Status

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.corp.local:8080/api/admin/kerberos/status
```

### Test Kerberos Authentication

Open `https://auth.corp.local:8080/test-negotiate` in a browser on a domain-joined machine. If Kerberos is working, you'll see your identity without entering a password.

### Browser Configuration

Most browsers support SPNEGO out of the box for intranet sites. Some may need configuration:

**Chrome/Edge:** Add the SimpleAuth hostname to the `AuthServerAllowlist` policy or navigate to `chrome://settings/` and ensure the host is in the Intranet zone.

**Firefox:** Navigate to `about:config` and add your SimpleAuth hostname to `network.negotiate-auth.trusted-uris`:

```
network.negotiate-auth.trusted-uris = auth.corp.local
```

### Cleaning Up Kerberos

To remove Kerberos configuration:

```bash
curl -k -X POST \
  https://auth.corp.local:8080/api/admin/kerberos/cleanup \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

---

## Disabled, Expired, and Deleted AD Accounts

> **New in v2.3.0.** Before v2.3.0, SimpleAuth never read the account state from AD. A user disabled in AD could keep signing in with Kerberos SSO for up to 10 hours, and keep using refresh tokens and the SSO session cookie for up to 30 days. See [SECURITY-AUDIT.md](../SECURITY-AUDIT.md) finding **H17**.

### What SimpleAuth checks

SimpleAuth asks AD whether the user's account is still active at **every** one of these moments:

| Moment | Endpoint(s) |
|---|---|
| Password login | `POST /api/auth/login`, `POST /login` (hosted login page), OIDC `grant_type=password` |
| Kerberos SSO login | `GET /login/sso`, `GET /api/auth/negotiate` |
| Token refresh | `POST /api/auth/refresh`, OIDC `POST /realms/{realm}/protocol/openid-connect/token` with `grant_type=refresh_token` |
| Shared SSO session cookie reuse | Any visit to the login page or OIDC authorize endpoint while `enable_session_sso` is on |

The check is one LDAP search as the configured service account, by the user's stored username (`username_attr`, default `sAMAccountName`), reading these attributes:

| AD attribute | Denied when | Set in AD by |
|---|---|---|
| `userAccountControl` | Bit `0x2` (`ACCOUNTDISABLE`) is set, e.g. value `514` or `66050` | Right-click user → **Disable Account**, or `Disable-ADAccount` |
| `accountExpires` | Set (not `0` and not `9223372036854775807`) and the date is in the past | User → Properties → Account → **Account expires**, or `Set-ADAccountExpiration` |
| *(the user entry itself)* | The search finds no entry: the user was deleted, or moved outside the configured `base_dn` | Deleting the user, or moving them to an OU outside `base_dn` |

**Why this is needed.** Disabling a user in AD only stops domain controllers from issuing **new** Kerberos tickets. A ticket the browser already holds stays valid until it expires (AD default: **10 hours**, domain policy "Maximum lifetime for service ticket"). On top of that, SimpleAuth's own refresh tokens (default 30 days) and SSO session cookie (default 8 hours idle / 30 days max) outlive any Kerberos ticket. Checking AD at each of the moments above closes all of these.

**What the user and the app see when access is denied:**

| Flow | Result |
|---|---|
| `POST /api/auth/login`, OIDC password grant | HTTP `401` `{"error": "invalid credentials"}`. The response is deliberately the same as a wrong password (no account-state enumeration). The audit log entry `login_failed` has `"reason": "account disabled"`. |
| Hosted login page `POST /login` | Login page shows "Invalid credentials". |
| `GET /login/sso` | Redirect back to the login page with the error "Account disabled". |
| `GET /api/auth/negotiate` | HTTP `403` `{"error": "account disabled"}` |
| `POST /api/auth/refresh` | HTTP `403` `{"error": "account disabled"}`. Your app must send the user back to login. |
| OIDC refresh | HTTP `401` `{"error": "invalid_grant", "error_description": "account disabled"}` |
| SSO session cookie | The session is deleted and the user sees the normal login page. |

**Who is checked.** Only users linked to the directory: users with a stored `sAMAccountName`, or with an `ldap` / `kerberos` identity mapping. Local users (created in SimpleAuth) and app-local users are **never** checked and are never affected by AD outages.

**Non-AD directories** (for example OpenLDAP) do not have `userAccountControl` or `accountExpires`. For them only the "user entry no longer found" rule applies.

**Cost.** One extra LDAP search per token refresh and per SSO-cookie reuse for directory users. With the default 15-minute access token, that is about 4 searches per hour per active user session.

### What happens when AD cannot be reached (outage behavior)

If LDAP is configured but the check fails because AD cannot be reached (network error, domain controller down, TLS failure, service-account bind failure), SimpleAuth cannot tell whether the user was disabled. The admin chooses what happens:

| Setting value | Admin UI label | Behavior during the AD outage |
|---|---|---|
| `grace` **(default)** | Stay logged in during ticket lifetime (default, recommended) | A user whose AD account was **confirmed active within the last `directory_outage_grace_hours` hours** (default `10`, the AD default Kerberos ticket lifetime) keeps access. A user not confirmed within that window is denied until AD is reachable again. |
| `block` | Block users (most secure) | **Every** directory user is denied until AD is reachable again, including users who are already signed in (at their next token refresh or SSO-cookie reuse). |
| `allow` | Keep allowing everyone (least secure, not recommended) | Every directory user is allowed. A user disabled in AD can keep signing in and refreshing tokens for as long as AD stays unreachable. |

**"Confirmed active"** means: the last time an AD check for that user succeeded, at any of the moments listed in [What SimpleAuth checks](#what-simpleauth-checks). SimpleAuth stores this time per user in its database (config key `dircheck:<user_guid>`, written at most once every 5 minutes per user), so the grace window survives a SimpleAuth restart. The value is deleted when the user is deleted.

**Worst case per setting** (a user disabled in AD at the moment AD becomes unreachable):

| Setting | How long that user can still get in |
|---|---|
| `grace` with default 10h | At most 10 hours after their last successful AD check |
| `block` | Not at all |
| `allow` | As long as the outage lasts (a refresh during the outage issues a new refresh token, which is re-checked at each later refresh) |

If LDAP is **not configured at all**, no check is done and this setting has no effect.

### How to change the outage behavior

**Admin UI:**

1. Open the admin UI: `https://<hostname>/<base_path>/` (for example `https://auth.corp.local/sauth/`).
2. Go to **Settings** → card **AD Outage Behavior**.
3. In **When AD is unreachable**, choose one of the three options.
4. If you chose *Stay logged in during ticket lifetime*, set **Grace period (hours)**: a whole number from `1` to `168`. Default `10`.
5. Click **Save Settings** at the top of the page. The change takes effect immediately; no restart.

**Admin API:** the settings endpoint replaces the full document, so read it first, change the two fields, and send it all back.

```bash
# 1. Read current settings
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.corp.local/sauth/api/admin/settings > settings.json

# 2. Set the policy (requires jq). Allowed values: "grace", "block", "allow".
jq '.directory_outage_policy = "block" | .directory_outage_grace_hours = 10' \
  settings.json > new-settings.json

# 3. Write the full document back
curl -k -X PUT https://auth.corp.local/sauth/api/admin/settings \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  --data @new-settings.json
```

| Field | Type | Allowed values | If omitted or out of range |
|---|---|---|---|
| `directory_outage_policy` | string | `"grace"`, `"block"`, `"allow"` (case-insensitive) | Omitted or `""` → `"grace"`. Any other value → HTTP `400` `{"error": "directory_outage_policy must be one of: grace, block, allow"}` |
| `directory_outage_grace_hours` | integer | `1` to `168` | Less than `1` → `10`. More than `168` → `168`. Only used when the policy is `"grace"`. |

**First start only (environment / config file):** these seed the runtime setting the very first time SimpleAuth starts with an empty database. After that, the admin UI / API value wins and these are ignored.

| Env var | YAML key | Example |
|---|---|---|
| `AUTH_DIRECTORY_OUTAGE_POLICY` | `directory_outage_policy` | `grace`, `block`, or `allow` |
| `AUTH_DIRECTORY_OUTAGE_GRACE` | `directory_outage_grace` | `10h` (Go duration, whole hours) |

**Auditing and logs:**

- Every change to the policy or grace period writes an audit log entry `directory_outage_policy_changed` with `policy`, `grace_hours`, `old_policy`, and `old_grace_hours`.
- Every allow/deny decision made during an outage is written to the server log, starting with `[auth] Directory status check failed`, followed by the username, user GUID, the LDAP error, and the decision (for example `— denying (policy=block)` or `— allowing (policy=grace, last confirmed 42m0s ago)`).
- A user denied because AD says the account is disabled or missing is logged as `[auth] Directory account disabled` or `[auth] Directory account not found`.

---

## Attribute Mapping Details

### What SimpleAuth Reads from AD

When a user authenticates via LDAP, SimpleAuth reads these attributes and stores them in the user record:

| SimpleAuth Field | Default AD Attribute | Example Value |
|---|---|---|
| `display_name` | `displayName` | `John Smith` |
| `email` | `mail` | `jsmith@corp.local` |
| `department` | `department` | `Engineering` |
| `company` | `company` | `Acme Corporation` |
| `job_title` | `title` | `Senior Software Engineer` |
| `groups` | `memberOf` | `["CN=Engineering,OU=Groups,DC=corp,DC=local"]` |

Attributes are refreshed on every login, so changes in AD are reflected automatically.

SimpleAuth also reads `userAccountControl` and `accountExpires` on every lookup. These are **not** stored on the user record. They only decide whether the account is still allowed in. See [Disabled, Expired, and Deleted AD Accounts](#disabled-expired-and-deleted-ad-accounts).

### User Identity

SimpleAuth identifies AD users by their `objectGUID` (a unique, immutable identifier). This means:
- Renaming a user in AD doesn't break their SimpleAuth identity
- Moving a user to a different OU doesn't break anything
- The identity mapping is `ldap:{objectGUID}`

### Groups

The `memberOf` attribute returns full DNs like:

```
CN=Engineering,OU=Groups,DC=corp,DC=local
```

These are included in JWT tokens as-is. Your app can parse the CN to get the group name, or compare full DNs for precision.

---

## Troubleshooting

### "LDAP test failed: connection refused"

- Check that the domain controller is reachable: `telnet dc01.corp.local 636`
- Check firewall rules between SimpleAuth and the DC
- If using LDAPS (port 636), ensure the DC has a valid TLS certificate

### "LDAP test failed: invalid credentials"

- Verify the Bind DN is the full distinguished name, not just the username
- Try the DN in `ldapsearch`: `ldapsearch -H ldaps://dc01.corp.local -D "CN=svc-sauth-prod,OU=Service Accounts,DC=corp,DC=local" -w password -b "DC=corp,DC=local" "(sAMAccountName=testuser)"`
- Check if the service account is locked out or disabled

### "User not found" when logging in

- Check the `username_attr` -- it must match the attribute users log in with (e.g., `sAMAccountName`)
- Verify the `base_dn` contains the user's OU

### "TLS certificate verification failed"

- Your DC's certificate might be signed by an internal CA
- Add the CA certificate to the system trust store on the SimpleAuth server
- Or set `"skip_tls_verify": true` (not recommended for production)

### Groups not showing up in tokens

- Verify the `groups_attr` is set to `memberOf`
- Check that the user actually has group memberships in AD
- Some groups (like "Domain Users") don't appear in `memberOf` because they're the primary group

### A user disabled in AD can still sign in

- Check the SimpleAuth version: this is only enforced from **v2.3.0**.
- Check that LDAP is configured (Admin UI → LDAP Providers) and **Test Connection** succeeds. With no LDAP configured, SimpleAuth cannot check account state.
- Check the outage setting (Settings → AD Outage Behavior). If AD is unreachable and the setting is `allow`, or `grace` and the user was confirmed within the grace period, the user is let in by design. Look for `[auth] Directory status check failed` in the server log.
- AD replication: SimpleAuth asks whichever DC the LDAP URL points to. A disable made on another DC is only seen once it replicates.

### An active AD user gets "Account disabled" or is logged out

- The user may have been moved to an OU outside `base_dn`. SimpleAuth treats "not found in AD" as deleted. Check the server log for `[auth] Directory account not found`.
- Check `accountExpires` on the user in AD (Properties → Account → Account expires).
- If AD is unreachable and the setting is `block`, or `grace` and the user was not confirmed within the grace period, the user is denied until AD is back. Look for `[auth] Directory status check failed ... — denying`.

### Kerberos not working

- Verify the SPN exists: `setspn -L svc-sauth-prod`
- Check that the hostname in the URL matches the SPN: `HTTP/auth.corp.local`
- Verify DNS resolves the hostname from the client machine
- Check `klist` on a client machine to see if a ticket was obtained
- Try the test page: `https://auth.corp.local:8080/test-negotiate`
- Check SimpleAuth logs for "negotiate_failed" audit entries

