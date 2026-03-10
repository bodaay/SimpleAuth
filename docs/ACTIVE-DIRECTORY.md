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
    "provider_id": "corp-ad",
    "name": "Corporate Active Directory",
    "url": "ldaps://dc01.corp.local:636",
    "base_dn": "DC=corp,DC=local",
    "bind_dn": "CN=svc-sauth-prod,OU=Service Accounts,DC=corp,DC=local",
    "bind_password": "YourStrongPassword",
    "user_filter": "(sAMAccountName={0})",
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

Navigate to your SimpleAuth instance in a browser and use the built-in admin UI to configure LDAP providers visually.

### Auto-Discovery

If your DNS is properly configured with SRV records, SimpleAuth can auto-discover your domain controllers:

```bash
curl -k -X POST https://auth.corp.local:8080/api/admin/ldap/auto-discover \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

---

## Step 3: Test the Connection

```bash
curl -k -X POST https://auth.corp.local:8080/api/admin/ldap/corp-ad/test \
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
| `user_filter` | `(sAMAccountName={0})` | LDAP search filter. `{0}` is replaced with the username. |

Common filters:
- **By login name:** `(sAMAccountName={0})` -- most common for AD
- **By email:** `(mail={0})` -- useful for email-based login
- **By UPN:** `(userPrincipalName={0})` -- for `user@domain` format
- **Combined:** `(|(sAMAccountName={0})(mail={0}))` -- accept either

### Attribute Mapping

These map AD attributes to SimpleAuth user fields:

| Field | Default AD Attribute | Description |
|---|---|---|
| `display_name_attr` | `displayName` | User's full display name |
| `email_attr` | `mail` | User's email address |
| `department_attr` | `department` | Department name |
| `company_attr` | `company` | Company name |
| `job_title_attr` | `title` | Job title |
| `groups_attr` | `memberOf` | Group membership (multi-valued DN list) |

### Priority

| Field | Default | Description |
|---|---|---|
| `priority` | `0` | Lower numbers are tried first. Use when you have multiple LDAP providers. |

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
  https://auth.corp.local:8080/api/admin/ldap/corp-ad/setup-kerberos \
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
  https://auth.corp.local:8080/api/admin/ldap/corp-ad/cleanup-kerberos \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

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

### User Identity

SimpleAuth identifies AD users by their `objectGUID` (a unique, immutable identifier). This means:
- Renaming a user in AD doesn't break their SimpleAuth identity
- Moving a user to a different OU doesn't break anything
- The identity mapping is `ldap:{provider_id}:{objectGUID}`

### Groups

The `memberOf` attribute returns full DNs like:

```
CN=Engineering,OU=Groups,DC=corp,DC=local
```

These are included in JWT tokens as-is. Your app can parse the CN to get the group name, or compare full DNs for precision.

---

## Multi-Domain / Multi-Forest Support

SimpleAuth supports multiple LDAP providers, making multi-domain setups straightforward:

```bash
# Domain 1: corp.local
curl -k -X POST https://auth.corp.local:8080/api/admin/ldap \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_id": "corp-local",
    "name": "corp.local",
    "url": "ldaps://dc01.corp.local:636",
    "base_dn": "DC=corp,DC=local",
    "bind_dn": "CN=svc-sauth-prod,OU=Service Accounts,DC=corp,DC=local",
    "bind_password": "Password1",
    "user_filter": "(sAMAccountName={0})",
    "priority": 10
  }'

# Domain 2: subsidiary.com
curl -k -X POST https://auth.corp.local:8080/api/admin/ldap \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_id": "subsidiary",
    "name": "subsidiary.com",
    "url": "ldaps://dc01.subsidiary.com:636",
    "base_dn": "DC=subsidiary,DC=com",
    "bind_dn": "CN=svc-sauth-prod,OU=Service Accounts,DC=subsidiary,DC=com",
    "bind_password": "Password2",
    "user_filter": "(sAMAccountName={0})",
    "priority": 20
  }'
```

On login, SimpleAuth tries `corp.local` first (priority 10), then `subsidiary.com` (priority 20).

### User Merging Across Domains

If the same person has accounts in multiple domains, you can merge them:

```bash
curl -k -X POST https://auth.corp.local:8080/api/admin/users/merge \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source_guids": ["guid-from-corp", "guid-from-subsidiary"],
    "display_name": "John Smith",
    "email": "jsmith@corp.local"
  }'
```

After merging, the user gets a single GUID. Both LDAP identities map to the same user. Roles and permissions from both accounts are combined.

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

- Check the `user_filter` -- it must contain `{0}` which gets replaced with the username
- Verify the `base_dn` contains the user's OU
- Try a broader search: `"user_filter": "(|(sAMAccountName={0})(mail={0}))"`

### "TLS certificate verification failed"

- Your DC's certificate might be signed by an internal CA
- Add the CA certificate to the system trust store on the SimpleAuth server
- Or set `"skip_tls_verify": true` (not recommended for production)

### Groups not showing up in tokens

- Verify the `groups_attr` is set to `memberOf`
- Check that the user actually has group memberships in AD
- Some groups (like "Domain Users") don't appear in `memberOf` because they're the primary group

### Kerberos not working

- Verify the SPN exists: `setspn -L svc-sauth-prod`
- Check that the hostname in the URL matches the SPN: `HTTP/auth.corp.local`
- Verify DNS resolves the hostname from the client machine
- Check `klist` on a client machine to see if a ticket was obtained
- Try the test page: `https://auth.corp.local:8080/test-negotiate`
- Check SimpleAuth logs for "negotiate_failed" audit entries

### Multiple people with the same username across domains

This works fine. SimpleAuth tracks users by their `objectGUID`, not their username. The `priority` setting determines which domain is tried first. Once a user authenticates from a specific domain, their identity mapping is cached, so future logins go directly to the right domain.
