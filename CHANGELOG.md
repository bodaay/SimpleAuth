# Changelog

All notable changes to SimpleAuth. Newest first.

Links use full `https://github.com/...` URLs because each section is also published as GitHub Release notes, where relative links do not work.

Each version's section is published as the top of its GitHub Release (the
release workflow extracts the `## vX.Y.Z` section matching the pushed tag). The
auto-generated list of merged PRs follows it.

## Unreleased

### ⭐ Highlight: Active Directory with an internal CA works with certificate verification on

On v2.3.0 a `ldap://` directory could not be used with certificate verification: every StartTLS upgrade failed with `tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config` ([#75](https://github.com/bodaay/SimpleAuth/pull/75) fixes that). Once it is fixed, an AD whose domain controllers have certificates from the organisation's own CA fails with `certificate signed by unknown authority`, and the only way out was `skip_tls_verify` (which the console did not even offer).

**New: `ca_cert` on the LDAP config.** Paste the AD root CA (PEM) in **Admin UI → LDAP Settings → TLS & certificates → AD root CA certificate (PEM)**, or send it as `ca_cert`. SimpleAuth trusts it in addition to the system CAs, for both StartTLS and `ldaps://`, and keeps verifying the certificate. Full documentation: [docs/ACTIVE-DIRECTORY.md → TLS and Certificates](https://github.com/bodaay/SimpleAuth/blob/master/docs/ACTIVE-DIRECTORY.md#tls-and-certificates).

### ⚠️ Upgrade notes (behavior changes)

1. **The URL scheme alone decides the encryption.** `ldaps://` is TLS from the first byte; `ldap://` is upgraded with StartTLS before any bind (unless `allow_insecure`). `use_tls` is no longer read; it is set from the scheme on every save.
   - A config with `ldap://` and `"use_tls": true` used to skip StartTLS and **bind in cleartext**. It now uses StartTLS. If that directory has no certificate, the connection now fails with the StartTLS error; fix the certificate, or set `allow_insecure` knowingly.
   - A config with `ldaps://` saved from the console (`use_tls` false) used go-ldap's default TLS settings and ignored `skip_tls_verify`. It now uses the configured settings.
2. **`PUT /api/admin/ldap` refuses an invalid `ca_cert`** with `400` (no certificate, a private key, a damaged or truncated block).
3. **Console saves now send `skip_tls_verify`, `allow_insecure` and `ca_cert`.** Before, saving from the console reset `skip_tls_verify` and `allow_insecure` set through the API to `false`.

### Security fixes

- `ldap://` with `"use_tls": true` sent the service-account and user passwords in cleartext (see above).

### Admin console

- **TLS & certificates** section in Connect, Manual Setup, Import Config and the Connection card's Edit: **AD root CA certificate (PEM)**, **Skip certificate verification** (with a warning), **Allow cleartext (no StartTLS)** (with a stronger warning).
- The Connection card shows **Encryption** (StartTLS / TLS / none) and **Cert check**.
- A failed **Connect** stays on screen, and a certificate error opens the TLS section.

### Added

- LDAP config field `ca_cert` (PEM, one or more CA certificates) in `GET`/`PUT /api/admin/ldap`, `POST /api/admin/ldap/auto-discover` and `POST /api/admin/ldap/import`.
- `auto-discover` and `import` accept `skip_tls_verify`, `allow_insecure` and `ca_cert`. Fields the request leaves out keep their stored values instead of being reset; the setup script's JSON never contains them.
- TLS errors caused by an untrusted CA end with `set ca_cert to the AD root CA certificate (PEM)`.
- Audit events `ldap_config_saved` / `ldap_config_imported` record `ca_cert_set`, `skip_tls_verify` and `allow_insecure` (never the certificate).

## v2.3.0

### ⭐ Highlight: users disabled in Active Directory now lose access

**Before this release, a user disabled in AD could keep signing in.** Disabling an account in AD only stops domain controllers from issuing *new* Kerberos tickets. A ticket the browser already holds stays valid for up to 10 hours, and SimpleAuth never checked the account state in AD. On top of that, SimpleAuth refresh tokens (30 days) and the SSO session cookie (up to 30 days) kept working. ([SECURITY-AUDIT.md](https://github.com/bodaay/SimpleAuth/blob/master/SECURITY-AUDIT.md) **H17**, severity HIGH.)

**From v2.3.0, SimpleAuth checks the account in AD** (`userAccountControl` disabled bit, `accountExpires`, and whether the user still exists) at every:

- password login (API, hosted login page, OIDC password grant)
- Kerberos SSO login (`/login/sso`, `/api/auth/negotiate`), even when the Kerberos ticket is still valid
- token refresh (`/api/auth/refresh` and OIDC `refresh_token`)
- reuse of the shared SSO session cookie

A user disabled, expired, or deleted in AD is therefore out within one access-token lifetime (15 minutes by default).

**New setting: AD outage behavior.** If AD cannot be reached, SimpleAuth cannot tell whether a user was disabled. Choose what happens in **Admin UI → Settings → AD Outage Behavior** (API field `directory_outage_policy`):

| Option | Value | During an AD outage |
|---|---|---|
| **Stay logged in during ticket lifetime** (default, recommended) | `grace` | Users confirmed active in AD within the last 10 hours (configurable 1–168 via `directory_outage_grace_hours`) keep access; others are blocked. |
| **Block users** | `block` | All AD users are blocked until AD is back. Most secure. |
| **Keep allowing everyone** | `allow` | Everyone is allowed. Least secure, not recommended. |

Full documentation: [docs/ACTIVE-DIRECTORY.md → Disabled, Expired, and Deleted AD Accounts](https://github.com/bodaay/SimpleAuth/blob/master/docs/ACTIVE-DIRECTORY.md#disabled-expired-and-deleted-ad-accounts).

### ⚠️ Upgrade notes (behavior changes)

Read before upgrading. No configuration is required; the defaults are safe.

1. **AD users that are disabled, expired, or deleted in AD are denied**, including users who are already signed in, at their next token refresh. This is the intended fix.
2. **AD users moved to an OU outside the configured Base DN are treated as deleted** and denied. Check that `base_dn` covers all your user OUs before upgrading.
3. **AD outage default is `grace` (10 hours).** Previously an AD outage had no effect on already-signed-in users. Now a user not confirmed active in AD within the last 10 hours is denied until AD is reachable again. Right after upgrading, nobody has been confirmed yet: the first successful login, refresh, or SSO after the upgrade records it. If AD goes down before that, those users are denied. Set the policy to `allow` temporarily if you expect AD maintenance right after upgrading.
4. **One extra LDAP search per token refresh and per SSO-cookie reuse** for AD users (about 4 per hour per active session with the default 15-minute access token).
5. **`/api/auth/refresh` now stamps the app's *current* audience** (`aud`) instead of the audience of the original login. If you changed an app's audience, existing sessions switch to the new value at their next refresh. ([SECURITY-AUDIT.md](https://github.com/bodaay/SimpleAuth/blob/master/SECURITY-AUDIT.md) **M40**)
6. **Building from source now requires Go 1.26** (`go.mod` is `go 1.26.8`; the Docker image builds with `golang:1.26-alpine`). Prebuilt binaries and the Docker image are unaffected.
7. **Refresh responses can now be `403 {"error":"account disabled"}`** (`/api/auth/refresh`) or `401 {"error":"invalid_grant","error_description":"account disabled"}` (OIDC) for AD users. Apps must treat these like an expired session and send the user back to login.

### Security fixes

- **H17 (HIGH)**: users disabled, expired, or deleted in AD kept access through Kerberos SSO, refresh tokens, and the SSO cookie. See the highlight above.
- **M40 (MEDIUM)**: `/api/auth/refresh` copied the original token's audience forward forever, so an admin correcting an app's audience never reached existing sessions.
- **L23 (LOW)**: after the SSO cookie moved from path `/` to the base path, an old `/` cookie survived logout and could silently sign the user back in. Logout now clears both.
- **L24 (LOW)**: creating an app-local user (`POST /api/app/users`) ignored store errors and could crash mid-way, leaving a user with no username mapping or roles. It now fails cleanly and rolls back.

### Admin console

- **Reworked admin UI.** Pages now have their own URLs (`#/users`, `#/apps`, …), so refresh, deep links, and Back/Forward work. The sidebar is grouped into Access / Directory / System.
- **Structured per-app authorization editor**, replacing the raw JSON textarea. Assignments can only use defined roles.
- **Accessible dialogs**: Escape closes them, focus is trapped and restored. Rotating a secret, deleting an app, and enabling require-assignment now ask for confirmation with a warning.
- **Users page**: Edit Profile and Unlock actions, and a "Locked" badge.
- If the admin session expires, the console now returns to the sign-in screen instead of showing a stream of errors.
- New **AD Outage Behavior** card on the Settings page (see the highlight above).

### Changed

- **Go 1.26.8** (was 1.25.12). The Go 1.25.12 standard library had 6 vulnerabilities the code reaches (net/url, html/template, crypto/tls, net/http, encoding/xml, encoding/asn1), plus GO-2026-5026 in `golang.org/x/net`. All are fixed.
- Dependencies updated: `golang.org/x/crypto` 0.57.0, `golang.org/x/net` 0.58.0, `github.com/go-ldap/ldap/v3` 3.4.14, `go.etcd.io/bbolt` 1.5.0, `github.com/jackc/pgx/v5` 5.11.0.
- SDK dev dependencies updated: TypeScript 7, `@types/node` 26, and newer Python minimums for `cryptography`, `fastapi`, `starlette`, `django`, and `setuptools`.
- GitHub Actions updated: `actions/checkout` v7, `actions/setup-go` v7, `github/codeql-action` v4.38.2, `softprops/action-gh-release` v3.0.3.
- **Security scan fixed.** The `govulncheck` CI job had been failing to install since `govulncheck` v1.8.0 started requiring a newer Go version, so no scan was actually running. It is now pinned to a working version.
- **Dependabot removed.** Dependencies are now reviewed by a maintainer once a month, following [docs/MAINTENANCE.md](https://github.com/bodaay/SimpleAuth/blob/master/docs/MAINTENANCE.md). `govulncheck` still runs on every push and pull request, and weekly.

### Added

- Runtime settings `directory_outage_policy` (`grace` | `block` | `allow`) and `directory_outage_grace_hours` (1–168, default 10), in `GET/PUT /api/admin/settings` and the admin UI.
- First-start seeds `AUTH_DIRECTORY_OUTAGE_POLICY` / `AUTH_DIRECTORY_OUTAGE_GRACE` (YAML: `directory_outage_policy` / `directory_outage_grace`).
- Audit event `directory_outage_policy_changed` (old and new values).
- Server log lines `[auth] Directory account disabled`, `[auth] Directory account not found`, and `[auth] Directory status check failed … — allowing/denying (policy=…)`.
