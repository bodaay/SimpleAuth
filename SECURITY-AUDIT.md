# SimpleAuth Security Audit Log

A living, append-only security audit trail. SimpleAuth is an authentication
server, so security is the top priority: bugs here are security bugs.

This file is audited repeatedly over time, by **different AI models and humans**.
Each pass appends a dated section; the **Status Summary** table is the single
source of truth for what is currently open vs. fixed.

## Conventions

- **Stable IDs.** Every finding gets a permanent ID: `C#` critical, `H#` high,
  `M#` medium, `L#` low, `I#` informational. **Never renumber or reuse an ID.**
  A new audit that rediscovers an existing issue references the existing ID.
- **Status.** `OPEN` → `FIXED` (with date + commit/branch) / `WONTFIX` (with
  rationale) / `REGRESSED` (reopened — link the regressing change).
- **Dates** are ISO `YYYY-MM-DD`. **Breaking changes are acceptable** when they
  close a real security hole — this project favors security over compatibility
  (operators can pin a previous commit). Each fix notes its blast radius anyway.
- **Append, don't rewrite.** Add a new "Audit Pass" section per run. Correct an
  earlier finding by adding a note, not by deleting it.

## How to run an audit (prompt for the next model)

> Review the whole repo as a security audit of an auth server. Read
> `SECURITY-AUDIT.md` first. For each existing OPEN finding, verify it is still
> present (or mark REGRESSED/FIXED). Then hunt for NEW issues across: auth flows
> (login, refresh rotation, Kerberos/SPNEGO, OIDC grants, impersonation),
> token handling (JWT alg/iss/aud/exp, JWKS, revocation), the store layer
> (atomicity, injection, migration), admin/authz, secret handling, and the SDKs.
> Append a new Audit Pass section with dated findings using stable IDs, and
> update the Status Summary table.

---

## Status Summary (current)

| ID | Title | Severity | Status | Fixed (date / commit) |
|----|-------|----------|--------|-----------------------|
| C1 | Kerberos AP-REQ decrypted but never verified → replay | CRITICAL | FIXED | 2026-05-30 (branch `security-hardening-2026-05-30`) |
| C2 | OIDC token endpoint: no client auth; `password`/`client_credentials` open | CRITICAL | FIXED | 2026-05-30 |
| C3 | OIDC token introspection unauthenticated | CRITICAL | FIXED | 2026-05-30 |
| H1 | Unthrottled brute-force surfaces; `/test-negotiate` LDAP-bind oracle | HIGH | FIXED | 2026-05-30 |
| H2 | Refresh-token rotation TOCTOU (non-atomic check-then-mark) | HIGH | FIXED | 2026-05-30 |
| H3 | Backend migration drops sessions + revocation blacklist | HIGH | FIXED | 2026-05-30 |
| H4 | LDAP bind password stored in plaintext at rest | HIGH | FIXED | 2026-05-30 |
| M1 | OIDC id_token `aud` empty on default install | MEDIUM | FIXED | 2026-05-30 |
| M2 | JWT `kid` regenerated every restart (JWKS kid churn) | MEDIUM | FIXED | 2026-05-30 |
| M3 | Refresh path ignores the `IsUserAccessRevoked` kill-switch | MEDIUM | FIXED | 2026-05-30 |
| M4 | Nil-deref: refresh token re-validated with ignored error | MEDIUM | FIXED | 2026-05-30 |
| M5 | `Retry-After` header emits garbage for values ≥ 10s | LOW | FIXED | 2026-05-30 |
| M6 | OIDC authorization-code flow has no PKCE | MEDIUM | FIXED | 2026-05-30 |
| M7 | Login user-enumeration via distinct disabled/locked responses | LOW | FIXED | 2026-05-30 |
| M8 | Security headers only on admin UI, not login/API responses | LOW | FIXED | 2026-05-30 |
| M9 | Reflected XSS via unescaped `error`/`state`/`nonce`/`scope` on login pages | MEDIUM | FIXED | 2026-05-30 |
| S1 | Python SDK was unimplemented (README/examples referenced missing code) | MEDIUM | FIXED | 2026-05-30 |
| S2 | JS/.NET SDK `iss` check hardcoded to base URL (always fails login tokens) | MEDIUM | FIXED | 2026-05-30 |
| S3 | Go SDK accepts refresh tokens as access tokens; skips `exp` when absent | MEDIUM | FIXED | 2026-05-30 |
| I1 | Single static admin key = entire authz model; actions audited as "admin" | INFO | WONTFIX | by design (documented) |
| I2 | No tests for `internal/auth` / `internal/config` | INFO | PARTIAL | 2026-05-30 (added auth + crypto + PKCE + consume tests) |
| H5 | v1 `/api/auth/refresh` drops per-app authz → privilege escalation | HIGH | FIXED | 2026-05-31 (branch `v2`) |
| H6 | `require_assignment` fails open when an app has no per-app authz | HIGH | FIXED | 2026-05-31 (branch `v2`) |
| H7 | App-management token accepted as a user access token (no `typ` gate) | HIGH | FIXED | 2026-05-31 (branch `v2`) |
| H8 | `DeleteApp` orphans app-local users → cross-tenant resurrection on app_id reuse | HIGH | FIXED | 2026-05-31 (branch `v2`) |
| M10 | OIDC refresh nil-derefs on disabled/deleted app; refresh skips app-disable | MEDIUM | FIXED | 2026-05-31 (branch `v2`) |
| M11 | OIDC `client_credentials`/`password` use the global secret but mint any app's `aud` | MEDIUM | FIXED | 2026-05-31 (branch `v2`) |
| M12 | Kerberos auto-provision binding hijack via app-set `email`/`display_name` | MEDIUM | FIXED | 2026-05-31 (branch `v2`) |
| M13 | Group list never cleared when a user leaves all directory groups (stale roles) | MEDIUM | FIXED | 2026-05-31 (branch `v2`) |
| M14 | Deleting an app-local user leaves a dangling mapping (username unprovisionable) | MEDIUM | FIXED | 2026-05-31 (branch `v2`) |
| M15 | App-local provisioning + reset bypass the password policy | MEDIUM | FIXED | 2026-05-31 (branch `v2`) |
| M16 | No rate-limit on `/api/app/token` + `/api/app/*` Basic auth (app_secret brute-force) | MEDIUM | FIXED | 2026-05-31 (branch `v2`) |
| L1 | `/login/sso` validates `redirect_uri` against the global, not per-app, allowlist | LOW | FIXED | 2026-05-31 (branch `v2`) |
| L2 | `handleImpersonate` mints an `aud`-less token carrying global roles | LOW | FIXED | 2026-05-31 (branch `v2`) |
| L3 | App-local user creation TOCTOU (store enforces no username uniqueness) | LOW | FIXED | 2026-05-31 (branch `v2`) |
| L4 | `rotate-secret` does not revoke outstanding app-management tokens | LOW | FIXED | 2026-05-31 (branch `v2`) |
| L5 | App-id enumeration via bcrypt timing oracle | LOW | FIXED | 2026-05-31 (branch `v2`) |
| I3 | Group-derived roles inherently stale on refresh (no directory re-read) | INFO | WONTFIX | by design — see Pass 2 remediation note |
| H3 | (regressed) PG→Bolt migration leaves stale sessions/revocation blacklist | HIGH | FIXED | 2026-06-01 (Pass 3) |
| M8 | (regressed) Frame protection only on admin UI → clickjacking of login/OIDC | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| L1 | (regressed) Hosted-login SSO redirect validated vs global, not per-app | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| H9 | Refresh/ID tokens accepted as access tokens at user-resource boundaries | HIGH | FIXED | 2026-06-01 (Pass 3) |
| H10 | LDAP bind + user passwords sent in cleartext over `ldap://` (no StartTLS) | HIGH | FIXED | 2026-06-01 (Pass 3) |
| H11 | `secret.key` silently overwritten on any read error → loses encrypted secrets | HIGH | FIXED | 2026-06-01 (Pass 3) |
| H12 | `RevokeUserTokens`/`RevokeTokenFamily` drop DELETE errors → fail-open revocation | HIGH | FIXED | 2026-06-01 (Pass 3) |
| H13 | OIDC login-error redirect drops `code_challenge` → PKCE silently disabled after any failed login attempt (M6 bypass) | HIGH | FIXED | 2026-08-08 (Pass 4) |
| S4 | Go SDK `Verify` accepts `typ=app-mgmt`/`typ=ID` tokens as access tokens | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| S5 | Python SDK `verify` accepts refresh tokens as access tokens | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| S6 | JS/.NET SDKs accept ID tokens as access; .NET threw non-SDK exception | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M17 | HTTP server has no read/header/write timeouts → Slowloris DoS | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M18 | OIDC end-session is an unauthenticated open redirect (`post_logout_redirect_uri`) | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M19 | OIDC authorize POST has no CSRF protection (login CSRF / session fixation) | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M20 | OIDC logout kills sessions on any token type, not just an ID token | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M21 | OIDC `client_credentials` app-secret brute-force unthrottled | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M22 | OIDC issuer / discovery / jwks_uri spoofable via the `Host` header | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M23 | Empty `redirect_uri` in auth-code flow delivered to the GLOBAL default URI | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M24 | `resolveApp` fails open for the default app on any store error (adjacent to H6) | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M25 | Admin settings mass-assignment silently weakens password policy / lockout / CORS | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M26 | Destructive admin actions (delete user, DB restore) write no audit entry | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M27 | Admin delete-user leaves access tokens valid + orphans SSO sessions | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M28 | `BoltStore.Restore` swaps the live `*bolt.DB` with no synchronization (data race) | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M29 | Refresh tokens never pruned — unbounded growth | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M30 | Postgres `QueryAuditLog` filters after SQL `LIMIT` → silently drops records | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M31 | Kerberos client realm never validated → cross-realm identity hijack | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M32 | Kerberos keytab includes RC4-HMAC → silent downgrade on AES salt mismatch | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M33 | Hosted-login empty-credential branch is an open redirect | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M34 | Restart loop leaks the pruner goroutine against the closed old store | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M35 | Auto-generated admin key printed to logs + regenerated every restart | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M36 | Container/CI hardening: EOL base image, host-exposed plaintext, root nginx, unpinned actions | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| M37 | LDAP group-CN parsing only strips uppercase `CN=` → broken role mapping | MEDIUM | FIXED | 2026-06-01 (Pass 3) |
| L6 | `ValidateToken` did not require `exp` (missing-`exp` token validated) | LOW | FIXED | 2026-06-01 (Pass 3) |
| L7 | PKCE accepted `plain`/empty downgrade though discovery advertises only S256 | LOW | FIXED | 2026-06-01 (Pass 3) |
| L8 | Impersonation issued a token for a disabled / access-revoked target | LOW | FIXED | 2026-06-01 (Pass 3) |
| L9 | CORS `*` reflected an arbitrary request `Origin` instead of literal `*` | LOW | FIXED | 2026-06-01 (Pass 3) |
| L10 | `data_dir` MkdirAll error ignored | LOW | FIXED | 2026-06-01 (Pass 3) |
| L11 | `MergeUsers` ignored errors on reassignment/updates → partial/corrupt merge | LOW | FIXED | 2026-06-01 (Pass 3) |
| L12 | Abandoned OIDC auth codes never cleaned — unbounded growth | LOW | FIXED | 2026-06-01 (Pass 3) |
| L13 | SSO session cookie scoped to `/` instead of `BasePath` | LOW | FIXED | 2026-06-01 (Pass 3) |
| L14 | JWKS SDKs performed unbounded upstream fetch per unknown `kid` (DoS amplification) | LOW | FIXED | 2026-06-01 (Pass 3) |
| L15 | Canonical Go example modeled insecure verification (`Audience`/issuer unset) | LOW | FIXED | 2026-06-01 (Pass 3) |
| L16 | Python JWKS accepted RSA keys of any modulus (no min key length) | LOW | FIXED | 2026-06-01 (Pass 3) |
| L17 | Express example wired admin-only route to a client with no admin key | LOW | FIXED | 2026-06-01 (Pass 3) |
| L18 | `.well-known` discovery checklist omitted `secret.key` backup + NTP | LOW | FIXED | 2026-06-01 (Pass 3) |
| L19 | `test-negotiate` test page not rate-limited (gated behind flag, default off) | LOW | OPEN | acknowledged — see Pass 3 deferred |
| L20 | `Retry-After` only emitted on `POST /login` 429, not other 429 responses | LOW | OPEN | acknowledged — see Pass 3 deferred |
| L21 | Several LDAP lookups hardcode `sAMAccountName`, ignoring `UsernameAttr` | LOW | OPEN | acknowledged — see Pass 3 deferred |
| L22 | `RateLimitMax`/`WindowS` settable via API but not applied to live limiter | LOW | OPEN | acknowledged — see Pass 3 deferred |

---

## Audit Pass 1 — 2026-05-30 — Claude Opus 4.8 (`claude-opus-4-8`)

Scope: full codebase (server `internal/`, `pkg/`, SDKs, examples, docs, deploy).
Method: full first-hand read of the auth, OIDC, store, config, and Kerberos code
paths, cross-checked by parallel sub-agent analysis. `go build`/`go vet` clean;
`internal/handler` and `internal/store` tests pass; `internal/auth` and
`internal/config` have no tests (see I2).

### C1 — Kerberos AP-REQ is decrypted but never verified (replayable) — CRITICAL
**Where:** `internal/handler/auth.go` — `handleNegotiate` (~:793), `handleNegotiateTest`
(~:930/:980), `extractKerberosUsername` (~:1208/:1224).
**Mechanism:** every SPNEGO path calls `apReq.Ticket.DecryptEncPart(kt, nil)` and
then trusts `DecryptedEncPart.CName`. There is **no `APReq.Verify`/authenticator
decryption, no replay cache, and no clock-skew check.** Decrypting the ticket only
proves it was issued for this SPN — not that the presenter holds the client session
key or that the request is fresh. A captured `Authorization: Negotiate …` header
replays indefinitely to mint a full token pair as the victim (token-minting paths:
`GET /api/auth/negotiate`, `GET /login/sso`). `patchKeytabKVNO` compounds it by
trusting the client's claimed kvno.
**Fix:** use gokrb5 `service.VerifyAPREQ` (decrypts + verifies authenticator,
enforces clock skew, consults the replay cache).
**Breaking:** **highest-risk fix.** Real verification enforces clock sync (NTP, ~5m
skew) and a correct keytab; setups that "worked" only because verification was
skipped may start rejecting logins. Validate against real AD in staging.

### C2 — OIDC token endpoint has no client auth; `password`/`client_credentials` open — CRITICAL
**Where:** `internal/handler/oidc.go` — `authenticateOIDCClient` (:96, `return nil`),
`handleOIDCTokenPassword` (:350), `handleOIDCTokenClientCredentials` (:399).
**Mechanism:** client authentication is a no-op, so an anonymous network caller can
(a) use the `password` grant as a credential-stuffing oracle and (b) mint signed
service tokens via `client_credentials` with an arbitrary `scope`.
**Fix:** require a configured client secret (constant-time) for confidential grants;
disable `password` and `client_credentials` unless a secret is configured. Keep
`authorization_code`/`refresh_token` as public flows (hardened by PKCE — see M6).
Update discovery to advertise only enabled grants and real auth methods.
**Breaking:** removes two grants by default. The documented browser/OIDC flows and
the direct `/api/auth/login` API don't use them; the service-to-service examples that
"used" `client_credentials` were already broken. Low real-world impact.

### C3 — OIDC token introspection is unauthenticated — CRITICAL
**Where:** `internal/handler/oidc.go` — `handleOIDCIntrospect` (:687 calls the no-op).
**Mechanism:** anyone can introspect any token and read `sub`/`email`/`name`/scope/
expiry — a PII + token-validity oracle (violates RFC 7662 "protected resource").
**Fix:** require confidential client auth (client secret) or the admin key.
**Breaking:** anonymous introspection callers must present a credential. Rare in a
single-app deploy (RPs verify locally via JWKS). Low.

### H1 — Unthrottled brute-force surfaces; `/test-negotiate` LDAP-bind oracle — HIGH
**Where:** `internal/handler/auth.go` — `handleNegotiateTestForm` (:1313, no rate
limit, full LDAP bind + renders user attributes on success), `handleNegotiate`
(:741), `handleSSOLogin` (:1013); lockout only accrues for users with a local
mapping (:175).
**Mechanism:** `POST /test-negotiate` is an unauthenticated, unthrottled AD password
oracle; the Kerberos endpoints have no per-IP limit; AD users not yet provisioned in
SimpleAuth have no account-level lockout.
**Fix:** add the per-IP limiter to the Kerberos/SSO endpoints; gate the diagnostic
`/test-negotiate` endpoints behind a config flag (default off).
**Breaking:** rate-limiting is invisible to legit users; disabling test endpoints in
prod could surprise anyone misusing them as a login page. Low.

### H2 — Refresh-token rotation TOCTOU — HIGH
**Where:** `internal/handler/auth.go` `handleRefresh` (:436 check / :453 mark);
`internal/handler/oidc.go` `handleOIDCTokenRefresh` (:457/:463); Postgres
`MarkRefreshTokenUsed` is itself non-atomic (Get-then-Save).
**Mechanism:** the `Used` check and the mark are separate store calls with no row
lock, so two concurrent refreshes with the same token both succeed — defeating
single-use rotation and the replay detector.
**Fix:** add an atomic `ConsumeRefreshToken` (Bolt single txn; Postgres
`SELECT … FOR UPDATE` then conditional update) that returns a reuse sentinel; treat
reuse as the family-revocation trigger.
**Breaking:** internal only. None.

### H3 — Backend migration drops sessions + revocation blacklist — HIGH
**Where:** `internal/store/migrate.go` (bucket/table lists omit `sessions`,
`revoked_tokens`, `revoked_users`; PG→Bolt reports success on count mismatch).
**Mechanism:** after a Bolt↔Postgres switch, **revoked access tokens become valid
again** and all SSO sessions drop.
**Fix:** migrate those buckets in both directions; fail (not warn) on mismatch.
**Breaking:** strictly positive (preserves more data). None.

### H4 — LDAP bind password stored in plaintext at rest — HIGH
**Where:** `internal/handler/secrets.go` (no-op shim), `internal/store/types.go`
`LDAPConfig.BindPassword`; exposed wholesale by `GET /api/admin/backup`.
**Mechanism:** the AD service-account password is stored in cleartext in the DB and
included verbatim in raw DB backups.
**Fix:** encrypt the bind password at rest with an AES-GCM data key kept in a
`0600` key file in the data dir (outside the DB, so backups don't carry the key).
Transparently migrate existing plaintext on next read/save.
**Breaking:** key file becomes required to decrypt the bind password; back it up with
(but stored separately from) the DB. Existing plaintext auto-migrates.

### M1 — OIDC id_token `aud` empty on default install — MEDIUM
**Where:** `internal/handler/oidc.go` `issueOIDCTokens` (:557 uses `cfg.ClientID`,
which has no default) vs `oidcClientID()` = `"simpleauth"` used everywhere else.
**Fix:** use `oidcClientID()` for the id_token audience. **Breaking:** positive.

### M2 — JWT `kid` regenerated every restart — MEDIUM
**Where:** `internal/auth/jwt.go` (:72 `uuid.New().String()[:8]`).
**Mechanism:** the key is stable on disk but the published `kid` changes each boot,
so strict clients that match by `kid` reject tokens issued before the last restart.
**Fix:** derive `kid` deterministically from the public key (SHA-256 thumbprint).
**Breaking:** clients refetch JWKS once. None (single key).

### M3 — Refresh path ignores the access-revocation kill-switch — MEDIUM
**Where:** `internal/handler/auth.go` `handleRefresh` (:421) / OIDC refresh — only
`Disabled` is rechecked; `IsUserAccessRevoked` is not.
**Fix:** consult `IsUserAccessRevoked` on refresh too.
**Breaking:** admin "revoke all sessions" now also stops refresh (intended). None.

### M4 — Nil-deref on re-validated refresh token — MEDIUM
**Where:** `internal/handler/auth.go` `issueTokenPair` (:350 `rtClaims, _ := …` then
deref); mirrored in `oidc.go`.
**Fix:** return `familyID` directly from `IssueRefreshToken` and drop the re-parse.
**Breaking:** internal signature change. None.

### M5 — `Retry-After` header emits garbage ≥ 10s — LOW
**Where:** `internal/handler/auth.go` (:27 `string(rune(n+'0'))`).
**Fix:** `strconv.Itoa`. **Breaking:** none.

### M6 — OIDC authorization-code flow has no PKCE — MEDIUM
**Where:** `internal/handler/oidc.go` (no `code_challenge`/`code_verifier` anywhere).
**Mechanism:** with codes not bound to a confidential client, an intercepted code can
be redeemed by anyone. Important now that the code grant stays public (C2).
**Fix:** support S256 PKCE — capture `code_challenge` at authorize, require a
matching `code_verifier` at token exchange when a challenge was set.
**Breaking:** optional (only enforced if a challenge was sent). None for existing
clients; SDKs/clients can opt in.

### M7 — Login user-enumeration via distinct responses — LOW
**Where:** `internal/handler/auth.go` (:52–:55 distinct 403 for disabled/locked).
**Fix:** generic failure message to unauthenticated callers (keep detail in audit log
+ admin UI). **Breaking:** less descriptive client errors.

### M8 — Security headers only on the admin UI — LOW
**Where:** `internal/handler/handler.go` (:258 `setAdminHeaders` only).
**Fix:** baseline headers (`X-Content-Type-Options`, `Referrer-Policy`,
`X-Frame-Options` where appropriate) on all responses.
**Breaking:** low.

### S1 — Python SDK was unimplemented — MEDIUM — FIXED 2026-05-30
`sdk/python/` shipped only `pyproject.toml` + `README.md`; every Python example
imported a package that did not exist. **Fixed:** full package implemented
(`client`, `middleware`, `models`, `jwks`, `errors`) with correct RS256/JWKS
verification (alg-pinned, `exp` fail-closed, configurable `iss`/`aud`). All five
examples resolve.

### S2 — JS/.NET SDK issuer check hardcoded to base URL — MEDIUM — OPEN
`sdk/js/index.ts` (~:486) and `sdk/dotnet/SimpleAuthClient.cs` (~:118) validate
`iss == base URL`, but direct login/refresh tokens are signed `iss="simpleauth"`, so
`verify()` always throws for login tokens. Also both skip the check when `iss` is
absent. **Fix (pending):** make issuer configurable (default off / accept the server
value), fail closed on absent `exp`.

### S3 — Go SDK accepts refresh tokens; skips `exp` when absent — MEDIUM — OPEN
`sdk/go/simpleauth.go` `Verify` (~:412) checks neither `iss` nor token type, so an
RS256-signed refresh token authenticates as a user; `exp` is only enforced when
present. **Fix (pending):** enforce `exp`, and reject non-access tokens (check a
token-type/`typ` claim or issuer).

### I1 — Single static admin key is the entire authz model — INFO — WONTFIX
The master admin key is the sole admin trust boundary; all admin actions are audited
as the literal actor `"admin"` (no per-admin attribution). Deliberate simplicity
trade-off for a single-app server; documented. Revisit if multi-admin is added.

### I2 — No tests for `internal/auth` / `internal/config` — INFO — PARTIAL
The most security-critical packages had no unit tests. **Partially addressed**:
added `internal/auth/jwt_test.go` (stable kid, alg-confusion rejection, refresh
family id), `internal/handler/security_fixes_test.go` (PKCE S256/plain, secret
encrypt/decrypt round-trip), and `internal/store/consume_test.go` (atomic
single-use refresh). Still missing: LDAP filter-escaping tests, config/TLS tests,
and an end-to-end Kerberos verify test (needs a fixture keytab).

### M9 — Reflected XSS on the login pages — MEDIUM — FIXED 2026-05-30
**Where:** `internal/handler/oidc.go` `showOIDCLoginPage` and
`internal/handler/hosted_login.go` `handleHostedLoginPage`.
**Mechanism:** the `error` query param (and `state`/`nonce`/`scope`/`redirect_uri`
on the OIDC page) were interpolated into the HTML response via `fmt.Fprintf`
without escaping, enabling reflected XSS on an unauthenticated page.
**Fix:** HTML-escape all reflected values with `html.EscapeString` before
rendering; URL components of the SSO link remain `url.QueryEscape`d.
**Breaking:** none.

---

## Remediation Log — Audit Pass 1 (2026-05-30, Claude Opus 4.8)

Released in **v1.1.0** — kept on the v1 line by request (v2.0.0 is reserved for
upcoming major work). Note: despite the minor version, these fixes include
**breaking behavior changes** — see Operator notes. All changes on branch
`security-hardening-2026-05-30`. Build, `go vet`, and the test suite are green.
Pre-existing non-gofmt formatting was left untouched to keep the diff scoped to
security.

| ID | Files | Approach |
|----|-------|----------|
| C1 | `internal/handler/auth.go` | Replaced decrypt-only paths with `service.VerifyAPREQ` (authenticator + 5-min clock skew + replay cache, PAC decoding disabled) via new `parseAPReqToken`/`verifyAPReq` helpers used by `handleNegotiate`, `handleSSOLogin`, and the diagnostic path. |
| C2 | `internal/handler/oidc.go` | `requireConfidentialClient` (constant-time secret check) gates `password` + `client_credentials`; disabled unless `AUTH_CLIENT_SECRET` is set. Discovery advertises only enabled grants/auth methods. `authorization_code`/`refresh_token` stay public (hardened by PKCE). |
| C3 | `internal/handler/oidc.go` | Introspection now requires `requireConfidentialClient`. |
| H1 | `internal/handler/auth.go`, `handler.go`, `internal/config/config.go` | Per-IP limiter added to `handleNegotiate`/`handleSSOLogin`/`handleNegotiateTestForm`; `/test-negotiate` routes gated behind new `EnableTestEndpoints` (default off, `AUTH_ENABLE_TEST_ENDPOINTS`). |
| H2 | `internal/store/{interface,bolt,postgres}.go`, `auth.go`, `oidc.go` | New atomic `ConsumeRefreshToken` (Bolt single txn; Postgres `SELECT … FOR UPDATE`) with `ErrRefreshTokenReused`/`ErrRefreshTokenNotFound`; both refresh handlers use it. |
| H3 | `internal/store/migrate.go` | Migrate `sessions`/`revoked_tokens`/`revoked_users` both directions; PG→Bolt now hard-fails on count mismatch. |
| H4 | `internal/handler/secrets.go`, `handler.go` | AES-256-GCM at-rest encryption of the LDAP bind password with a `0600` `secret.key` in the data dir (not in the DB, so backups don't carry the key); legacy plaintext auto-migrates on next save. |
| M1 | `internal/handler/oidc.go` | id_token `aud` uses `oidcClientID()`. |
| M2 | `internal/auth/jwt.go` | `kid` = SHA-256 thumbprint of the public key (stable across restarts). |
| M3 | `auth.go`, `oidc.go` | Both refresh paths consult `IsUserAccessRevoked`. |
| M4 | `internal/auth/jwt.go` (+ callers) | `IssueRefreshToken` returns `familyID`; removed the ignored-error re-parse + nil-deref. Also persists refresh rows before returning the pair. |
| M5 | `internal/handler/auth.go` | `Retry-After` via `strconv.Itoa`. |
| M6 | `internal/handler/oidc.go`, `internal/store/types.go`, `auth.go` | Optional S256/plain PKCE: challenge captured at authorize (incl. SSO link + hidden form fields), verified at token exchange. |
| M7 | `internal/handler/auth.go` | Uniform `invalid credentials` on login failure; real reason stays in the audit log. |
| M8 | `internal/handler/handler.go` | Global `X-Content-Type-Options: nosniff` + `Referrer-Policy: no-referrer`. |
| M9 | `oidc.go`, `hosted_login.go` | HTML-escape reflected values on both login pages. |

### Operator notes (behavior changes shipped in this pass)
- **Kerberos now requires NTP** (server/KDC/client within 5 minutes) and a correct
  keytab. Validate SSO in staging before production. (C1)
- **OIDC `password` and `client_credentials` grants are disabled** unless
  `AUTH_CLIENT_SECRET` is set; when set, callers must present that secret. (C2)
- **Token introspection requires the client secret.** (C3)
- **`/test-negotiate` is gone unless `AUTH_ENABLE_TEST_ENDPOINTS=true`.** (H1)
- **`secret.key` is now a critical file** in the data dir — back it up alongside
  (but stored separately from) the database. (H4)

### Still open (recommended next pass)
- **I2** remainder — LDAP escaping + config tests + Kerberos verify fixture.
- Not yet done: per-admin attribution (I1, by design), refresh-token/OIDC-code
  pruning, and `X-Forwarded-Proto` trusted-proxy gating in `oidcBaseURL`.

---

## Remediation Log — Follow-up (2026-05-30): SDK hardening + docs

| ID | Files | Approach |
|----|-------|----------|
| S2 | `sdk/js/index.ts`, `sdk/dotnet/{SimpleAuthClient,SimpleAuthUser}.cs` | Issuer check is now opt-in (`expectedIssuer`/`ExpectedIssuer`, default off) instead of a hardcoded base-URL compare that rejected every login token; `exp` is mandatory (fail closed); refresh tokens (carrying `family_id`) are rejected; optional audience check added. |
| S3 | `sdk/go/simpleauth.go` | `Verify` now enforces `exp` (fail closed when absent), rejects refresh tokens, and adds optional `ExpectedIssuer`/`Audience` (string-or-array `aud`). |
| docs | `README.md`, `docs/API.md`, `docs/CONFIGURATION.md` | OIDC `password`/`client_credentials`/introspection documented as confidential (require `AUTH_CLIENT_SECRET`, disabled by default); authorization-code PKCE noted; added `client_secret`, `enable_test_endpoints`, `secret.key`, and the Kerberos NTP requirement. |

**Build verification:** Go SDK `go build`/`go vet` clean. The JS SDK ships without a
`tsconfig.json` (pre-existing) and the .NET toolchain is absent in this environment,
so those two could not be fully compiled here — changes mirror existing patterns and
were reviewed by hand. Recommend wiring SDK builds into CI.

All three SDKs now (a) pin RS256, (b) fail closed on missing `exp`, (c) refuse
refresh tokens as access tokens, and (d) make issuer/audience validation opt-in so
`verify()` works against the stock server (login tokens use `iss="simpleauth"`). The
Python SDK (S1) already followed this model.

---

## Audit Pass 2 — 2026-05-31 — Claude Opus 4.8 (`claude-opus-4-8`)

**Scope:** the **v2 per-app authorization** work on the `v2` branch (NOT yet
released — these are pre-release findings to fix before merging to `2.0.0`). New
surface: app registry (`admin_apps.go`), app self-service + app-management tokens
(`app_selfservice.go`), app/authz resolution + audience scoping (`apps.go`),
app-local users, the `apps`/`app_authz` store, refresh re-stamping, and the admin
UI Apps page. The pre-existing v1 surface (Pass 1) was not re-audited here.

**Method:** first-hand read of every v2 file, then three parallel adversarial
sub-agents (app-credential auth; authz/token scoping; app-local users/store/UI),
each instructed to refute before reporting. H5 and M11 were confirmed with
throwaway PoCs (written, run green, deleted). `go build` clean; v2 test suite green
(the bugs below are mostly in paths the tests don't assert on).

All 17 findings are **OPEN**. None is a v1 regression. The v2 model's core promise
— "a token for app A is useless on app B, and each app controls its own
roles/users" — is undermined primarily by H5, H6, and M11.

### H5 — v1 `/api/auth/refresh` drops per-app authz → privilege escalation — HIGH
**Where:** `internal/handler/auth.go` `handleRefresh` — `roles, _ := h.store.GetUserRoles(user.GUID)` (:540), audience re-stamp (:557-559).
**Mechanism:** the OIDC refresh path correctly re-resolves the app and calls
`resolveTokenRoles` + the `denied` check (`oidc.go:607-612`). The legacy
`/api/auth/refresh` path does **not**: it loads the user's **global** roles, never
resolves the app, never checks `require_assignment` — yet it still re-stamps
`storedRT.Audience` so the new token carries `aud=<appB>`. Any user who logs into a
scoped app (e.g. `roles=[viewer]` at `billing`) and then calls `/api/auth/refresh`
with that app-bound refresh token receives a token with `aud=[billing]` but
`roles=[<their global roles, e.g. superadmin>]`. The RP verifies `aud`, trusts
`roles`, and grants escalated access. Also bypasses `require_assignment`
de-assignment (a user removed from the app still refreshes successfully).
**PoC:** login `billing` → `roles=[viewer]`; refresh → `roles=[superadmin] aud=[billing]`. Confirmed.
**Fix:** in `handleRefresh`, resolve `app` from `storedRT.AppID` and replace the
global-roles load with `roles, perms, denied := h.resolveTokenRoles(app, user)`;
return 403 on `denied`; guard nil app (see M10). Mirrors `handleOIDCTokenRefresh`.
**Breaking:** no (restores intended v2 scoping; only "breaks" the escalation).
**Note:** existing `TestAudienceScopedTokens` asserts `aud` is preserved on refresh
but never asserts the *roles* — which is why this slipped through. Add a roles
assertion.

### H6 — `require_assignment` fails open when an app has no per-app authz — HIGH
**Where:** `internal/handler/apps.go` `resolveTokenRoles` (:88-96, :125).
**Mechanism:** when the app has defined no roles/user-assignments/group-assignments
(`hasPerApp == false`), the function returns the user's **global** roles with
`denied = false` and returns **before** the `require_assignment` check at :125. So
an operator who sets `require_assignment: true` (expecting deny-by-default) but has
not yet populated assignments admits **every** directory user with their global
roles — the exact opposite of the control they enabled. The deny check only runs on
the `hasPerApp == true` branch.
**Fix:** evaluate `require_assignment` independently of `hasPerApp` — if
`app.RequireAssignment` and the user is not an owner-app-local user and has no
assignment, deny, regardless of whether the app has defined roles yet. (The
v1-fallback should apply only when `require_assignment` is false.)
**Breaking:** yes, intentionally — apps with `require_assignment: true` and no
assignments will (correctly) start denying. That is the point of the flag.

### H7 — App-management token is accepted as a user access token (no `typ` gate) — HIGH
**Where:** `internal/handler/auth.go` `validateAccessToken` (:719) and userinfo
(:598); `internal/handler/oidc.go` userinfo (:784) / introspection (:864). Token
minted at `app_selfservice.go:72-74` with `Typ:"app-mgmt"`, `Subject:app_id`.
**Mechanism:** the app-management token is an ordinary RS256 JWT signed by the same
key as user tokens, and the resource-server validators never check `claims.Typ`. So
a management token passes `/api/auth/userinfo`, OIDC `/userinfo`,
`/api/auth/reset-password`, and introspects as `active:true`. Because `app_id` and
user `GUID` share a namespace (the slug regex `^[a-z0-9][a-z0-9_-]{0,63}$` at
`admin_apps.go:17` admits any UUID), a master admin can register an app whose
`app_id` equals a victim's GUID; a management token for it makes
`ResolveUser(claims.Subject)` return the victim's profile at `/userinfo`. Even
without the collision, a management credential validating as a user credential is a
privilege-boundary failure.
**Refuted (SAFE):** the reverse is blocked — `authenticateApp` strictly requires
`Typ=="app-mgmt"` (`app_selfservice.go:41`), so user/refresh tokens cannot pass
`requireApp`; mgmt tokens cannot be used as OIDC refresh tokens nor reach
`client_credentials`/admin.
**Fix:** in `validateAccessToken` reject `claims.Typ=="app-mgmt"` (treat management
tokens as a separate audience/typ that only `authenticateApp` accepts).
**Breaking:** no (management tokens were never meant to work at user endpoints).

### H8 — `DeleteApp` orphans app-local users + mappings → cross-tenant resurrection — HIGH
**Where:** `internal/store/bolt.go` `DeleteApp` (:123-131), `internal/store/postgres.go` `DeleteApp` (:180-187); auth at `internal/handler/auth.go` (:135-150).
**Mechanism:** `DeleteApp` cascades only `app_authz`; it never deletes the `User`
rows with `OwnerAppID==appID` nor their `applocal:{appID}` identity mappings (no FK
cascade in the PG schema either). A deleted `app_id` can be re-registered freely,
possibly by a different owner. On reuse, `authenticateUser` step 0 resolves the
**old** `applocal:{appID}` mapping, sees `user.OwnerAppID == app.AppID`, and accepts
the **old account's old password** — the new owner silently inherits accounts (and
stored password hashes) they never created. With authz cascaded away, those ghosts
hit the v1-fallback path and `assignDefaultRoles` grants them default roles on the
new owner's app.
**Fix:** on `DeleteApp`, enumerate `OwnerAppID==appID` users, delete each user row +
its `applocal:{appID}` mappings, then delete the app. (Optionally also tombstone
deleted app_ids to forbid reuse.) Add to both Bolt and Postgres.
**Breaking:** no.

### M10 — OIDC refresh nil-derefs on a disabled/deleted app; both refresh paths skip app-disable — MEDIUM
**Where:** `internal/handler/oidc.go` `handleOIDCTokenRefresh` (:607-608);
`internal/handler/auth.go` `handleRefresh` (no app re-resolution at all).
**Mechanism:** `app, _ := h.resolveApp(storedRT.AppID)` ignores the error. When the
app is disabled or deleted, `resolveApp` returns `(nil, err)`, so `app == nil`, and
`resolveTokenRoles(app, user)` dereferences `app.AppID` → nil-deref → 500 (a
crash/DoS on a normal client action). Separately, the v1 `handleRefresh` never
checks `app.Disabled` at all, so **disabling an app does not stop token refresh** —
the app-disable kill switch is incomplete on the refresh paths (primary issuance
*does* honor disable via `resolveApp`).
**Fix:** in both refresh handlers, resolve the app and on error return a clean
`invalid_grant`/401 (and stop minting tokens for a disabled app); never deref a nil
app. Folds into the H5 fix for `handleRefresh`.
**Breaking:** no (refreshing into a disabled/deleted app *should* fail).

### M11 — OIDC `client_credentials`/`password` use the global secret but mint any app's `aud` — MEDIUM
**Where:** `internal/handler/oidc.go` `requireConfidentialClient` (:130-144),
`handleOIDCTokenClientCredentials` (:517-538), `handleOIDCTokenPassword` (:460-481).
**Mechanism:** `requireConfidentialClient` compares only against the single global
`cfg.ClientSecret`; the handler then does `resolveApp(r.FormValue("client_id"))` and
sets `sub=app_id, aud=appAudience(app)`. The per-app `App.SecretHash` is never
consulted. So any holder of the one global secret can mint a `client_credentials`
machine token — or a `password`-grant user token — scoped to **any** registered
app's audience by changing `client_id`. The "token for app A is useless on app B"
guarantee collapses for confidential grants: one shared secret impersonates every
app. (`password` still runs `resolveTokenRoles`, so its role/`require_assignment`
logic is intact; the defect is the cross-app `aud` selection. `client_credentials`
carries no roles, so impact there is the `aud`/`sub=app_id` confusion.)
**PoC:** `client_id=billing` + global secret → 200 `aud=[billing]`; billing's own
`app_secret` on the same grant → 401. Confirmed.
**Fix:** when `client_id` names a real app, authenticate against that app's
`SecretHash` (`auth.CheckPassword`) instead of the global secret.
**Breaking:** yes — deployments using the global secret with a non-default
`client_id` on these grants must switch to the per-app secret. Acceptable per the
security-over-compat policy.

### M12 — Kerberos auto-provision binding hijack via app-set `email`/`display_name` — MEDIUM
**Where:** `internal/handler/auth.go` negotiate auto-provision scan (:881-888);
app-local fields set at `app_selfservice.go:216-218`.
**Mechanism:** when no `kerberos` identity mapping exists for a verified principal,
the negotiate flow scans **all** users (`ListUsers()`, which includes app-local
users) and binds the principal to the first user whose `DisplayName == username` or
`Email == username`. An app can pre-create an app-local user whose `email` equals a
target principal's local part; with Kerberos enabled, that app captures the
principal's first negotiate login onto an app-owned GUID (or pollutes the directory
user's mapping). Conditional on negotiate being enabled and a name collision; scan
order is nondeterministic.
**Fix:** exclude `OwnerAppID != ""` users from the negotiate auto-provision scan
(app-local users are never directory principals).
**Breaking:** no.

### M13 — Group list never cleared when a user leaves all directory groups → stale roles — MEDIUM
**Where:** `internal/handler/auth.go` `syncUserFromLDAP` (:335-338).
**Mechanism:** the guard `if len(result.Groups) > 0 && …` means when an LDAP/Kerberos
login returns **zero** groups (user removed from all groups, or `GroupsAttr` unset),
the previously-cached non-empty `user.Groups` is left intact. `resolveTokenRoles`
(`apps.go:109-111`) then keeps awarding `GroupAssignments` roles for groups the user
no longer belongs to, and the stale set is emitted as the JWT `groups` claim.
(Reducing to a *different non-empty* set updates correctly — only the empty-result
case is buggy.)
**Fix:** drop the `len(result.Groups) > 0 &&` condition so an empty result overwrites
`Groups` (sync runs only after a successful bind, so an empty list is authoritative).
**Breaking:** no.

### M14 — Deleting an app-local user leaves a dangling mapping (username unprovisionable) — MEDIUM
**Where:** `internal/handler/app_selfservice.go` `handleDeleteLocalUser` (:269) vs the
create-time conflict check (:204-208).
**Mechanism:** delete calls only `store.DeleteUser(guid)`, which removes the user row
but not the `applocal:{appID}` identity mapping. `handleCreateLocalUser` rejects when
`ResolveMapping` still resolves that (now stale) mapping, so a just-deleted username
returns 409 **forever** and leaves a permanently dangling mapping. (Same root pattern
affects admin `handleDeleteUser` in `admin.go` — pre-existing, out of v2 scope but
worth a follow-up.)
**Fix:** in `handleDeleteLocalUser`, resolve the username from `GetMappingsForUser`
and call `DeleteIdentityMapping("applocal:"+appID, username)` after `DeleteUser`.
**Breaking:** no.

### M15 — App-local provisioning + reset bypass the password policy — MEDIUM
**Where:** `internal/handler/app_selfservice.go` create (:209) and reset (:294) call
`auth.HashPassword` directly with no `auth.ValidatePassword(..., h.passwordPolicy())`.
**Mechanism:** every other password sink enforces the policy (`admin.go:213`,
`auth.go:767`); the app-local paths do not, so an app can set
policy-violating/weak passwords (no complexity, no history check) on identities that
then authenticate through the normal login flow. (Lockout *is* honored for app-local
users; only complexity/history are skipped.)
**Fix:** call `auth.ValidatePassword` in both handlers before hashing.
**Breaking:** only for apps relying on weak passwords.

### M16 — No rate-limit on `/api/app/token` + `/api/app/*` Basic auth — MEDIUM
**Where:** `internal/handler/app_selfservice.go` Basic-auth path (:32-48) and
`handleAppToken` (:57-84) — neither calls `h.loginLimiter.allow(...)`.
**Mechanism:** unlike `handleLogin`/OIDC token, the app credential surface has no
per-IP throttle, so `app_id:app_secret` can be hammered without brake (online
brute-force / DoS). Generated secrets are 24 random bytes (strong), but admins may
set weak custom secrets, and the absence of any limiter is itself the defect.
**Fix:** gate both on the existing IP limiter.
**Breaking:** no.

### L1 — `/login/sso` validates `redirect_uri` against the global, not per-app, allowlist — LOW
**Where:** `internal/handler/auth.go` `handleSSOLogin` (:1076 uses
`isAllowedRedirect(h.getRedirectURIs(), …)`), then resolves the app from `client_id`
and issues an app-scoped token/code to that URI.
**Mechanism:** the hosted-login and OIDC-authorize paths correctly use
`appAllowsRedirect(app, …)`; `/login/sso` does not. With `client_id=appB`, a
`redirect_uri` that is globally allowed but absent from app B's stricter
`redirect_uris` leaks an app-B-scoped token to a URI app B never authorized
(bounded by the global allowlist, so the destination is still admin-registered).
**Fix:** resolve the app earlier and use `h.appAllowsRedirect(app, redirectURI)`.
**Breaking:** no.

### L2 — `handleImpersonate` mints an `aud`-less token with global roles — LOW
**Where:** `internal/handler/auth.go` `handleImpersonate` (:668-684) calls
`IssueAccessToken` with no `Audience`. Master-admin-gated.
**Mechanism:** RPs that opt into `aud` verification reject it (no `aud`); RPs that
skip `aud` accept a global-role token. Acceptable for an admin console but
inconsistent with per-app scoping.
**Fix:** scope impersonation to a target app (require/stamp an `aud`), or document
the exception.
**Breaking:** depends (if a target app is required).

### L3 — App-local user creation TOCTOU (store enforces no username uniqueness) — LOW
**Where:** `internal/handler/app_selfservice.go` (:204-225); store `CreateUser` +
`SetIdentityMapping` impose no uniqueness on `applocal:{appID}`+username.
**Mechanism:** the existence check and the create are not atomic; two concurrent
`POST /api/app/users` with the same username both pass, create two GUIDs, and the
second `SetIdentityMapping` overwrites the first — orphaning a fully-provisioned user
and making login nondeterministic. Not a privilege escalation.
**Fix:** make check-then-create atomic in the store (or a per-app lock); enforce
mapping uniqueness on write.
**Breaking:** no.

### L4 — `rotate-secret` does not revoke outstanding app-management tokens — LOW
**Where:** `internal/handler/admin_apps.go` `handleRotateAppSecret` (:209-232) only
rewrites `SecretHash`.
**Mechanism:** existing app-management JWTs remain valid until `AccessTTL` expiry
(self-contained, unrevocable; `authenticateApp` re-checks only `Disabled`, not a
secret version). Rotating a leaked secret does not actually cut off active sessions —
only *disabling* the app does.
**Fix:** stamp a per-app secret version / `not-before` into the management token and
check it on use, or document disable (not rotate) as the kill switch.
**Breaking:** no.

### L5 — App-id enumeration via bcrypt timing oracle — LOW
**Where:** `internal/handler/app_selfservice.go` (:34-37, :66-67): bcrypt
`CheckPassword` runs only when `GetApp` succeeds.
**Mechanism:** a valid `app_id` with a wrong secret is measurably slower than an
unknown `app_id`, letting an attacker enumerate registered app_ids (which are not
themselves secrets, so impact is low).
**Fix:** run a dummy bcrypt compare on the not-found branch, or accept it.
**Breaking:** no.

### I3 — Group-derived roles are inherently stale on refresh — INFO
**Where:** both refresh paths; `user.Groups` is refreshed only by `syncUserFromLDAP`
on interactive LDAP/Kerberos login.
**Mechanism:** neither refresh path re-reads the directory, so AD group changes
aren't reflected in per-app group-assignment roles until the user's next interactive
login. Inherent to the persisted-`Groups` design; amplified by H5/M13. Operator
note rather than a code bug — short access-token TTLs bound the staleness window.

### Verified SAFE in Pass 2 (tried to break, survived)
- **App scope/provenance:** every `/api/app/*` handler derives `app_id` from the
  credential (`appIDFromContext`), never from a body/path field; no cross-app IDOR
  (delete/password/list enforce `OwnerAppID==appID`). Per-app authz is keyed by
  `app.AppID` — no cross-app bleed.
- **Secret handling:** `appView` never emits `SecretHash`; the secret is shown once
  on create/rotate only.
- **Audience consistency:** `aud` is set on every *primary* issuance path (direct /
  hosted / Kerberos / SSO / OIDC authcode/password), always as an array; the SDKs
  handle string-or-array `aud`.
- **Cross-app refresh via `client_id` injection:** not possible — both refresh
  handlers derive app/audience from the **stored** refresh row, never a request
  `client_id`.
- **OIDC authcode binding:** resolves the app from the code, binds + re-checks
  `redirect_uri`, enforces PKCE when set.
- **`resolveApp` transient-default:** synthesized only for the default app id, never
  for a named/disabled app.
- **Local users can't set their own `Groups`:** `Groups` is written only from LDAP
  results, never via admin or self-service create.
- **App-local fencing:** app-local users shadow correctly, are exempt from
  `require_assignment` only for their owner app, and are excluded from cross-app SSO
  cookies; a wrong app-local password does not fall through to directory auth.
- **Store parity:** `App`/`AppAuthz` CRUD behaves identically across Bolt/Postgres
  (including the buggy `DeleteApp` cascade — same on both); migration round-trips
  `apps`+`app_authz` both directions with row-count checks.
- **Admin UI Apps page:** Preact/htm auto-escapes all interpolated app fields, the
  shown secret, and the authz editor; no `innerHTML`/`dangerouslySetInnerHTML` sink;
  actions hit the correct credential-scoped endpoints.

### Recommended fix order (all OPEN)
1. **H5, H6, M10** — the per-app authz / refresh correctness cluster (one coherent
   change to `handleRefresh` + `resolveTokenRoles`). Highest impact, mostly
   non-breaking.
2. **H7** — add the `typ` gate in `validateAccessToken` (trivial, non-breaking).
3. **H8, M14, L3** — app-local user lifecycle / mapping hygiene in the store.
4. **M11** — per-app secret for confidential grants (breaking; bundle with the
   `2.0.0` notes).
5. **M12, M13, M15, M16** — provisioning + sync + rate-limit hardening.
6. **L1, L2, L4, L5, I3** — lower-impact hardening + operator docs.

---

## Remediation Log — Audit Pass 2 (2026-05-31, Claude Opus 4.8)

All 16 code findings (H5–H8, M10–M16, L1–L5) are **FIXED** on branch `v2`, one
commit per finding, each with a regression test in
`internal/handler/pass2_test.go` (plus store-layer coverage for H8). I3 is
**WONTFIX** (design note, below). `go build`, `go vet`, and the full test suite are
green.

| ID | Files | Approach |
|----|-------|----------|
| H5 | `internal/handler/auth.go` | `handleRefresh` re-resolves the app from the stored refresh row and uses `resolveTokenRoles` (per-app roles + `require_assignment`) instead of global roles; rejects a disabled/deleted app. |
| H6 | `internal/handler/apps.go` | `resolveTokenRoles` evaluates `require_assignment` **before** the v1 global-roles fallback, so an app with the flag on but no assignments fails closed. |
| H7 | `internal/handler/auth.go` | `validateAccessToken` rejects `typ=="app-mgmt"`, so management tokens can't act as user tokens at userinfo/introspection/reset-password. |
| H8 | `internal/store/{bolt,postgres}.go` | `DeleteApp` cascades app-local users + their `applocal:` identity mappings inside one transaction. |
| M10 | `internal/handler/oidc.go` (+ H5 for auth.go) | OIDC refresh resolves the app and returns `invalid_grant` on a disabled/deleted app instead of nil-dereferencing. |
| M11 | `internal/handler/oidc.go` | New `authenticateConfidentialClient`: named apps authenticate against their own `SecretHash` for `client_credentials`/`password`; the secret-less default client falls back to `AUTH_CLIENT_SECRET`. |
| M12 | `internal/handler/{auth,apps}.go` | Kerberos auto-provision (`matchAutoProvisionUser`) skips `OwnerAppID!=""` users. |
| M13 | `internal/handler/auth.go` | `syncUserFromLDAP` always reconciles `user.Groups` to the bind result, clearing stale groups when the user is in none. |
| M14 | `internal/handler/app_selfservice.go` | `handleDeleteLocalUser` deletes the user's identity mappings + stale per-app assignment. |
| M15 | `internal/handler/app_selfservice.go` | App-local create + password reset call `auth.ValidatePassword(…, h.passwordPolicy())`. |
| M16 | `internal/handler/app_selfservice.go` | `/api/app/token` and Basic-auth `/api/app/*` go through the per-IP login limiter; Bearer mgmt-token calls are exempt. |
| L1 | `internal/handler/auth.go` | `/login/sso` resolves the app up front and validates `redirect_uri` via `appAllowsRedirect`. |
| L2 | `internal/handler/auth.go` | `handleImpersonate` scopes the token to an app (optional `app_id`, default app otherwise), stamping `aud` + per-app roles. |
| L4 | `internal/store/types.go`, `internal/handler/{admin_apps,app_selfservice}.go` | `App.SecretRotatedAt` stamped on rotate; `authenticateApp` rejects mgmt tokens with `iat` before it. |
| L5 | `internal/handler/app_selfservice.go` | App credential check always runs one bcrypt compare (dummy hash when unknown/secret-less). |

### Operator notes (behavior changes shipped in this pass — for the `2.0.0` release)
- **`require_assignment` now denies by default (H6).** An app with
  `require_assignment: true` and no assignments will reject all directory users until
  you assign them. (Previously it silently admitted everyone with their global roles.)
- **Refreshed tokens carry per-app roles, not global roles (H5).** A user's effective
  app roles are re-evaluated on every refresh, including `require_assignment`
  de-assignment.
- **Confidential grants need the per-app secret (M11).** `client_credentials` and
  `password` for a **named** app must present that app's `app_secret`; only the
  secret-less default client uses `AUTH_CLIENT_SECRET`.
- **App-local passwords must meet the password policy (M15).**
- **Disabling or deleting an app now stops token refresh (H5/M10);** deleting an app
  also removes its app-local users (H8); rotating an app secret revokes its
  outstanding management tokens (L4).

### I3 — group-derived roles are stale on refresh — INFO — WONTFIX (by design)
Neither refresh path re-reads the directory, so an AD group change isn't reflected in
group-derived per-app roles until the user's next interactive login. This is inherent
to the persisted-`Groups` design (M3): it lets every flow resolve group roles without
a live LDAP round-trip on each token. The staleness window is bounded by the
access-token TTL, and **M13** now guarantees the next interactive login reconciles the
set (including clearing all groups). Operators who need immediate revocation should use
the access-revocation kill switch (`IsUserAccessRevoked`, honored on refresh per M3) or
a short access-token TTL. Revisit if a directory-change webhook/poll is added.

---

## Audit Pass 3 — 2026-06-01 — Claude Opus 4.8 (`claude-opus-4-8`, 1M)

Scope: full re-audit of the whole repo (server `internal/`, `pkg/`, all four SDKs,
examples, infra/CI, docs) **plus remediation in the same pass**. Method: an 18-dimension
multi-agent review (92 sub-agents) with every finding adversarially re-verified against the
cited code, cross-checked by static analysis (`go vet`, `gosec`, `staticcheck`,
`govulncheck`) and first-hand reading of all HIGH findings. After triage, 73 findings were
confirmed (1 candidate rejected as a false positive — a claimed empty-password LDAP bind
that `go-ldap` v3.4.13 already fails closed on). Baseline before and after: `go build`,
`go vet`, `gofmt`, `go test ./... -race` all clean; `govulncheck` reports 0 called
vulnerabilities; `staticcheck` clean.

Most findings were remediated this pass. The three **regressions / incomplete prior fixes**
below are referenced by their original IDs; genuinely new issues take new IDs.

### Regressions / incomplete prior fixes
- **H3 (regressed direction).** `MigrateFromPostgres` reused the existing `auth.db` data dir
  without clearing it and skipped verification for any table the source had 0 rows for, so
  stale users / SSO sessions / **revoked-token + revoked-user blacklists** from a prior BoltDB
  era could resurface — making revoked credentials valid again. Fixed: target buckets are now
  wiped (DeleteBucket+CreateBucket) before copy, and verification runs even for 0-row tables.
- **M8 (incomplete).** The Pass 1 baseline headers omitted frame protection, so only the admin
  UI was clickjacking-protected. `X-Frame-Options: DENY` + `Content-Security-Policy:
  frame-ancestors 'none'` are now part of the global baseline.
- **L1 (sibling endpoint).** The hosted-login (`GET /login`) session-SSO fast path validated
  `redirect_uri` against the **global** allowlist, then minted a token for the
  attacker-supplied `client_id`'s audience and delivered it there. Now validated against the
  resolved app's own allowlist up front and again inside `completeHostedLoginWithSession`.

### New HIGH findings (all FIXED)
- **H9 — Refresh/ID tokens accepted as access tokens.** `validateAccessToken` gated only
  `typ=="app-mgmt"`; refresh tokens (same key, marked only by `family_id`) and OIDC id_tokens
  (`typ="ID"`) passed it, authenticating at `/userinfo`, OIDC userinfo / introspection, and
  `/reset-password`. Fixed by rejecting `family_id != ""` and `typ=="ID"` there; `ValidateToken`
  now also requires `exp` (L6). The SDKs got the matching client-side gate (S4/S5/S6).
- **H10 — LDAP cleartext binds.** `LDAPConnect` only used TLS for `ldaps://`; plain `ldap://`
  sent the service-account and end-user passwords in the clear. Now `ldap://` is
  StartTLS-upgraded and **fails closed** unless the operator sets the new `allow_insecure`
  opt-out. (The search filter already used `ldap.EscapeFilter`, so no LDAP injection exists.)
- **H11 — `secret.key` overwrite.** `loadOrCreateSecretKey` treated *any* read error as
  "create new key" and overwrote the file, permanently destroying decryption of stored LDAP
  bind passwords. Now guarded with `errors.Is(err, os.ErrNotExist)`.
- **H12 — Fail-open revocation.** `RevokeUserTokens`/`RevokeTokenFamily` (Postgres) discarded
  every per-row DELETE error and always returned `nil`, so "disable user / log out everywhere"
  could report success while tokens survived. Replaced with single atomic parameterized DELETEs
  that surface errors.

### New MEDIUM findings (all FIXED)
M17 HTTP server timeouts (closes Slowloris); M18 OIDC end-session open redirect (now validates
`post_logout_redirect_uri` against the app allowlist); M19 OIDC authorize-POST CSRF; M20 OIDC
logout requires a genuine `typ="ID"` token before revocation; M21 `client_credentials`
IP-rate-limited; M22 `oidcBaseURL` pins the host on `Host`-header mismatch and only trusts
`X-Forwarded-Proto` from a trusted proxy; M23 empty `redirect_uri` resolves from the app's own
URIs, not the global default; M24 `resolveApp` fails closed on a real store error (new
`ErrAppNotFound` sentinel); M25 settings PUT floors `password_min_length` at 8 and rejects
`cors_origins="*"`; M26 delete-user + DB restore now audited; M27 delete-user revokes tokens +
SSO sessions; M28 `BoltStore.Restore` serialized by `sync.RWMutex` (race-clean under `-race`);
M29 expired refresh tokens pruned hourly; M30 Postgres audit filters pushed into SQL before
`LIMIT`; M31 verified Kerberos principal bound to the configured realm; M32 keytab drops
RC4-HMAC; M33 hosted-login error redirects re-validated; M34 restart loop tears down the pruner
via a stop channel (also `pkg/server`); M35 admin key persisted to `<data_dir>/admin.key`
(0600), path logged not the secret; M36 container/CI hardening (pinned non-EOL base, plaintext
app un-published, unprivileged nginx, SHA-pinned least-privilege Actions, secure TLS defaults);
M37 LDAP group-CN parsing case-insensitive.

### New LOW findings (FIXED): L6–L18
`exp` mandatory in `ValidateToken` (L6); PKCE rejects `plain`/empty (L7); impersonation rejects
disabled/revoked targets (L8); CORS `*` emits literal `*` (L9); `data_dir` MkdirAll error
surfaced (L10); `MergeUsers` rolls back on write errors (L11); abandoned OIDC auth codes pruned
(L12); SSO cookie scoped to `BasePath` (L13); SDK JWKS unknown-`kid` refetch bounded (L14); the
canonical Go example pins `Audience`/issuer (L15); the Python SDK rejects sub-2048-bit JWKS keys
(L16); the Express example no longer wires an admin-only route to a key-less client (L17); the
deployment checklist now covers `secret.key` backup, NTP, and the correct health path (L18).

### Deferred (acknowledged, not yet fixed)
- **L19** `GET /test-negotiate` is not rate-limited — but it is gated behind
  `AUTH_ENABLE_TEST_ENDPOINTS` (default off), so it is not exposed in production.
- **L20** `Retry-After` only on `POST /api/auth/login` 429s — cosmetic; throttling still applies.
- **L21** Several LDAP lookups hardcode `sAMAccountName` instead of `UsernameAttr` — affects only
  non-AD directories using a non-default username attribute.
- **L22** Runtime `rate_limit_*` settings are persisted but applied only on restart.
- **F51 (partial).** `ValidateToken` still does not pin `iss`/`aud` (only `exp` is now required):
  intentional, because OIDC tokens legitimately carry Host-derived and per-app issuers/audiences
  through the same validator — issuer/audience are enforced at the SDK/RP layer (the
  `ExpectedIssuer`/`Audience` options) rather than centrally.

These remain the standing OPEN items for the next pass.
</content>

---

## Audit Pass 4 — 2026-08-08 — Claude Opus 5 (`claude-opus-5`)

Whole-codebase review (11 scoped reviewers, adversarial per-finding verification)
against `master` @ `c182507`. Each finding from that pass is documented in this
section as it is remediated, with a row in the Status Summary table above.

### H13 — OIDC login-error redirect drops `code_challenge` (PKCE bypass)

**Severity:** HIGH — reachable by any user mistyping their password once.

`renderOIDCLoginError` rebuilt the authorize URL by hand with `fmt.Sprintf`,
carrying `client_id`, `redirect_uri`, `state`, `nonce` and `scope` — but **not**
`code_challenge` or `code_challenge_method`.

Chain: a failed credential POST redirects to the login page without PKCE →
`showOIDCLoginPage` reads an empty challenge and stamps empty hidden fields →
the successful retry stores `OIDCAuthCode.CodeChallenge = ""` → the token
endpoint's `if ac.CodeChallenge != ""` guard is false → the code redeems with
**no `code_verifier`**. This undoes M6 for the remainder of the login, so an
intercepted code (referrer leak, malicious app on the redirect host) is
redeemable by anyone.

**Approach.** Introduced `oidcAuthzRequest` — a typed allowlist that is the single
definition of "the authorize request" — plus `parseOIDCAuthzRequest` and
`values()`. `renderOIDCLoginError` and the Kerberos `ssoLink` are both now built
from it, so a parameter added there is carried at every hop instead of having to
be remembered at each hand-concatenated site.

Deliberately **not** a copy of `r.Form`: `renderOIDCLoginError` runs on a
*credential POST*, whose body carries `username` and `password`. Copying and
mutating the form would place live credentials in a `Location:` header, browser
history and every proxy log on the path. `r.URL.Query()` is equally wrong — the
form posts to the bare authorize path, so the query is empty. The typed allowlist
gets the durability benefit with neither footgun.

Two invariants are preserved and now asserted by tests: the error always returns
to SimpleAuth's **own** authorize endpoint (the empty-credentials branch reaches
this function *before* `redirect_uri` is allowlist-checked, so bouncing to it
would be an open redirect — the OIDC sibling of F29), and credentials/CSRF are
never carried.

Also fixed in the same pass, same defect class: `handleLogout` dropped
`client_id`, dead-ending the documented logout round-trip on a `400` for any app
with its own `redirect_uris`.

**Tests:** `internal/handler/oidc_pkce_test.go` — `TestOIDCPKCESurvivesFailedLogin`
drives the full chain and asserts the post-retry code is **rejected** without a
verifier and accepted with one; `TestOIDCLoginErrorPreservesAuthorizeRequest`
pins the whole allowlist and the no-credential-leak invariant;
`TestOIDCLoginErrorWithNoCredentials` pins the open-redirect invariant;
`TestLogoutPreservesClientID` pins the logout round-trip.

**Known adjacent, not fixed here:** `handleSSOLogin`'s SPNEGO Negotiate-retry URL
(`internal/handler/auth.go`) drops every parameter including the `client_id` this
change adds to `ssoLink`. That is a design decision about the challenge-retry
shape rather than a parameter carry, and is filed separately.
