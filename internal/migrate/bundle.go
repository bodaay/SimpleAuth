// Package migrate builds and applies migration BUNDLES that move a standalone
// SimpleAuth deployment into a single named app on a central deployment.
//
// What moves is the AUTHORIZATION POLICY, not signing keys or PII we can avoid:
//   - the source home app's config (audience, redirect_uris, cors, secret hash,
//     flags) is carried onto the target named app, so the consumer app's existing
//     client_id / secret / redirect_uri keep working;
//   - the role->permission catalog becomes the target app's per-app authz;
//   - each user's EFFECTIVE roles travel keyed by a PORTABLE identity —
//   - AD users    -> sAMAccountName: the central re-binds them from the SAME
//     AD on login; no record or password is copied.
//   - local users -> username, with their password hash, materialized as
//     app-local users on the target app.
//
// The split is by AUTHENTICATION method, because that is the thing that does not
// move: a local user carries their hash; an AD user needs the central on the same
// AD. Classify (dry-run) reports whether every user is satisfiable on the central
// BEFORE any write; Apply performs the import.
package migrate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"simpleauth/internal/store"
)

// SchemaRev is the bundle wire-format revision; bump on incompatible changes.
//
// 2 (H16): user classification moved from "PasswordHash first" to "directory
// identity first", and a KindAD entry no longer carries a password hash. That
// decision is made on the SOURCE side, so a patched central cannot trust the Kind
// values in a rev-1 bundle. The exact-match check in guardMigrationCall turns the
// bump into the right operator instruction — "incompatible migration bundle;
// upgrade the older deployment first" — instead of silently importing a bundle
// built by the buggy classifier.
const SchemaRev = 2

// UserKind is how a user authenticates, which determines how they migrate.
type UserKind string

const (
	KindAD    UserKind = "ad"    // AD-backed: re-bound from the central's AD; key = sAMAccountName
	KindLocal UserKind = "local" // local password: materialized as an app-local user
)

// Bundle is the portable migration payload.
type Bundle struct {
	SchemaRev     int       `json:"schema_rev"`
	SourceVersion string    `json:"source_version"`
	CreatedAt     time.Time `json:"created_at"`

	// SourceAD describes the source's directory binding (nil if not AD-connected),
	// so the central can confirm it is the SAME AD before resolving AD users.
	SourceAD *ADInfo `json:"source_ad,omitempty"`

	App     AppConfig   `json:"app"`
	Catalog Catalog     `json:"catalog"`
	Users   []UserEntry `json:"users"`
}

// ADInfo identifies the source's Active Directory binding.
type ADInfo struct {
	Domain string `json:"domain,omitempty"`
	BaseDN string `json:"base_dn,omitempty"`
}

// AppConfig is the source home app's config, carried onto the target app.
type AppConfig struct {
	Audience          string            `json:"audience,omitempty"`
	RedirectURIs      []string          `json:"redirect_uris,omitempty"`
	CORSOrigins       []string          `json:"cors_origins,omitempty"`
	SecretHash        string            `json:"secret_hash,omitempty"`
	RequireAssignment bool              `json:"require_assignment"`
	BaseURL           string            `json:"base_url,omitempty"`
	DisplayName       map[string]string `json:"display_name,omitempty"`
	Category          string            `json:"category,omitempty"`
	Icon              string            `json:"icon,omitempty"`
}

// Catalog is the source's role/permission definitions.
type Catalog struct {
	RolePermissions map[string][]string `json:"role_permissions,omitempty"`
	Permissions     []string            `json:"permissions,omitempty"`
	DefaultRoles    []string            `json:"default_roles,omitempty"`
}

// UserEntry is one user's portable identity + effective roles.
type UserEntry struct {
	Kind  UserKind `json:"kind"`
	Key   string   `json:"key"`             // sAMAccountName (AD) or username (local)
	Roles []string `json:"roles,omitempty"` // effective roles (explicit, or default_roles)

	// DirectPerms are the user's direct (non-role) permissions. Reported by the
	// dry-run; NOT applied in this revision (named apps derive perms from roles).
	DirectPerms []string `json:"direct_perms,omitempty"`

	// Local-only: enough to materialize an app-local user with the same login.
	DisplayName  string `json:"display_name,omitempty"`
	Email        string `json:"email,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`

	// HadLocalPassword marks a KindAD user who ALSO held a local password on the
	// source (a break-glass account, or one acquired via a reset path). The hash is
	// NOT carried — see classifyUser — because the central re-binds this identity
	// from AD. Only the boolean travels, so the dry run can tell the operator which
	// logins do not survive the move.
	HadLocalPassword bool `json:"had_local_password,omitempty"`
}

// Package builds a Bundle from a standalone deployment's store, capturing its home
// app (homeAppID) config + the whole directory.
func Package(s store.Store, homeAppID, sourceVersion string) (*Bundle, error) {
	b := &Bundle{SchemaRev: SchemaRev, SourceVersion: sourceVersion, CreatedAt: time.Now().UTC()}

	if ldap, _ := s.GetLDAPConfig(); ldap != nil && (ldap.Domain != "" || ldap.BaseDN != "") {
		b.SourceAD = &ADInfo{Domain: ldap.Domain, BaseDN: ldap.BaseDN}
	}

	if app, err := s.GetApp(homeAppID); err == nil {
		aud := app.Audience
		if aud == "" {
			aud = app.AppID
		}
		b.App = AppConfig{
			Audience:          aud,
			RedirectURIs:      app.RedirectURIs,
			CORSOrigins:       app.CORSOrigins,
			SecretHash:        app.SecretHash,
			RequireAssignment: app.RequireAssignment,
			BaseURL:           app.BaseURL,
			DisplayName:       app.DisplayName,
			Category:          app.Category,
			Icon:              app.Icon,
		}
	}

	rp, _ := s.GetRolePermissions()
	perms, _ := s.GetDefinedPermissions()
	defs, _ := s.GetDefaultRoles()
	b.Catalog = Catalog{RolePermissions: rp, Permissions: perms, DefaultRoles: defs}

	users, err := s.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	for _, u := range users {
		if u.MergedInto != "" {
			continue // merged-away shadow
		}
		// App-local users owned by ANOTHER app aren't part of this home directory.
		if u.OwnerAppID != "" && u.OwnerAppID != homeAppID {
			continue
		}
		if entry, ok := classifyUser(s, u, b.Catalog.DefaultRoles); ok {
			b.Users = append(b.Users, entry)
		}
	}
	return b, nil
}

// classifyUser turns a source user into a portable UserEntry. ok=false skips a
// user with no usable identity.
//
// PRECEDENCE (H16): a DIRECTORY identity beats a local credential, always. This
// used to test PasswordHash first, so any AD-backed user who ALSO carried a local
// hash migrated as an app-LOCAL shadow keyed by that credential. Three things went
// wrong at once:
//   - the central ended up holding a standing password for someone whose identity
//     is directory-governed, so the account outlived AD-side disablement, lockout
//     and password policy — exactly what "no record or password is copied" in this
//     package's doc comment promises never happens;
//   - Classify never BLOCKS a local user, so a whole AD population misclassified
//     as local sailed straight past the "central is on a different AD" guard;
//   - Apply flipped allow_local_users on the target for accounts that must never
//     use the app-local login path.
//
// So: resolve the directory key first. Only a user with NO directory identity at
// all is a local user.
func classifyUser(s store.Store, u *store.User, defaultRoles []string) (UserEntry, bool) {
	roles, _ := s.GetUserRoles(u.GUID)
	if len(roles) == 0 {
		roles = defaultRoles // effective baseline the user had on the home app
	}
	direct, _ := s.GetUserPermissions(u.GUID)

	// An app-local user (OwnerAppID set) is local BY CONSTRUCTION: created only by
	// the app self-service path, authenticated locally, and never auto-provisioned
	// from the directory (M12). Package has already dropped the ones owned by
	// ANOTHER app, so an owner still set here is the home app's. Never resolve
	// these against the directory, whatever mappings an admin may have hung off
	// the record.
	if u.OwnerAppID == "" {
		key, err := directoryKey(s, u)
		if err != nil {
			// Cannot prove this user is local, so do not export a credential for
			// them. Skipping is the safe direction: a missing user is visible in the
			// preflight counts, a leaked hash is not.
			return UserEntry{}, false
		}
		if key != "" {
			// Directory-governed. The local hash — if any — is deliberately left
			// behind: the central re-binds this person from the SAME AD, so copying
			// the credential would recreate exactly the shadow account this
			// precedence exists to prevent. HadLocalPassword (a bool, never the
			// hash) lets the dry run tell the operator it did not travel.
			return UserEntry{
				Kind: KindAD, Key: key, Roles: roles, DirectPerms: direct,
				HadLocalPassword: u.PasswordHash != "",
			}, true
		}
	}

	if u.PasswordHash != "" {
		username, err := localUsername(s, u)
		if err != nil || username == "" {
			return UserEntry{}, false
		}
		return UserEntry{
			Kind: KindLocal, Key: username, Roles: roles, DirectPerms: direct,
			DisplayName: u.DisplayName, Email: u.Email, PasswordHash: u.PasswordHash,
		}, true
	}
	return UserEntry{}, false
}

// isDirectoryProvider reports whether an identity-mapping provider denotes a
// DIRECTORY identity (AD via LDAP or Kerberos) rather than a credential stored
// here.
//
// Both the bare names and the per-directory forms count. build.md documents
// multi-directory deployments as `ldap:corp` / `ldap:partner`, and
// handleSetMapping accepts an arbitrary provider string with no allow-list, so an
// exact match on "ldap" silently misses every deployment that followed the docs —
// their directory users would classify as local and have their password hashes
// exported, which is the whole defect H16 exists to prevent.
//
// "local" and "applocal:<app_id>" are deliberately excluded: those ARE credentials
// stored here.
func isDirectoryProvider(provider string) bool {
	switch provider {
	case "ldap", "kerberos":
		return true
	}
	return strings.HasPrefix(provider, "ldap:") || strings.HasPrefix(provider, "kerberos:")
}

// directoryKey returns the AD key a directory-governed user travels under, or ""
// when the user has no directory identity at all.
//
// SAMAccountName is preferred when present, but it is NOT universal: it is written
// on the LDAP bind path (and self-healed by syncUserFromLDAP), while the Kerberos
// SPNEGO path writes only a `kerberos` mapping and leaves SAMAccountName empty
// (handleNegotiate), and handleImportLDAPUsers leaves it empty until the user's
// first login. Hence the mapping fallback — without it those users misclassify as
// local and have their password hash exported.
//
// The `local` provider is deliberately NOT consulted. On the LDAP password path a
// JIT provision writes BOTH an `ldap` and a `local` mapping, so `local` is present
// on many AD users too — which is exactly how localUsername happily returned an AD
// username under the old precedence. (The Kerberos path writes neither, so this
// exclusion is about the LDAP case specifically.)
//
// Ordering must not depend on the backend: GetMappingsForUser returns insertion
// order on Bolt and UNORDERED rows on Postgres, and an LDAP user commonly carries
// two mappings (the typed cname/UPN plus the real sAMAccountName). Preferring a
// candidate without "@" is a best-effort tiebreak toward the sAMAccountName form,
// not a guarantee of it — a Kerberos-only user's sole candidate is a
// realm-qualified `user@REALM` cname, and that is simply what they travel under.
// Ties break lexicographically, so a given mapping SET yields the same key on both
// backends.
//
// NOTE: internal/handler has its own directory predicate (isDirectoryBacked,
// deny-by-default over "not local and not applocal"). This one is an allow-list
// because it must produce a KEY, not a verdict. The asymmetry is intentional; do
// not unify them — internal/migrate importing from internal/handler would invert
// the dependency direction.
func directoryKey(s store.Store, u *store.User) (string, error) {
	if u.SAMAccountName != "" {
		return u.SAMAccountName, nil
	}
	mappings, err := s.GetMappingsForUser(u.GUID)
	if err != nil {
		// Fail CLOSED. Swallowing this would mean "no directory identity", which
		// classifies the user as LOCAL and EXPORTS their password hash into the
		// bundle — the exact outcome this precedence exists to prevent. Refuse to
		// classify instead; Package drops the user and the operator sees a short
		// bundle rather than a leaked credential.
		return "", fmt.Errorf("mappings for %s: %w", u.GUID, err)
	}
	var cands []string
	for _, m := range mappings {
		if isDirectoryProvider(m.Provider) && m.ExternalID != "" {
			cands = append(cands, m.ExternalID)
		}
	}
	if len(cands) == 0 {
		return "", nil
	}
	sort.Slice(cands, func(i, j int) bool {
		iUPN, jUPN := strings.Contains(cands[i], "@"), strings.Contains(cands[j], "@")
		if iUPN != jUPN {
			return jUPN // a bare sAMAccountName sorts before a UPN/cname form
		}
		return cands[i] < cands[j]
	})
	return cands[0], nil
}

// localUsername finds the login username for a local user.
func localUsername(s store.Store, u *store.User) (string, error) {
	mappings, err := s.GetMappingsForUser(u.GUID)
	if err != nil {
		// Same reasoning as directoryKey: swallowing this makes the function fall
		// through to u.Email and export a credential under a key that is not the
		// user's login. Refuse instead.
		return "", fmt.Errorf("mappings for %s: %w", u.GUID, err)
	}
	for _, m := range mappings {
		if m.Provider == "local" {
			return m.ExternalID, nil
		}
	}
	for _, m := range mappings {
		if strings.HasPrefix(m.Provider, "applocal:") {
			return m.ExternalID, nil
		}
	}
	if u.SAMAccountName != "" {
		return u.SAMAccountName, nil
	}
	return u.Email, nil
}

// Report is the dry-run result the central computes before any write.
type Report struct {
	SourceVersion string `json:"source_version"`
	TargetApp     string `json:"target_app"`

	ADUsersSameDomain int `json:"ad_users_same_domain"` // resolvable from the central's AD
	ADUsersKnown      int `json:"ad_users_known"`       // already present in the central directory
	LocalUsers        int `json:"local_users"`          // materialized as app-local users
	// NoRoles counts users the bundle carries that Apply will NOT migrate: with no
	// effective roles there is nothing to grant, so no assignment is written and no
	// local account is created. Counted separately so the dry run's numbers are the
	// numbers the operator actually gets.
	NoRoles int           `json:"no_roles"`
	Blocked []BlockedUser `json:"blocked,omitempty"`
	Notes   []string      `json:"notes,omitempty"`

	RedirectURIsToReview []string `json:"redirect_uris_to_review,omitempty"`

	// AudienceToApply is the audience Apply will end up storing on the target —
	// shown in the dry run so an operator sees a carried audience BEFORE committing.
	AudienceToApply string `json:"audience_to_apply,omitempty"`
}

// BlockedUser is a user the central cannot satisfy as-is.
type BlockedUser struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// resolveCarriedAudience decides what audience the target app should end up with,
// and refuses a bundle that tries to claim somebody else's.
//
// The audience is a security PRINCIPAL, not a label: appAudience() feeds
// claims.Audience on every issuance path, and SimpleAuth deliberately does not
// pin `aud` centrally — F51 records that issuer/audience are enforced at the
// SDK/RP layer. So the string in `aud`, verified offline against the shared JWKS,
// is the ONLY thing between a token and a victim resource server.
//
// The migration-token holder is not a master admin: guardMigrationCall
// authenticates a single-use bearer token scoped to ONE target app. Carrying an
// arbitrary audience therefore lets that holder re-stamp their own app to mint
// `aud: ["billing-api"]` with self-chosen roles from the bundle's catalog, which
// the real billing service then admits (H15).
//
// Rules, in order:
//   - empty carried audience  → keep whatever the master admin set on the target.
//   - unchanged / equal to the target's own app_id → fine, and idempotent so a
//     re-run of the same migration does not collide with itself.
//   - equal to the central's DEFAULT app id → refused. This is checked explicitly
//     rather than via ListApps because ensureDefaultApp is called only from
//     main.go — on an embedded deployment (pkg/server) the row can be absent while
//     resolveApp still synthesizes it, so a ListApps-only check would miss the
//     highest-value target. It is also the no-effort version of the attack: a
//     stock standalone packages `aud = "simpleauth"`.
//   - equal to any OTHER registered app's audience or app_id → refused.
func resolveCarriedAudience(central store.Store, target *store.App, defaultAppID, bundleAud string) (string, string, error) {
	aud := strings.TrimSpace(bundleAud)
	if aud == "" {
		return target.Audience, "", nil
	}
	// Idempotency: carrying the value the target ALREADY holds is a no-op, so a
	// re-run of the same migration cannot collide with itself.
	//
	// Deliberately NOT `|| aud == target.AppID`. The target's app_id is not proven
	// free: nothing in handleCreateApp or handleUpdateApp enforces audience
	// uniqueness, so a central can legitimately hold App{AppID:"reports",
	// Audience:"analytics"} while an operator registers the migration target as
	// App{AppID:"analytics", Audience:"analytics-migrated"}. Self-allowing the
	// app_id there would hand the bundle "analytics" — the live audience of a
	// third-party resource server — which is exactly the takeover this refuses.
	if aud == target.Audience {
		return aud, "", nil
	}
	if defaultAppID != "" && aud == defaultAppID {
		return "", fmt.Sprintf("bundle audience %q is the central's default app — refusing (it would mint tokens the global directory app's consumers accept)", aud), nil
	}
	apps, err := central.ListApps()
	if err != nil {
		// Fail CLOSED: without the app list we cannot prove the audience is free.
		return "", "", fmt.Errorf("list apps for audience collision check: %w", err)
	}
	for _, a := range apps {
		if a.AppID == target.AppID {
			continue
		}
		if aud == a.Audience || aud == a.AppID {
			return "", fmt.Sprintf("bundle audience %q is already claimed by app %q — refusing (tokens minted for this app would be accepted by that app's resource servers)", aud, a.AppID), nil
		}
	}
	return aud, "", nil
}

// OK reports whether the migration can proceed (no blocked users).
func (r *Report) OK() bool { return len(r.Blocked) == 0 }

// Classify computes the dry-run report. It validates every user is satisfiable on
// the central WITHOUT mutating anything.
func Classify(b *Bundle, central store.Store, targetAppID, defaultAppID string) (*Report, error) {
	r := &Report{SourceVersion: b.SourceVersion, TargetApp: targetAppID, RedirectURIsToReview: b.App.RedirectURIs}

	// Fresh-target guard: Apply wholesale-replaces the target's authz, so refuse a
	// target that already has ANY per-app authorization — user OR group
	// assignments, roles, role→perm map, or a permission catalog. Migrate into a
	// freshly-created app to avoid clobbering an in-use one.
	if cur, _ := central.GetAppAuthz(targetAppID); cur != nil && (len(cur.UserAssignments) > 0 || len(cur.GroupAssignments) > 0 || len(cur.RolePermissions) > 0 || len(cur.Roles) > 0 || len(cur.Permissions) > 0) {
		r.Blocked = append(r.Blocked, BlockedUser{Key: targetAppID, Reason: "target app already has authorization configured — migrate into a freshly-created app"})
		return r, nil
	}

	// Audience collision: refuse a bundle that claims another app's audience (H15).
	// Reported as a Blocked entry so the existing preflight UI renders it and
	// Report.OK() is false, which is what stops handleMigrationCommit.
	if target, err := central.GetApp(targetAppID); err == nil {
		aud, conflict, err := resolveCarriedAudience(central, target, defaultAppID, b.App.Audience)
		if err != nil {
			return nil, err
		}
		if conflict != "" {
			r.Blocked = append(r.Blocked, BlockedUser{Key: targetAppID, Reason: conflict})
			return r, nil
		}
		r.AudienceToApply = aud
	}

	centralLDAP, _ := central.GetLDAPConfig()
	centralHasAD := centralLDAP != nil && (centralLDAP.Domain != "" || centralLDAP.BaseDN != "")
	sameAD := centralHasAD && b.SourceAD != nil && sameADDomain(b.SourceAD, centralLDAP)

	known := map[string]bool{}
	if cu, err := central.ListUsers(); err == nil {
		for _, u := range cu {
			if u.SAMAccountName != "" {
				known[u.SAMAccountName] = true
			}
		}
	}

	directPermUsers := 0
	adWithLocalPassword := 0
	for _, u := range b.Users {
		if len(u.DirectPerms) > 0 {
			directPermUsers++
		}
		if u.HadLocalPassword {
			adWithLocalPassword++
		}
		// Apply grants nothing for a user with no effective roles and does not even
		// materialize a local account for them, so the report must not count them as
		// migrating — preflight promised N and Apply delivered fewer, with nothing in
		// the report explaining the gap. The AD BLOCK checks below still run either
		// way: "the central cannot authenticate this person" is worth telling the
		// operator regardless of whether they happen to carry roles today.
		migrating := len(u.Roles) > 0
		if !migrating {
			r.NoRoles++
		}
		switch u.Kind {
		case KindLocal:
			if migrating {
				r.LocalUsers++
			}
		case KindAD:
			switch {
			case !centralHasAD:
				r.Blocked = append(r.Blocked, BlockedUser{Key: u.Key, Reason: "central is not connected to AD; cannot authenticate this user"})
			case !sameAD:
				r.Blocked = append(r.Blocked, BlockedUser{Key: u.Key, Reason: "central is on a different AD; key by UPN/email or connect the same AD"})
			default:
				if migrating {
					r.ADUsersSameDomain++
					if known[u.Key] {
						r.ADUsersKnown++
					}
				}
			}
		}
	}

	if directPermUsers > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d user(s) have direct (non-role) permissions that are NOT carried in this version — re-grant via roles on the target app", directPermUsers))
	}
	if r.NoRoles > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d user(s) carry no effective roles (no explicit role on the source and no default_roles) — they do NOT migrate: no assignment is written and no local account is created", r.NoRoles))
	}
	if adWithLocalPassword > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d AD user(s) also had a LOCAL password on the source; it is NOT carried — the central re-binds them from AD. Re-create any break-glass login deliberately on the central", adWithLocalPassword))
	}
	if b.SourceAD != nil && !centralHasAD {
		r.Notes = append(r.Notes, "source is AD-connected but the central is not — connect the central to the same AD to migrate AD users")
	}
	return r, nil
}

func sameADDomain(src *ADInfo, c *store.LDAPConfig) bool {
	if src.Domain != "" && c.Domain != "" {
		return strings.EqualFold(strings.TrimSpace(src.Domain), strings.TrimSpace(c.Domain))
	}
	if src.BaseDN != "" && c.BaseDN != "" {
		return strings.EqualFold(strings.TrimSpace(src.BaseDN), strings.TrimSpace(c.BaseDN))
	}
	return false
}

// ApplyResult summarizes a committed import.
type ApplyResult struct {
	AppUpdated        bool `json:"app_updated"`
	RolesDefined      int  `json:"roles_defined"`
	AssignmentsSet    int  `json:"assignments_set"`
	LocalUsersCreated int  `json:"local_users_created"`
	Skipped           int  `json:"skipped"`
}

// Apply imports the bundle into targetAppID on the central store. Additive, and
// idempotent for local users (an existing app-local username is left in place).
// carrySecret copies the source app's secret hash so the consumer's existing
// secret keeps working; pass false to keep the target app's own secret.
func Apply(b *Bundle, central store.Store, targetAppID, defaultAppID string, carrySecret bool) (*ApplyResult, error) {
	res := &ApplyResult{}

	app, err := central.GetApp(targetAppID)
	if err != nil {
		return nil, fmt.Errorf("target app: %w", err)
	}

	// Re-check the audience here, not only in Classify: Apply is reachable on its
	// own and the central's app set can change between preflight and commit. This
	// runs BEFORE the first write, so a refused bundle leaves nothing behind (H15).
	aud, conflict, err := resolveCarriedAudience(central, app, defaultAppID, b.App.Audience)
	if err != nil {
		return nil, err
	}
	if conflict != "" {
		return nil, fmt.Errorf("%s", conflict)
	}
	app.Audience = aud
	if len(b.App.RedirectURIs) > 0 {
		app.RedirectURIs = b.App.RedirectURIs
	}
	if len(b.App.CORSOrigins) > 0 {
		app.CORSOrigins = b.App.CORSOrigins
	}
	// Carry the SA-1 presentation metadata onto the target (additive; never blanks
	// an existing value the operator set on the target). The bundle comes from a
	// lower-trust source deployment, so re-run the SAME syntactic validation the
	// admin write path enforces — a stored base_url/icon must be a trusted
	// same-origin launch target regardless of which path wrote it. Invalid values
	// are skipped (never planted), not fatal to the migration.
	if b.App.BaseURL != "" {
		if nb, err := store.NormalizeBaseURL(b.App.BaseURL); err == nil {
			app.BaseURL = nb
		}
	}
	if len(b.App.DisplayName) > 0 {
		app.DisplayName = b.App.DisplayName
	}
	if b.App.Category != "" {
		app.Category = b.App.Category
	}
	if b.App.Icon != "" {
		if err := store.ValidateIconPath(b.App.Icon); err == nil {
			app.Icon = b.App.Icon
		}
	}
	// Never WEAKEN the target's access gate via a migration: OR-in only. A target
	// the operator deliberately created with require_assignment=true must not be
	// downgraded to open by a source home app that ran with it off.
	app.RequireAssignment = app.RequireAssignment || b.App.RequireAssignment
	if carrySecret && b.App.SecretHash != "" {
		app.SecretHash = b.App.SecretHash
	}
	for _, u := range b.Users {
		// Only for an entry Apply will actually materialize. A zero-role local
		// entry is skipped below, and Classify no longer counts it — opening the
		// target's local-login gate for a user that is never created would weaken
		// the app's authentication surface for nothing.
		if u.Kind == KindLocal && len(u.Roles) > 0 {
			app.AllowLocalUsers = true
			break
		}
	}
	if err := central.UpdateApp(app); err != nil {
		return nil, fmt.Errorf("update app: %w", err)
	}
	res.AppUpdated = true

	authz, _ := central.GetAppAuthz(targetAppID)
	if authz == nil {
		authz = &store.AppAuthz{AppID: targetAppID}
	}
	authz.AppID = targetAppID
	if b.Catalog.RolePermissions != nil {
		authz.RolePermissions = b.Catalog.RolePermissions
		authz.Roles = sortedKeys(b.Catalog.RolePermissions)
	}
	if len(b.Catalog.Permissions) > 0 {
		authz.Permissions = b.Catalog.Permissions
	}
	if authz.UserAssignments == nil {
		authz.UserAssignments = map[string][]string{}
	}
	res.RolesDefined = len(authz.Roles)

	mapKey := "applocal:" + targetAppID
	for _, u := range b.Users {
		if len(u.Roles) == 0 {
			res.Skipped++ // nothing to grant
			continue
		}
		if u.Kind == KindLocal {
			if existing, _ := central.ResolveMapping(mapKey, u.Key); existing == "" {
				nu := &store.User{OwnerAppID: targetAppID, DisplayName: u.DisplayName, Email: u.Email, PasswordHash: u.PasswordHash, CreatedAt: time.Now().UTC()}
				if err := central.CreateUser(nu); err != nil {
					return nil, fmt.Errorf("create local user %q: %w", u.Key, err)
				}
				if err := central.SetIdentityMapping(mapKey, u.Key, nu.GUID); err != nil {
					return nil, fmt.Errorf("map local user %q: %w", u.Key, err)
				}
				res.LocalUsersCreated++
			}
		}
		authz.UserAssignments[u.Key] = u.Roles
		res.AssignmentsSet++
	}

	if err := central.SaveAppAuthz(authz); err != nil {
		return nil, fmt.Errorf("save authz: %w", err)
	}
	return res, nil
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
