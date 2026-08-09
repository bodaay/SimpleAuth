package migrate

import (
	"testing"

	"simpleauth/internal/store"
)

func open(t *testing.T) store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seedSource builds a standalone, AD-connected source: catalog + default_roles +
// a home app + two AD users (one explicit-role, one default-role) + one local user.
func seedSource(t *testing.T) store.Store {
	t.Helper()
	s := open(t)
	must(t, s.SaveLDAPConfig(&store.LDAPConfig{Domain: "corp.local", BaseDN: "dc=corp,dc=local"}))
	must(t, s.SetDefinedPermissions([]string{"invoice:read", "invoice:write"}))
	must(t, s.SetRolePermissions(map[string][]string{"admin": {"invoice:write"}, "viewer": {"invoice:read"}}))
	must(t, s.SetDefaultRoles([]string{"viewer"}))
	must(t, s.CreateApp(&store.App{
		AppID: "simpleauth", Audience: "simpleauth-aud",
		RedirectURIs: []string{"https://app.example/callback"},
		CORSOrigins:  []string{"https://app.example"},
		SecretHash:   "carried-secret-hash",
	}))

	// AD user with an explicit role + a direct permission.
	must(t, s.CreateUser(&store.User{GUID: "g-ada", DisplayName: "Ada", SAMAccountName: "ada"}))
	must(t, s.SetUserRoles("g-ada", []string{"admin"}))
	must(t, s.SetUserPermissions("g-ada", []string{"invoice:read"}))
	// AD user with NO explicit role -> effective = default_roles.
	must(t, s.CreateUser(&store.User{GUID: "g-new", DisplayName: "Newbie", SAMAccountName: "newbie"}))
	// Local user with a password hash + a local mapping.
	must(t, s.CreateUser(&store.User{GUID: "g-loc", DisplayName: "Loc", Email: "loc@x", PasswordHash: "loc-hash"}))
	must(t, s.SetIdentityMapping("local", "loc", "g-loc"))
	must(t, s.SetUserRoles("g-loc", []string{"viewer"}))
	return s
}

func TestPackageClassifyApply_SameAD(t *testing.T) {
	src := seedSource(t)
	b, err := Package(src, "simpleauth", "2.2.0-test")
	if err != nil {
		t.Fatalf("package: %v", err)
	}

	// Bundle captured AD binding, app config, catalog, 3 classified users.
	if b.SourceAD == nil || b.SourceAD.Domain != "corp.local" {
		t.Fatalf("source AD not captured: %+v", b.SourceAD)
	}
	if b.App.Audience != "simpleauth-aud" || b.App.SecretHash != "carried-secret-hash" || len(b.App.RedirectURIs) != 1 {
		t.Fatalf("app config not captured: %+v", b.App)
	}
	if len(b.Users) != 3 {
		t.Fatalf("want 3 users, got %d: %+v", len(b.Users), b.Users)
	}
	byKey := map[string]UserEntry{}
	for _, u := range b.Users {
		byKey[u.Key] = u
	}
	if e := byKey["ada"]; e.Kind != KindAD || len(e.Roles) != 1 || e.Roles[0] != "admin" || len(e.DirectPerms) != 1 {
		t.Fatalf("ada entry wrong: %+v", e)
	}
	if e := byKey["newbie"]; e.Kind != KindAD || len(e.Roles) != 1 || e.Roles[0] != "viewer" { // default_roles
		t.Fatalf("newbie effective roles should be [viewer] from defaults: %+v", e)
	}
	if e := byKey["loc"]; e.Kind != KindLocal || e.PasswordHash != "loc-hash" {
		t.Fatalf("loc entry wrong: %+v", e)
	}

	// Central on the SAME AD, with an empty target app.
	central := open(t)
	must(t, central.SaveLDAPConfig(&store.LDAPConfig{Domain: "corp.local"}))
	must(t, central.CreateApp(&store.App{AppID: "billing", Audience: "billing"}))

	rep, err := Classify(b, central, "billing", "simpleauth")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("should be no blocked users on same AD: %+v", rep.Blocked)
	}
	if rep.ADUsersSameDomain != 2 || rep.LocalUsers != 1 {
		t.Fatalf("report counts wrong: %+v", rep)
	}
	if len(rep.Notes) == 0 { // the direct-perm note
		t.Fatalf("expected a direct-perm note")
	}

	res, err := Apply(b, central, "billing", "simpleauth", true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.LocalUsersCreated != 1 || res.AssignmentsSet != 3 {
		t.Fatalf("apply result wrong: %+v", res)
	}

	// Target app carried config + allow_local_users.
	app, _ := central.GetApp("billing")
	if app.Audience != "simpleauth-aud" || app.SecretHash != "carried-secret-hash" || !app.AllowLocalUsers || len(app.RedirectURIs) != 1 {
		t.Fatalf("target app config not carried: %+v", app)
	}
	// Authz: assignments keyed by SAM / username, role->perm carried.
	authz, _ := central.GetAppAuthz("billing")
	if got := authz.UserAssignments["ada"]; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("ada assignment: %v", got)
	}
	if got := authz.UserAssignments["newbie"]; len(got) != 1 || got[0] != "viewer" {
		t.Fatalf("newbie assignment: %v", got)
	}
	if got := authz.UserAssignments["loc"]; len(got) != 1 || got[0] != "viewer" {
		t.Fatalf("loc assignment: %v", got)
	}
	if len(authz.RolePermissions) != 2 {
		t.Fatalf("role->perm not carried: %+v", authz.RolePermissions)
	}
	// Local user materialized with the carried hash (so the same password works).
	guid, err := central.ResolveMapping("applocal:billing", "loc")
	if err != nil || guid == "" {
		t.Fatalf("local user not materialized: %v", err)
	}
	if cu, _ := central.GetUser(guid); cu == nil || cu.PasswordHash != "loc-hash" || cu.OwnerAppID != "billing" {
		t.Fatalf("local user record wrong: %+v", cu)
	}

	// Idempotent re-apply: no second local user, assignments unchanged.
	res2, err := Apply(b, central, "billing", "simpleauth", true)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if res2.LocalUsersCreated != 0 {
		t.Fatalf("re-apply must not recreate local users, got %+v", res2)
	}
}

func TestClassify_CentralNotOnAD_BlocksADUsers(t *testing.T) {
	src := seedSource(t)
	b, err := Package(src, "simpleauth", "2.2.0-test")
	if err != nil {
		t.Fatalf("package: %v", err)
	}

	central := open(t) // NO LDAP configured
	must(t, central.CreateApp(&store.App{AppID: "billing", Audience: "billing"}))

	rep, err := Classify(b, central, "billing", "simpleauth")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if rep.OK() {
		t.Fatalf("AD users must be blocked when central has no AD")
	}
	if len(rep.Blocked) != 2 { // ada + newbie
		t.Fatalf("want 2 blocked AD users, got %d: %+v", len(rep.Blocked), rep.Blocked)
	}
	if rep.LocalUsers != 1 {
		t.Fatalf("local user should still be OK, got %+v", rep)
	}
}

func TestClassify_DifferentAD_BlocksADUsers(t *testing.T) {
	src := seedSource(t)
	b, _ := Package(src, "simpleauth", "2.2.0-test")

	central := open(t)
	must(t, central.SaveLDAPConfig(&store.LDAPConfig{Domain: "other.local"})) // different AD
	must(t, central.CreateApp(&store.App{AppID: "billing", Audience: "billing"}))

	rep, _ := Classify(b, central, "billing", "simpleauth")
	if rep.OK() || len(rep.Blocked) != 2 {
		t.Fatalf("different-AD must block the 2 AD users: %+v", rep.Blocked)
	}
}

// TestApply_DoesNotDowngradeRequireAssignment: a source home app with the gate
// OFF must not relax a target the operator deliberately locked down.
func TestApply_DoesNotDowngradeRequireAssignment(t *testing.T) {
	central := open(t)
	must(t, central.CreateApp(&store.App{AppID: "payroll", Audience: "payroll", RequireAssignment: true}))
	b := &Bundle{SchemaRev: SchemaRev, App: AppConfig{RequireAssignment: false}}
	if _, err := Apply(b, central, "payroll", "simpleauth", false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if app, _ := central.GetApp("payroll"); !app.RequireAssignment {
		t.Fatal("migration must not downgrade require_assignment from true to false")
	}
}

// TestApply_ValidatesPresentationFields: a bundle from a lower-trust source must
// not plant an unvalidated launch target. An invalid base_url/icon (which the
// admin write path would reject) is skipped on import; a valid one carries.
func TestApply_ValidatesPresentationFields(t *testing.T) {
	central := open(t)
	must(t, central.CreateApp(&store.App{AppID: "portal", Audience: "portal"}))
	// A malicious bundle: non-https phishing origin + an off-origin icon.
	bad := &Bundle{SchemaRev: SchemaRev, App: AppConfig{
		BaseURL: "http://evil.example", Icon: "../../evil",
	}}
	if _, err := Apply(bad, central, "portal", "simpleauth", false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if app, _ := central.GetApp("portal"); app.BaseURL != "" || app.Icon != "" {
		t.Fatalf("invalid base_url/icon must be skipped, got base_url=%q icon=%q", app.BaseURL, app.Icon)
	}

	// A valid bundle carries (and normalizes) the values.
	must(t, central.CreateApp(&store.App{AppID: "portal2", Audience: "portal2"}))
	good := &Bundle{SchemaRev: SchemaRev, App: AppConfig{
		BaseURL: "https://portal.example.com/", Icon: "/icon.svg",
	}}
	if _, err := Apply(good, central, "portal2", "simpleauth", false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if app, _ := central.GetApp("portal2"); app.BaseURL != "https://portal.example.com" || app.Icon != "/icon.svg" {
		t.Fatalf("valid base_url/icon must carry normalized, got base_url=%q icon=%q", app.BaseURL, app.Icon)
	}
}

// TestClassify_FreshTargetGuard: refuse to migrate into an app that already has
// per-app authorization (would clobber an in-use app).
func TestClassify_FreshTargetGuard(t *testing.T) {
	central := open(t)
	must(t, central.CreateApp(&store.App{AppID: "billing", Audience: "billing"}))
	must(t, central.SaveAppAuthz(&store.AppAuthz{AppID: "billing", UserAssignments: map[string][]string{"x": {"r"}}}))
	b := &Bundle{SchemaRev: SchemaRev, Users: []UserEntry{{Kind: KindLocal, Key: "bob", Roles: []string{"r"}, PasswordHash: "h"}}}
	rep, _ := Classify(b, central, "billing", "simpleauth")
	if rep.OK() {
		t.Fatal("classify must block a non-empty target app")
	}
}

// TestClassify_FreshTargetGuard_Groups: a target configured with only GROUP
// assignments (no user assignments) is still in-use and must be protected.
func TestClassify_FreshTargetGuard_Groups(t *testing.T) {
	central := open(t)
	must(t, central.CreateApp(&store.App{AppID: "billing", Audience: "billing"}))
	must(t, central.SaveAppAuthz(&store.AppAuthz{AppID: "billing", GroupAssignments: map[string][]string{"Finance": {"viewer"}}}))
	b := &Bundle{SchemaRev: SchemaRev, Users: []UserEntry{{Kind: KindLocal, Key: "bob", Roles: []string{"r"}, PasswordHash: "h"}}}
	rep, _ := Classify(b, central, "billing", "simpleauth")
	if rep.OK() {
		t.Fatal("classify must block a target that has group assignments")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
