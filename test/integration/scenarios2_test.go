//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"

	"simpleauth/internal/migrate"
)

// TestMoreScenarios extends the matrix: the seamless-secret round-trip, the
// central-not-on-AD block, the live security guards (single-use token +
// fresh-target), and a mixed AD+local population migrating in one shot.
func TestMoreScenarios(t *testing.T) {
	central := &node{centralURL, centralKey, caClient()}
	local := &node{standaloneURL, standaloneKey, &http.Client{Timeout: 20 * time.Second}}
	sAD := &node{standaloneADURL, standaloneADKey, &http.Client{Timeout: 20 * time.Second}}

	waitReady(t, "central", centralURL, central.c)
	waitReady(t, "standalone-local", local.base, local.c)
	waitReady(t, "standalone-ad", sAD.base, sAD.c)

	corpCfg := corpLDAPConfig()
	central.must(t, "PUT", "/api/admin/ldap", corpCfg)
	sAD.must(t, "PUT", "/api/admin/ldap", corpCfg)

	// The consumer app keeps its OWN secret after cutover: carry_secret moves the
	// source home app's secret hash, so the same secret authenticates on the central.
	t.Run("carry_secret_roundtrip", func(t *testing.T) {
		var rot struct {
			Secret string `json:"app_secret"`
		}
		decode(t, local.must(t, "POST", "/api/admin/apps/simpleauth/rotate-secret", nil), &rot)
		if rot.Secret == "" {
			t.Fatal("no rotated secret")
		}
		mig := newMigTargetFrom(t, central, local, "secretapp", true)
		local.must(t, "POST", "/api/admin/migrate-to-central/commit", mig)

		if code, data := central.doBasic(t, "POST", "/api/app/token", "secretapp", rot.Secret); code != http.StatusOK {
			t.Fatalf("carried secret must authenticate on the central, got %d: %s", code, data)
		}
		if code, _ := central.doBasic(t, "POST", "/api/app/token", "secretapp", "wrong-secret"); code != http.StatusUnauthorized {
			t.Fatalf("a wrong secret must be rejected (401), got %d", code)
		}
		t.Log("OK carry_secret: the consumer's original secret authenticates the migrated central app")
	})

	// An AD standalone cannot migrate into a central that has no AD.
	t.Run("central_not_on_ad", func(t *testing.T) {
		loginRetry(t, sAD, "bob", "bobpass", "") // JIT-provision bob on the standalone

		central.must(t, "DELETE", "/api/admin/ldap", nil)
		t.Cleanup(func() { central.must(t, "PUT", "/api/admin/ldap", corpCfg) })

		mig := newMigTargetFrom(t, central, sAD, "noad", false)
		var rep migrate.Report
		decode(t, sAD.must(t, "POST", "/api/admin/migrate-to-central/preflight", mig), &rep)
		if rep.OK() {
			t.Fatalf("AD users must be blocked when the central has no AD; got %+v", rep)
		}
		t.Logf("OK central_not_on_ad: %d AD user(s) blocked", len(rep.Blocked))
	})

	// The cross-install security guards: single-use token + fresh-target.
	t.Run("migration_guards", func(t *testing.T) {
		local.must(t, "PUT", "/api/admin/role-permissions", map[string][]string{"r": {}}) // ensure the bundle carries some authz
		mig := newMigTargetFrom(t, central, local, "guardapp", false)

		local.must(t, "POST", "/api/admin/migrate-to-central/commit", mig) // first commit OK
		if code, _ := local.do(t, "POST", "/api/admin/migrate-to-central/commit", mig); code != http.StatusUnauthorized {
			t.Fatalf("a reused single-use token must be 401, got %d", code)
		}
		// A brand-new token cannot re-migrate into the now-populated app.
		mig2 := migPayload(t, central, "guardapp", false)
		var rep migrate.Report
		decode(t, local.must(t, "POST", "/api/admin/migrate-to-central/preflight", mig2), &rep)
		if rep.OK() {
			t.Fatalf("fresh-target guard must block migrating into a non-empty app; got %+v", rep)
		}
		t.Log("OK migration_guards: token single-use + fresh-target enforced across containers")
	})

	// A standalone with BOTH an AD user and a local break-glass account: the AD
	// user migrates policy-only, the local one carries its hash — in one bundle.
	// (Local-user hashes are always carried; carry_secret only affects the app secret.)
	t.Run("mixed_population", func(t *testing.T) {
		central.must(t, "PUT", "/api/admin/ldap", corpCfg) // don't depend on central_not_on_ad's restore

		sAD.must(t, "PUT", "/api/admin/permissions", []string{"x:read", "x:write"})
		sAD.must(t, "PUT", "/api/admin/role-permissions", map[string][]string{"editor": {"x:write"}, "ops": {"x:read"}})
		loginRetry(t, sAD, "bob", "bobpass", "")
		bob := findGUIDBySAM(t, sAD, "bob")
		sAD.must(t, "PUT", "/api/admin/users/"+bob+"/roles", []string{"editor"})
		var bg struct {
			GUID string `json:"guid"`
		}
		decode(t, sAD.must(t, "POST", "/api/admin/users", map[string]any{"display_name": "Breakglass", "password": "bgpass123"}), &bg)
		if bg.GUID == "" {
			t.Fatal("no guid for the break-glass user")
		}
		t.Cleanup(func() {
			// Remove the break-glass user so the other test functions still see a
			// standalone-ad with zero local users, whatever order the tests run in.
			if code, data := sAD.do(t, "DELETE", "/api/admin/users/"+bg.GUID, nil); code < 200 || code >= 300 {
				t.Errorf("cleanup: delete break-glass user -> %d: %s", code, data)
			}
		})
		sAD.must(t, "PUT", "/api/admin/users/"+bg.GUID+"/mappings", map[string]any{"provider": "local", "external_id": "breakglass"})
		sAD.must(t, "PUT", "/api/admin/users/"+bg.GUID+"/roles", []string{"ops"})

		mig := newMigTargetFrom(t, central, sAD, "mixedapp", false)

		var rep migrate.Report
		decode(t, sAD.must(t, "POST", "/api/admin/migrate-to-central/preflight", mig), &rep)
		if !rep.OK() || rep.ADUsersSameDomain != 1 || rep.LocalUsers != 1 {
			t.Fatalf("mixed preflight: want 1 AD + 1 local, none blocked; got %+v", rep)
		}
		var res migrate.ApplyResult
		decode(t, sAD.must(t, "POST", "/api/admin/migrate-to-central/commit", mig), &res)
		if res.LocalUsersCreated != 1 {
			t.Fatalf("mixed: want exactly the break-glass user materialized; got %+v", res)
		}

		// AD user re-binds from AD; local break-glass uses its carried hash (its
		// login is deterministic, so a single attempt — no LDAP bootstrap to absorb).
		if rb, _, _ := tokenClaims(t, loginRetry(t, central, "bob", "bobpass", "mixedapp")); !has(rb, "editor") {
			t.Fatalf("bob (AD) on central roles = %v, want editor", rb)
		}
		if rl, _, _ := tokenClaims(t, login(t, central, "breakglass", "bgpass123", "mixedapp")); !has(rl, "ops") {
			t.Fatalf("break-glass (local) on central roles = %v, want ops", rl)
		}
		t.Log("OK mixed_population: AD (policy-only) + local (carried hash) migrated together; both authenticate on central")
	})

	// An AD user gets a role on a central app purely via GROUP membership (no
	// per-user assignment) — bob is in the Finance group (see ldap/corp.ldif).
	// His memberOf is the DN-shaped value real AD emits; SimpleAuth extracts the
	// CN, so the assignment is keyed by the bare group name.
	t.Run("group_to_role", func(t *testing.T) {
		central.must(t, "PUT", "/api/admin/ldap", corpCfg) // don't depend on central_not_on_ad's restore

		central.must(t, "POST", "/api/admin/apps", map[string]any{"app_id": "fin", "audience": "fin"})
		central.must(t, "PUT", "/api/admin/apps/fin/authz", map[string]any{
			"roles":             []string{"analyst"},
			"role_permissions":  map[string][]string{"analyst": {"fin:read"}},
			"group_assignments": map[string][]string{"Finance": {"analyst"}},
		})
		roles, perms, _ := tokenClaims(t, loginRetry(t, central, "bob", "bobpass", "fin"))
		if !has(roles, "analyst") || !has(perms, "fin:read") {
			t.Fatalf("group->role: bob via Finance should be analyst/fin:read; got roles=%v perms=%v", roles, perms)
		}
		t.Log("OK group_to_role: bob gets 'analyst' on central via Finance group membership (no per-user assignment)")
	})
}
