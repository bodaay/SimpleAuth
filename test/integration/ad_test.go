//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"

	"simpleauth/internal/migrate"
)

// ldapConfig builds the SimpleAuth LDAP config payload. username_attr=uid means
// User.SAMAccountName is populated from `uid` — so vanilla OpenLDAP works and the
// migration (which keys on sAMAccountName) sees the uid value.
func ldapConfig(url, baseDN, domain string) map[string]any {
	return map[string]any{
		"url": url, "base_dn": baseDN, "bind_dn": "cn=admin," + baseDN,
		"bind_password": "adminpw", "username_attr": "uid",
		"display_name_attr": "cn", "email_attr": "mail", "groups_attr": "memberOf",
		"use_tls": false, "allow_insecure": true, "domain": domain,
	}
}

// corpLDAPConfig is the shared corp.local directory (see ldap/corp.ldif for the
// seeded users and groups).
func corpLDAPConfig() map[string]any {
	return ldapConfig("ldap://ldap-corp:389", "dc=corp,dc=local", "corp.local")
}

// loginRetry retries an LDAP login until it succeeds (OpenLDAP takes a while to
// bootstrap its seed LDIF on first boot) and returns the access token.
func loginRetry(t *testing.T, n *node, username, password, appID string) string {
	t.Helper()
	body := map[string]any{"username": username, "password": password}
	if appID != "" {
		body["app_id"] = appID
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		code, data := n.do(t, "POST", "/api/auth/login", body)
		if code == http.StatusOK {
			var r struct {
				AccessToken string `json:"access_token"`
			}
			decode(t, data, &r)
			return r.AccessToken
		}
		if time.Now().After(deadline) {
			t.Fatalf("login %q never succeeded (last %d: %s)", username, code, data)
		}
		time.Sleep(3 * time.Second)
	}
}

func findGUIDBySAM(t *testing.T, n *node, sam string) string {
	t.Helper()
	var users []struct {
		GUID string `json:"guid"`
		SAM  string `json:"sam_account_name"`
	}
	decode(t, n.must(t, "GET", "/api/admin/users", nil), &users)
	for _, u := range users {
		if u.SAM == sam {
			return u.GUID
		}
	}
	t.Fatalf("user with sAMAccountName=%q not found on %s", sam, n.base)
	return ""
}

// TestADMigrationScenarios covers the AD half of the matrix against real
// OpenLDAP directories: a same-AD policy-only migration (AD user re-binds on the
// central), a different-AD migration that is blocked at preflight, and an app
// registered directly on the central.
func TestADMigrationScenarios(t *testing.T) {
	central := &node{centralURL, centralKey, caClient()}
	sAD := &node{standaloneADURL, standaloneADKey, &http.Client{Timeout: 20 * time.Second}}
	sDiff := &node{env("ITEST_STANDALONE_ADDIFF_URL", "http://127.0.0.1:9446"), "addiff-admin-key", &http.Client{Timeout: 20 * time.Second}}

	waitReady(t, "central", centralURL, central.c)
	waitReady(t, "standalone-ad", sAD.base, sAD.c)
	waitReady(t, "standalone-addiff", sDiff.base, sDiff.c)

	// central + standalone-ad share corp.local; standalone-addiff is on other.local.
	central.must(t, "PUT", "/api/admin/ldap", corpLDAPConfig())
	sAD.must(t, "PUT", "/api/admin/ldap", corpLDAPConfig())
	sDiff.must(t, "PUT", "/api/admin/ldap", ldapConfig("ldap://ldap-other:389", "dc=other,dc=local", "other.local"))

	t.Run("same_ad_policy_migration", func(t *testing.T) {
		sAD.must(t, "PUT", "/api/admin/permissions", []string{"hr:read", "hr:write"})
		sAD.must(t, "PUT", "/api/admin/role-permissions", map[string][]string{"editor": {"hr:read", "hr:write"}})

		// bob (AD) logs into the standalone -> JIT-provisioned; give him a role.
		loginRetry(t, sAD, "bob", "bobpass", "")
		bob := findGUIDBySAM(t, sAD, "bob")
		sAD.must(t, "PUT", "/api/admin/users/"+bob+"/roles", []string{"editor"})

		mig := newMigTargetFrom(t, central, sAD, "hr", true)

		// Policy-only: an AD user, no local-user record/password is copied.
		var rep migrate.Report
		decode(t, sAD.must(t, "POST", "/api/admin/migrate-to-central/preflight", mig), &rep)
		if !rep.OK() || rep.ADUsersSameDomain != 1 || rep.LocalUsers != 0 {
			t.Fatalf("preflight: want 1 same-AD user, 0 local, none blocked; got %+v", rep)
		}
		var res migrate.ApplyResult
		decode(t, sAD.must(t, "POST", "/api/admin/migrate-to-central/commit", mig), &res)
		if res.AssignmentsSet != 1 || res.LocalUsersCreated != 0 {
			t.Fatalf("commit (policy-only) result: %+v", res)
		}

		var az struct {
			UserAssignments map[string][]string `json:"user_assignments"`
		}
		decode(t, central.must(t, "GET", "/api/admin/apps/hr/authz", nil), &az)
		if got := az.UserAssignments["bob"]; len(got) != 1 || got[0] != "editor" {
			t.Fatalf("central hr assignment for bob = %v, want [editor]", got)
		}

		// bob RE-BINDS from the SAME AD on the central and resolves his migrated role.
		roles, perms, _ := tokenClaims(t, loginRetry(t, central, "bob", "bobpass", "hr"))
		if !has(roles, "editor") || !has(perms, "hr:write") {
			t.Fatalf("central hr token roles=%v perms=%v, want editor/hr:write", roles, perms)
		}
		t.Logf("OK same-AD: bob migrated policy-only, re-binds on central roles=%v perms=%v", roles, perms)
	})

	t.Run("different_ad_blocked", func(t *testing.T) {
		sDiff.must(t, "PUT", "/api/admin/role-permissions", map[string][]string{"viewer": {}})
		loginRetry(t, sDiff, "carol", "carolpass", "")
		carol := findGUIDBySAM(t, sDiff, "carol")
		sDiff.must(t, "PUT", "/api/admin/users/"+carol+"/roles", []string{"viewer"})

		mig := newMigTargetFrom(t, central, sDiff, "diffapp", false)

		var rep migrate.Report
		decode(t, sDiff.must(t, "POST", "/api/admin/migrate-to-central/preflight", mig), &rep)
		if rep.OK() {
			t.Fatalf("different-AD must block carol at preflight; got %+v", rep)
		}
		// And commit is refused (the central re-runs the classifier).
		if code, data := sDiff.do(t, "POST", "/api/admin/migrate-to-central/commit", mig); code != http.StatusConflict {
			t.Fatalf("different-AD commit must be 409, got %d: %s", code, data)
		}
		t.Logf("OK different-AD: carol blocked at preflight + commit (%d blocked)", len(rep.Blocked))
	})

	t.Run("direct_app_on_central", func(t *testing.T) {
		central.must(t, "POST", "/api/admin/apps", map[string]any{"app_id": "portal", "audience": "portal"})
		central.must(t, "PUT", "/api/admin/apps/portal/authz", map[string]any{
			"roles":            []string{"viewer"},
			"role_permissions": map[string][]string{"viewer": {"portal:read"}},
			"user_assignments": map[string][]string{"bob": {"viewer"}},
		})
		// bob (corp AD) authenticates DIRECTLY against the central for portal.
		roles, perms, aud := tokenClaims(t, loginRetry(t, central, "bob", "bobpass", "portal"))
		if !has(roles, "viewer") || !has(perms, "portal:read") || !has(aud, "portal") {
			t.Fatalf("direct portal token roles=%v perms=%v aud=%v", roles, perms, aud)
		}
		t.Logf("OK direct: bob authenticates directly on central for portal roles=%v", roles)
	})
}
