package handler

import (
	"net/http"
	"testing"

	"simpleauth/internal/store"
)

// seedDirectoryUser creates a user in the exact end state the LDAP/Kerberos JIT
// paths leave behind: empty PasswordHash, SAMAccountName set, and BOTH an "ldap"
// and a "local" identity mapping (auth.go creates both so future lookups by
// either name resolve).
func seedDirectoryUser(t *testing.T, s store.Store, username string) *store.User {
	t.Helper()
	u := &store.User{DisplayName: username, SAMAccountName: username}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create directory user: %v", err)
	}
	if err := s.SetIdentityMapping("ldap", username, u.GUID); err != nil {
		t.Fatalf("set ldap mapping: %v", err)
	}
	if err := s.SetIdentityMapping("local", username, u.GUID); err != nil {
		t.Fatalf("set local mapping: %v", err)
	}
	return u
}

// impersonationToken mints an access token for an arbitrary user via master-admin
// POST /api/auth/impersonate. There is no LDAP server in unit tests, so this is
// how a test obtains a bearer token for a directory-backed user — and it is also
// a faithful model of the threat: the attacker holds SOME token for the victim.
func impersonationToken(t *testing.T, h *Handler, guid string) map[string]string {
	t.Helper()
	w := doJSON(h, "POST", "/api/auth/impersonate", map[string]interface{}{
		"target_guid": guid,
	}, adminHeaders())
	if w.Code != http.StatusOK {
		t.Fatalf("impersonate: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("impersonate returned no access_token: %v", tok)
	}
	return map[string]string{"Authorization": "Bearer " + access}
}

// TestResetPasswordRefusesDirectoryUser is the SA-7 regression, driven as the
// full exploit chain: plant, then try to use.
//
// Before the fix, `PasswordHash != "" && !ForcePasswordChange` skipped the entire
// proof-of-possession block for any user with an empty hash — the state of every
// directory user — so a bearer token alone wrote a permanent local bcrypt hash
// onto an AD-backed record. authenticateUser resolves the "local" mapping FIRST,
// so that hash then outlives AD disablement and account termination.
func TestResetPasswordRefusesDirectoryUser(t *testing.T) {
	h, s := testSetup(t)
	victim := seedDirectoryUser(t, s, "alice")
	bearer := impersonationToken(t, h, victim.GUID)

	// The plant: no current_password, because there is no local password to prove.
	w := doJSON(h, "POST", "/api/auth/reset-password", map[string]interface{}{
		"new_password": "Attacker1!",
	}, bearer)
	if w.Code != http.StatusForbidden {
		t.Fatalf("planting a local password on a directory user must be 403, got %d %s", w.Code, w.Body.String())
	}

	// Nothing was written.
	after, err := s.GetUser(victim.GUID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.PasswordHash != "" {
		t.Fatal("a local password hash was written to a directory-backed user (SA-7)")
	}

	// And the credential does not work — the part that actually matters.
	lw := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "alice", "password": "Attacker1!",
	}, nil)
	if lw.Code == http.StatusOK {
		t.Fatal("planted credential authenticated — the shadow credential survived (SA-7)")
	}
}

// TestResetPasswordRefusesAccountWithNoLocalPassword covers the other empty-hash
// case: an admin-created account that never had a password. Such a user can never
// log in (authenticateUser requires a non-empty hash), so there is no legitimate
// first-time-set flow through this endpoint to protect.
func TestResetPasswordRefusesAccountWithNoLocalPassword(t *testing.T) {
	h, s := testSetup(t)
	u := &store.User{DisplayName: "No Password"}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.SetIdentityMapping("local", "nopass", u.GUID); err != nil {
		t.Fatalf("map: %v", err)
	}
	bearer := impersonationToken(t, h, u.GUID)

	w := doJSON(h, "POST", "/api/auth/reset-password", map[string]interface{}{
		"new_password": "Whatever1!",
	}, bearer)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for an account with no local password, got %d %s", w.Code, w.Body.String())
	}
}

// TestResetPasswordLocalUserStillWorks is the most important not-broken test in
// this change: a genuine local user must still rotate their own password with
// proof of possession, and must still be refused without it.
func TestResetPasswordLocalUserStillWorks(t *testing.T) {
	h, s := testSetup(t)
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Local Larry", "password": "oldpass1",
	}, adminHeaders())
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var u map[string]interface{}
	parseJSON(t, w, &u)
	guid := u["guid"].(string)
	if err := s.SetIdentityMapping("local", "larry", guid); err != nil {
		t.Fatalf("map: %v", err)
	}

	lw := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "larry", "password": "oldpass1",
	}, nil)
	if lw.Code != http.StatusOK {
		t.Fatalf("login: %d %s", lw.Code, lw.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, lw, &tok)
	bearer := map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)}

	// Without current_password -> 400, unchanged behaviour.
	if w := doJSON(h, "POST", "/api/auth/reset-password", map[string]interface{}{
		"new_password": "newpass1",
	}, bearer); w.Code != http.StatusBadRequest {
		t.Fatalf("local user without current_password must be 400, got %d %s", w.Code, w.Body.String())
	}
	// Wrong current_password -> 403.
	if w := doJSON(h, "POST", "/api/auth/reset-password", map[string]interface{}{
		"current_password": "wrong", "new_password": "newpass1",
	}, bearer); w.Code != http.StatusForbidden {
		t.Fatalf("wrong current_password must be 403, got %d", w.Code)
	}
	// Correct current_password -> 200, and the new password works.
	if w := doJSON(h, "POST", "/api/auth/reset-password", map[string]interface{}{
		"current_password": "oldpass1", "new_password": "newpass1",
	}, bearer); w.Code != http.StatusOK {
		t.Fatalf("valid rotation must succeed, got %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "larry", "password": "newpass1",
	}, nil); w.Code != http.StatusOK {
		t.Fatalf("rotated password must authenticate, got %d", w.Code)
	}
}

// TestResetPasswordForceChangeStillWorks pins the admin temp-password flow. The
// whole safety of putting the empty-hash gate AHEAD of the force-change branch
// rests on ForcePasswordChange never coexisting with an empty hash — admin.go
// writes a real hash immediately before setting the flag. This asserts it.
func TestResetPasswordForceChangeStillWorks(t *testing.T) {
	h, s := testSetup(t)
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Temp Tina", "password": "temppass1",
	}, adminHeaders())
	var u map[string]interface{}
	parseJSON(t, w, &u)
	guid := u["guid"].(string)
	if err := s.SetIdentityMapping("local", "tina", guid); err != nil {
		t.Fatalf("map: %v", err)
	}

	// Admin sets a temp password with force_change.
	if w := doJSON(h, "PUT", "/api/admin/users/"+guid+"/password", map[string]interface{}{
		"password": "temppass2", "force_change": true,
	}, adminHeaders()); w.Code != http.StatusOK {
		t.Fatalf("admin set password: %d %s", w.Code, w.Body.String())
	}
	su, err := s.GetUser(guid)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if su.PasswordHash == "" {
		t.Fatal("invariant broken: ForcePasswordChange set with an EMPTY hash — the empty-hash gate would break this flow")
	}

	lw := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "tina", "password": "temppass2",
	}, nil)
	if lw.Code != http.StatusOK {
		t.Fatalf("login with temp password: %d %s", lw.Code, lw.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, lw, &tok)
	bearer := map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)}

	// The point: change WITHOUT re-typing the temp password must still work.
	if w := doJSON(h, "POST", "/api/auth/reset-password", map[string]interface{}{
		"new_password": "chosen99",
	}, bearer); w.Code != http.StatusOK {
		t.Fatalf("force-change flow must not require current_password, got %d %s", w.Code, w.Body.String())
	}
}

// TestIsDirectoryBackedClassification pins the predicate itself, including the
// app-local carve-out that a naive `provider != "local"` test would get wrong.
func TestIsDirectoryBackedClassification(t *testing.T) {
	h, s := testSetup(t)

	mk := func(name string, u *store.User, provider string) *store.User {
		t.Helper()
		if err := s.CreateUser(u); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if provider != "" {
			if err := s.SetIdentityMapping(provider, name, u.GUID); err != nil {
				t.Fatalf("map %s: %v", name, err)
			}
		}
		return u
	}

	cases := []struct {
		name string
		user *store.User
		prov string
		want bool
	}{
		{"plain local user", &store.User{DisplayName: "L"}, "local", false},
		{"app-local user", &store.User{DisplayName: "A", OwnerAppID: "billing"}, "applocal:billing", false},
		{"ldap-mapped, no SAMAccountName (import path)", &store.User{DisplayName: "I"}, "ldap", true},
		{"SAMAccountName set", &store.User{DisplayName: "S", SAMAccountName: "sam"}, "local", true},
		{"kerberos-mapped", &store.User{DisplayName: "K"}, "kerberos", true},
		// An app-local user whose OwnerAppID wins over a SAMAccountName that should
		// never be there — the short-circuit must be exact, not best-effort.
		{"app-local beats stray SAMAccountName", &store.User{DisplayName: "X", OwnerAppID: "shop", SAMAccountName: "stray"}, "applocal:shop", false},
	}
	for _, tc := range cases {
		u := mk(tc.name, tc.user, tc.prov)
		if got := h.isDirectoryBacked(u); got != tc.want {
			t.Errorf("%s: isDirectoryBacked = %v, want %v", tc.name, got, tc.want)
		}
	}
}
