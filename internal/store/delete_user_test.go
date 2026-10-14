package store

import (
	"testing"

	bolt "go.etcd.io/bbolt"
)

// TestDeleteUserRemovesMappingsRolesAndPermissions is the M41 regression: a
// deleted user must not leave identity mappings, roles or direct permissions
// behind, so the same username can be provisioned again.
func TestDeleteUserRemovesMappingsRolesAndPermissions(t *testing.T) {
	s := openTestBolt(t, t.TempDir())
	u := &User{DisplayName: "Alice"}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.SetIdentityMapping("local", "alice", u.GUID); err != nil {
		t.Fatalf("map local: %v", err)
	}
	if err := s.SetIdentityMapping("ldap", "alice", u.GUID); err != nil {
		t.Fatalf("map ldap: %v", err)
	}
	if err := s.SetUserRoles(u.GUID, []string{"Analyst"}); err != nil {
		t.Fatalf("roles: %v", err)
	}
	if err := s.SetUserPermissions(u.GUID, []string{"reports:read"}); err != nil {
		t.Fatalf("permissions: %v", err)
	}

	if err := s.DeleteUser(u.GUID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	for _, p := range []string{"local", "ldap"} {
		if guid, err := s.ResolveMapping(p, "alice"); err == nil {
			t.Fatalf("%s:alice still resolves to %s after DeleteUser", p, guid)
		}
	}
	if claims := indexClaims(t, s, u.GUID); len(claims) != 0 {
		t.Fatalf("reverse index still holds %v", claims)
	}
	if roles, _ := s.GetUserRoles(u.GUID); len(roles) != 0 {
		t.Fatalf("roles survived: %v", roles)
	}
	if perms, _ := s.GetUserPermissions(u.GUID); len(perms) != 0 {
		t.Fatalf("permissions survived: %v", perms)
	}

	// The username is free again.
	u2 := &User{DisplayName: "Alice again"}
	if err := s.CreateUser(u2); err != nil {
		t.Fatalf("create again: %v", err)
	}
	if err := s.SetIdentityMapping("local", "alice", u2.GUID); err != nil {
		t.Fatalf("map again: %v", err)
	}
	if guid, err := s.ResolveMapping("local", "alice"); err != nil || guid != u2.GUID {
		t.Fatalf("local:alice = %q, %v; want %s", guid, err, u2.GUID)
	}
}

// TestDeleteUserKeepsMappingOwnedBySomeoneElse: if the reverse index ever claims
// a mapping that the forward bucket gives to another user, deleting the stale
// claimant must not delete the real owner's mapping (H14 applied to M41).
func TestDeleteUserKeepsMappingOwnedBySomeoneElse(t *testing.T) {
	s := openTestBolt(t, t.TempDir())
	stale := &User{DisplayName: "Stale"}
	owner := &User{DisplayName: "Owner"}
	for _, u := range []*User{stale, owner} {
		if err := s.CreateUser(u); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	if err := s.SetIdentityMapping("local", "erin", owner.GUID); err != nil {
		t.Fatalf("map: %v", err)
	}
	if err := s.update(func(tx *bolt.Tx) error {
		return s.addMappingToIndex(tx, stale.GUID, IdentityMapping{Provider: "local", ExternalID: "erin"})
	}); err != nil {
		t.Fatalf("inject stale claim: %v", err)
	}

	if err := s.DeleteUser(stale.GUID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if guid, err := s.ResolveMapping("local", "erin"); err != nil || guid != owner.GUID {
		t.Fatalf("local:erin = %q, %v; the owner's mapping must survive", guid, err)
	}
}

// danglingMappingStore creates a user mapped as local:<name>, then removes only
// the user row, as DeleteUser did before M41. It returns the store's directory
// and the deleted GUID; the store is closed.
func danglingMappingStore(t *testing.T, name string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	s := openTestBolt(t, dir)
	gone := &User{DisplayName: "Gone"}
	if err := s.CreateUser(gone); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.SetIdentityMapping("local", name, gone.GUID); err != nil {
		t.Fatalf("map: %v", err)
	}
	if err := s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUsers).Delete([]byte(gone.GUID))
	}); err != nil {
		t.Fatalf("simulate old delete: %v", err)
	}
	s.Close()
	return dir, gone.GUID
}

// TestDanglingMappingsReportOnlyByDefault: without the opt-in, opening the store
// reports a dangling mapping and leaves it in place. Removing it could let a
// deleted directory user sign in again.
func TestDanglingMappingsReportOnlyByDefault(t *testing.T) {
	dir, guid := danglingMappingStore(t, "ivan")
	s := openTestBolt(t, dir)
	if got, err := s.ResolveMapping("local", "ivan"); err != nil || got != guid {
		t.Fatalf("local:ivan = %q, %v; the default check must not write", got, err)
	}
}

// TestRepairDanglingMappingsOnOpen: with SA_REPAIR_DANGLING_MAPPINGS=1, mappings
// pointing at a deleted user are removed on open and live mappings are kept.
func TestRepairDanglingMappingsOnOpen(t *testing.T) {
	dir, guid := danglingMappingStore(t, "frank")
	s := openTestBolt(t, dir)
	live := &User{DisplayName: "Live"}
	if err := s.CreateUser(live); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.SetIdentityMapping("local", "grace", live.GUID); err != nil {
		t.Fatalf("map live: %v", err)
	}
	s.Close()

	t.Setenv("SA_REPAIR_DANGLING_MAPPINGS", "1")
	s2 := openTestBolt(t, dir)
	if got, err := s2.ResolveMapping("local", "frank"); err == nil {
		t.Fatalf("dangling local:frank -> %s survived the repair", got)
	}
	if claims := indexClaims(t, s2, guid); len(claims) != 0 {
		t.Fatalf("reverse index still holds %v for the deleted user", claims)
	}
	if got, err := s2.ResolveMapping("local", "grace"); err != nil || got != live.GUID {
		t.Fatalf("live local:grace = %q, %v; must be kept", got, err)
	}
}

// TestDanglingRepairRespectsSkipEnv: SA_SKIP_MAPPING_REPAIR=1 overrides the
// opt-in, so nothing is written.
func TestDanglingRepairRespectsSkipEnv(t *testing.T) {
	dir, guid := danglingMappingStore(t, "heidi")
	t.Setenv("SA_REPAIR_DANGLING_MAPPINGS", "1")
	t.Setenv("SA_SKIP_MAPPING_REPAIR", "1")
	s := openTestBolt(t, dir)
	if got, err := s.ResolveMapping("local", "heidi"); err != nil || got != guid {
		t.Fatalf("local:heidi = %q, %v; SA_SKIP_MAPPING_REPAIR=1 must not write", got, err)
	}
}

// TestRepairDanglingClearsLocalAssignment: when the opt-in repair removes an
// app-local mapping, it also clears the app's role assignment for that username,
// unless a live user can still match the name.
func TestRepairDanglingClearsLocalAssignment(t *testing.T) {
	dir := t.TempDir()
	s := openTestBolt(t, dir)
	gone1, gone2, live := &User{DisplayName: "Gone1"}, &User{DisplayName: "Gone2"}, &User{DisplayName: "Live"}
	for _, u := range []*User{gone1, gone2, live} {
		if err := s.CreateUser(u); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	for _, m := range []struct{ provider, name, guid string }{
		{"applocal:desk", "agent9", gone1.GUID},
		{"applocal:desk", "kim", gone2.GUID},
		{"local", "kim", live.GUID}, // a live user still matches "kim"
	} {
		if err := s.SetIdentityMapping(m.provider, m.name, m.guid); err != nil {
			t.Fatalf("map: %v", err)
		}
	}
	if err := s.SaveAppAuthz(&AppAuthz{AppID: "desk", UserAssignments: map[string][]string{
		"agent9": {"Supervisor"}, "kim": {"Viewer"},
	}}); err != nil {
		t.Fatalf("authz: %v", err)
	}
	if err := s.update(func(tx *bolt.Tx) error {
		for _, g := range []string{gone1.GUID, gone2.GUID} {
			if err := tx.Bucket(bucketUsers).Delete([]byte(g)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("simulate old delete: %v", err)
	}
	s.Close()

	t.Setenv("SA_REPAIR_DANGLING_MAPPINGS", "1")
	s2 := openTestBolt(t, dir)
	authz, err := s2.GetAppAuthz("desk")
	if err != nil {
		t.Fatalf("authz: %v", err)
	}
	if roles, ok := authz.UserAssignments["agent9"]; ok {
		t.Fatalf("stale assignment for agent9 survived: %v", roles)
	}
	if roles := authz.UserAssignments["kim"]; len(roles) != 1 {
		t.Fatalf("assignment for kim, which a live user matches, must be kept; got %v", roles)
	}
	if _, err := s2.ResolveMapping("applocal:desk", "kim"); err == nil {
		t.Fatal("dangling applocal:desk:kim survived the repair")
	}
}
