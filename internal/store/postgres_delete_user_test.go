package store

import (
	"os"
	"testing"

	"github.com/google/uuid"
)

// The Postgres tests need a database: set SA_TEST_POSTGRES_DSN, e.g.
// postgres://postgres:postgres@127.0.0.1:5432/simpleauth_test?sslmode=disable
// They are skipped otherwise, so `go test ./...` still needs no external service.
func openTestPostgres(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("SA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SA_TEST_POSTGRES_DSN not set")
	}
	s, err := OpenPostgres(dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// cleanupPostgresUser removes what a test created for guid, so repeated runs
// against the same database start clean.
func cleanupPostgresUser(t *testing.T, s *PostgresStore, guid string) {
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM sa_identity_mappings WHERE user_guid = $1`,
			`DELETE FROM sa_user_roles WHERE guid = $1`,
			`DELETE FROM sa_user_permissions WHERE guid = $1`,
			`DELETE FROM sa_users WHERE guid = $1`,
		} {
			if _, err := s.db.Exec(q, guid); err != nil {
				t.Errorf("cleanup %s: %v", guid, err)
			}
		}
	})
}

// danglingPostgresMapping creates a user mapped as local:<name>, then removes
// only the user row, as DeleteUser did before M41. It returns the deleted GUID.
func danglingPostgresMapping(t *testing.T, s *PostgresStore, name string) string {
	t.Helper()
	gone := &User{DisplayName: "Gone"}
	if err := s.CreateUser(gone); err != nil {
		t.Fatalf("create: %v", err)
	}
	cleanupPostgresUser(t, s, gone.GUID)
	if err := s.SetIdentityMapping("local", name, gone.GUID); err != nil {
		t.Fatalf("map: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM sa_users WHERE guid = $1`, gone.GUID); err != nil {
		t.Fatalf("simulate old delete: %v", err)
	}
	return gone.GUID
}

// TestPostgresDeleteUserRemovesMappingsRolesAndPermissions is the M41 regression
// for the Postgres store.
func TestPostgresDeleteUserRemovesMappingsRolesAndPermissions(t *testing.T) {
	s := openTestPostgres(t)
	name := "m41-" + uuid.NewString()
	u := &User{DisplayName: "Alice"}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create: %v", err)
	}
	cleanupPostgresUser(t, s, u.GUID)
	if err := s.SetIdentityMapping("local", name, u.GUID); err != nil {
		t.Fatalf("map: %v", err)
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
	if guid, err := s.ResolveMapping("local", name); err == nil {
		t.Fatalf("local:%s still resolves to %s after DeleteUser", name, guid)
	}
	if roles, _ := s.GetUserRoles(u.GUID); len(roles) != 0 {
		t.Fatalf("roles survived: %v", roles)
	}
	if perms, _ := s.GetUserPermissions(u.GUID); len(perms) != 0 {
		t.Fatalf("permissions survived: %v", perms)
	}
}

// TestPostgresDanglingMappingsReportOnlyByDefault: without the opt-in, opening
// the store leaves a dangling mapping in place.
func TestPostgresDanglingMappingsReportOnlyByDefault(t *testing.T) {
	s := openTestPostgres(t)
	name := "m41-report-" + uuid.NewString()
	guid := danglingPostgresMapping(t, s, name)

	s2 := openTestPostgres(t)
	if got, err := s2.ResolveMapping("local", name); err != nil || got != guid {
		t.Fatalf("local:%s = %q, %v; the default check must not write", name, got, err)
	}
}

// TestPostgresRepairDanglingMappingsOnOpen: with SA_REPAIR_DANGLING_MAPPINGS=1, a
// mapping left pointing at a deleted user is removed on open; a live mapping is
// kept.
func TestPostgresRepairDanglingMappingsOnOpen(t *testing.T) {
	s := openTestPostgres(t)
	goneName, liveName := "m41-gone-"+uuid.NewString(), "m41-live-"+uuid.NewString()
	danglingPostgresMapping(t, s, goneName)
	live := &User{DisplayName: "Live"}
	if err := s.CreateUser(live); err != nil {
		t.Fatalf("create: %v", err)
	}
	cleanupPostgresUser(t, s, live.GUID)
	if err := s.SetIdentityMapping("local", liveName, live.GUID); err != nil {
		t.Fatalf("map live: %v", err)
	}

	t.Setenv("SA_REPAIR_DANGLING_MAPPINGS", "1")
	s2 := openTestPostgres(t)
	if guid, err := s2.ResolveMapping("local", goneName); err == nil {
		t.Fatalf("dangling local:%s -> %s survived the repair", goneName, guid)
	}
	if guid, err := s2.ResolveMapping("local", liveName); err != nil || guid != live.GUID {
		t.Fatalf("live local:%s = %q, %v; must be kept", liveName, guid, err)
	}
}

// TestPostgresConnectionDoesNotRepair: TestPostgresConnection only probes the
// DSN, so it must not remove anything even with the opt-in set.
func TestPostgresConnectionDoesNotRepair(t *testing.T) {
	s := openTestPostgres(t)
	name := "m41-probe-" + uuid.NewString()
	guid := danglingPostgresMapping(t, s, name)

	t.Setenv("SA_REPAIR_DANGLING_MAPPINGS", "1")
	if err := TestPostgresConnection(os.Getenv("SA_TEST_POSTGRES_DSN")); err != nil {
		t.Fatalf("TestPostgresConnection: %v", err)
	}
	if got, err := s.ResolveMapping("local", name); err != nil || got != guid {
		t.Fatalf("local:%s = %q, %v; TestPostgresConnection must not write", name, got, err)
	}
}

// TestPostgresRepairDanglingClearsLocalAssignment: the Postgres repair clears
// the app's role assignment for a removed app-local mapping, unless a live user
// can still match the name.
func TestPostgresRepairDanglingClearsLocalAssignment(t *testing.T) {
	s := openTestPostgres(t)
	appID := "m41-" + uuid.NewString()
	goneName, sharedName := "agent-"+uuid.NewString(), "kim-"+uuid.NewString()
	t.Cleanup(func() { s.db.Exec(`DELETE FROM sa_app_authz WHERE app_id = $1`, appID) })
	gone1 := &User{DisplayName: "Gone1"}
	gone2 := &User{DisplayName: "Gone2"}
	live := &User{DisplayName: "Live"}
	for _, u := range []*User{gone1, gone2, live} {
		if err := s.CreateUser(u); err != nil {
			t.Fatalf("create: %v", err)
		}
		cleanupPostgresUser(t, s, u.GUID)
	}
	for _, m := range []struct{ provider, name, guid string }{
		{"applocal:" + appID, goneName, gone1.GUID},
		{"applocal:" + appID, sharedName, gone2.GUID},
		{"local", sharedName, live.GUID},
	} {
		if err := s.SetIdentityMapping(m.provider, m.name, m.guid); err != nil {
			t.Fatalf("map: %v", err)
		}
	}
	if err := s.SaveAppAuthz(&AppAuthz{AppID: appID, UserAssignments: map[string][]string{
		goneName: {"Supervisor"}, sharedName: {"Viewer"},
	}}); err != nil {
		t.Fatalf("authz: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM sa_users WHERE guid = ANY($1)`, []string{gone1.GUID, gone2.GUID}); err != nil {
		t.Fatalf("simulate old delete: %v", err)
	}

	t.Setenv("SA_REPAIR_DANGLING_MAPPINGS", "1")
	s2 := openTestPostgres(t)
	authz, err := s2.GetAppAuthz(appID)
	if err != nil {
		t.Fatalf("authz: %v", err)
	}
	if roles, ok := authz.UserAssignments[goneName]; ok {
		t.Fatalf("stale assignment for %s survived: %v", goneName, roles)
	}
	if roles := authz.UserAssignments[sharedName]; len(roles) != 1 {
		t.Fatalf("assignment for %s, which a live user matches, must be kept; got %v", sharedName, roles)
	}
}
