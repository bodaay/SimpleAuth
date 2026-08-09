package store

import (
	"encoding/json"
	"os"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// openTestBolt returns a concrete *BoltStore (openTestStore returns the Store
// interface, and these tests reach into bucket internals).
func openTestBolt(t *testing.T, dir string) *BoltStore {
	t.Helper()
	s, err := OpenBolt(dir)
	if err != nil {
		t.Fatalf("OpenBolt: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// indexClaims returns the mappings the reverse index attributes to a GUID.
func indexClaims(t *testing.T, s *BoltStore, guid string) []IdentityMapping {
	t.Helper()
	var out []IdentityMapping
	err := s.view(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketIdxMappingsByGUID).Get([]byte(guid))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &out)
	})
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	return out
}

// TestSetIdentityMappingRetractsFromPreviousOwner is the H14 regression.
//
// Re-pointing a mapping used to leave the loser's reverse-index entry in place,
// so BOTH GUIDs claimed the username. resolvePreferredUsername reads the reverse
// index, so the loser kept stamping the winner's username into every token as the
// standard `preferred_username` claim.
func TestSetIdentityMappingRetractsFromPreviousOwner(t *testing.T) {
	s := openTestBolt(t, t.TempDir())

	u1 := &User{DisplayName: "Alice (LDAP JIT)"}
	if err := s.CreateUser(u1); err != nil {
		t.Fatalf("create u1: %v", err)
	}
	u2 := &User{DisplayName: "Alice (admin-created)"}
	if err := s.CreateUser(u2); err != nil {
		t.Fatalf("create u2: %v", err)
	}

	// u1 is JIT-provisioned: owns both ldap:alice and local:alice.
	if err := s.SetIdentityMapping("ldap", "alice", u1.GUID); err != nil {
		t.Fatalf("set ldap: %v", err)
	}
	if err := s.SetIdentityMapping("local", "alice", u1.GUID); err != nil {
		t.Fatalf("set local: %v", err)
	}
	// An admin later creates a local account for the same name -> re-point.
	if err := s.SetIdentityMapping("local", "alice", u2.GUID); err != nil {
		t.Fatalf("re-point local: %v", err)
	}

	// Forward map is authoritative and must name u2.
	if guid, err := s.ResolveMapping("local", "alice"); err != nil || guid != u2.GUID {
		t.Fatalf("forward map: want %s, got %q (err %v)", u2.GUID, guid, err)
	}

	// u1 must NO LONGER claim local:alice — this is the bug.
	for _, m := range indexClaims(t, s, u1.GUID) {
		if m.Provider == "local" && m.ExternalID == "alice" {
			t.Fatal("previous owner still claims local:alice in the reverse index (H14)")
		}
	}
	// u1 keeps its own untouched mapping.
	var keptLDAP bool
	for _, m := range indexClaims(t, s, u1.GUID) {
		if m.Provider == "ldap" && m.ExternalID == "alice" {
			keptLDAP = true
		}
	}
	if !keptLDAP {
		t.Fatal("re-pointing local:alice must not disturb u1's ldap:alice mapping")
	}
	// u2 claims it exactly once.
	var count int
	for _, m := range indexClaims(t, s, u2.GUID) {
		if m.Provider == "local" && m.ExternalID == "alice" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("new owner should claim local:alice exactly once, got %d", count)
	}
}

// TestSetIdentityMappingIdempotent guards the fix against over-correction: a
// naive remove-then-add on the SAME guid would strip the entry addMappingToIndex
// just wrote. (Mirrors TestSetIdentityMapping_Duplicate at the index level.)
func TestSetIdentityMappingIdempotent(t *testing.T) {
	s := openTestBolt(t, t.TempDir())
	u := &User{DisplayName: "Bob"}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := s.SetIdentityMapping("local", "bob", u.GUID); err != nil {
			t.Fatalf("set #%d: %v", i, err)
		}
	}
	claims := indexClaims(t, s, u.GUID)
	if len(claims) != 1 {
		t.Fatalf("re-setting the same mapping must leave exactly 1 index entry, got %d: %+v", len(claims), claims)
	}
	if guid, err := s.ResolveMapping("local", "bob"); err != nil || guid != u.GUID {
		t.Fatalf("forward map broken: %q err=%v", guid, err)
	}
}

// TestListAllMappingsPreservesCompositeProvider is the M38 regression: an
// app-local provider is itself "applocal:<appID>", so splitting the composite
// forward key on the FIRST ':' reported provider="applocal" and smuggled the app
// id into the external id — diverging from Postgres, which stores two columns.
func TestListAllMappingsPreservesCompositeProvider(t *testing.T) {
	s := openTestBolt(t, t.TempDir())
	u := &User{DisplayName: "Tenant User", OwnerAppID: "billing"}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.SetIdentityMapping("applocal:billing", "bob", u.GUID); err != nil {
		t.Fatalf("set: %v", err)
	}

	entries, err := s.ListAllMappings()
	if err != nil {
		t.Fatalf("ListAllMappings: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.UserGUID != u.GUID {
			continue
		}
		found = true
		if e.Provider != "applocal:billing" || e.ExternalID != "bob" {
			t.Fatalf("composite provider corrupted: provider=%q external_id=%q (want applocal:billing / bob)", e.Provider, e.ExternalID)
		}
	}
	if !found {
		t.Fatal("mapping missing from ListAllMappings")
	}
}

// TestRepairMappingIndexPrunesStaleClaims covers the existing-data repair: a
// deployment corrupted by the pre-fix writer must be cleaned on open, and a
// healthy index must be left completely alone.
func TestRepairMappingIndexPrunesStaleClaims(t *testing.T) {
	dir := t.TempDir()
	s := openTestBolt(t, dir)

	u1 := &User{DisplayName: "Loser"}
	u2 := &User{DisplayName: "Winner"}
	if err := s.CreateUser(u1); err != nil {
		t.Fatalf("create u1: %v", err)
	}
	if err := s.CreateUser(u2); err != nil {
		t.Fatalf("create u2: %v", err)
	}
	if err := s.SetIdentityMapping("local", "carol", u2.GUID); err != nil {
		t.Fatalf("set: %v", err)
	}
	// u1 legitimately owns something else, which must survive the repair.
	if err := s.SetIdentityMapping("ldap", "carol", u1.GUID); err != nil {
		t.Fatalf("set ldap: %v", err)
	}

	// Inject exactly the corruption the old writer produced: u1 claims local:carol
	// in the reverse index while the forward map names u2.
	if err := s.update(func(tx *bolt.Tx) error {
		return s.addMappingToIndex(tx, u1.GUID, IdentityMapping{Provider: "local", ExternalID: "carol"})
	}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	if len(indexClaims(t, s, u1.GUID)) != 2 {
		t.Fatal("setup: expected the injected stale claim to be present")
	}
	s.Close()

	// Reopen — repairMappingIndex runs in OpenBolt.
	s2 := openTestBolt(t, dir)
	for _, m := range indexClaims(t, s2, u1.GUID) {
		if m.Provider == "local" && m.ExternalID == "carol" {
			t.Fatal("repair did not prune the stale claim (H14)")
		}
	}
	// The legitimate claim survived.
	var keptOwn bool
	for _, m := range indexClaims(t, s2, u1.GUID) {
		if m.Provider == "ldap" && m.ExternalID == "carol" {
			keptOwn = true
		}
	}
	if !keptOwn {
		t.Fatal("repair pruned a mapping the user legitimately owns")
	}
	// The real owner is untouched.
	if len(indexClaims(t, s2, u2.GUID)) != 1 {
		t.Fatalf("repair disturbed the real owner: %+v", indexClaims(t, s2, u2.GUID))
	}
}

// TestRepairMappingIndexRespectsSkipEnv pins the escape hatch: an operator who
// sees an unexpected prune count must be able to inspect before committing to it.
func TestRepairMappingIndexRespectsSkipEnv(t *testing.T) {
	dir := t.TempDir()
	s := openTestBolt(t, dir)
	u1 := &User{DisplayName: "Loser"}
	u2 := &User{DisplayName: "Winner"}
	if err := s.CreateUser(u1); err != nil {
		t.Fatalf("create u1: %v", err)
	}
	if err := s.CreateUser(u2); err != nil {
		t.Fatalf("create u2: %v", err)
	}
	if err := s.SetIdentityMapping("local", "dave", u2.GUID); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := s.update(func(tx *bolt.Tx) error {
		return s.addMappingToIndex(tx, u1.GUID, IdentityMapping{Provider: "local", ExternalID: "dave"})
	}); err != nil {
		t.Fatalf("inject: %v", err)
	}
	s.Close()

	t.Setenv("SA_SKIP_MAPPING_REPAIR", "1")
	if os.Getenv("SA_SKIP_MAPPING_REPAIR") != "1" {
		t.Fatal("env not set")
	}
	s2 := openTestBolt(t, dir)
	var stillThere bool
	for _, m := range indexClaims(t, s2, u1.GUID) {
		if m.Provider == "local" && m.ExternalID == "dave" {
			stillThere = true
		}
	}
	if !stillThere {
		t.Fatal("SA_SKIP_MAPPING_REPAIR=1 must report without writing")
	}
}

// TestDeleteAppOnlyDeletesOwnedMappings covers the defense-in-depth ownership
// check: if the index ever drifts again, the H8 app-delete cascade must not
// delete a live mapping belonging to somebody else.
func TestDeleteAppOnlyDeletesOwnedMappings(t *testing.T) {
	s := openTestBolt(t, t.TempDir())

	if err := s.CreateApp(&App{AppID: "tenant", Audience: "tenant"}); err != nil {
		t.Fatalf("create app: %v", err)
	}
	appUser := &User{DisplayName: "Ghost", OwnerAppID: "tenant"}
	if err := s.CreateUser(appUser); err != nil {
		t.Fatalf("create app user: %v", err)
	}
	if err := s.SetIdentityMapping("applocal:tenant", "ghost", appUser.GUID); err != nil {
		t.Fatalf("set applocal: %v", err)
	}

	// An unrelated user owns a mapping the app user's index falsely claims.
	victim := &User{DisplayName: "Victim"}
	if err := s.CreateUser(victim); err != nil {
		t.Fatalf("create victim: %v", err)
	}
	if err := s.SetIdentityMapping("local", "victim", victim.GUID); err != nil {
		t.Fatalf("set victim: %v", err)
	}
	if err := s.update(func(tx *bolt.Tx) error {
		return s.addMappingToIndex(tx, appUser.GUID, IdentityMapping{Provider: "local", ExternalID: "victim"})
	}); err != nil {
		t.Fatalf("inject: %v", err)
	}

	if err := s.DeleteApp("tenant"); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	// The app's own mapping is gone (H8 still holds).
	if _, err := s.ResolveMapping("applocal:tenant", "ghost"); err == nil {
		t.Fatal("app delete must cascade the app-local user's own mapping (H8)")
	}
	// The victim's live mapping survived.
	if guid, err := s.ResolveMapping("local", "victim"); err != nil || guid != victim.GUID {
		t.Fatalf("app delete destroyed another user's live mapping (H14): %q err=%v", guid, err)
	}
}
