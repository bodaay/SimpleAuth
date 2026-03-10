package store

import (
	"bytes"
	"testing"
	"time"
)

// helper opens a store in a temporary directory and returns it with a cleanup.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// ---- Open / Close ----

func TestOpenClose(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen the same directory to ensure DB file persists.
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	s2.Close()
}

// ---- User CRUD ----

func TestUserCRUD(t *testing.T) {
	s := openTestStore(t)

	u := &User{DisplayName: "Alice", Email: "alice@example.com"}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.GUID == "" {
		t.Fatal("expected GUID to be generated")
	}

	// GetUser
	got, err := s.GetUser(u.GUID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.DisplayName != "Alice" {
		t.Fatalf("got DisplayName=%q, want Alice", got.DisplayName)
	}

	// ResolveUser (no merge chain)
	resolved, err := s.ResolveUser(u.GUID)
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if resolved.GUID != u.GUID {
		t.Fatal("ResolveUser returned different user")
	}

	// ListUsers
	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("ListUsers: got %d, want 1", len(users))
	}

	// UpdateUser
	u.Email = "alice2@example.com"
	if err := s.UpdateUser(u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got, _ = s.GetUser(u.GUID)
	if got.Email != "alice2@example.com" {
		t.Fatal("UpdateUser: email not updated")
	}

	// DisableUser (set Disabled flag via UpdateUser)
	u.Disabled = true
	if err := s.UpdateUser(u); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	got, _ = s.GetUser(u.GUID)
	if !got.Disabled {
		t.Fatal("expected user to be disabled")
	}
}

func TestGetUser_NotFound(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetUser("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

func TestUpdateUser_NotFound(t *testing.T) {
	s := openTestStore(t)
	err := s.UpdateUser(&User{GUID: "nope"})
	if err == nil {
		t.Fatal("expected error updating nonexistent user")
	}
}

// ---- Identity Mappings ----

func TestIdentityMappings(t *testing.T) {
	s := openTestStore(t)

	u := &User{DisplayName: "Bob", Email: "bob@example.com"}
	s.CreateUser(u)

	// SetIdentityMapping
	if err := s.SetIdentityMapping("github", "bob123", u.GUID); err != nil {
		t.Fatalf("SetIdentityMapping: %v", err)
	}
	if err := s.SetIdentityMapping("google", "bob@gmail.com", u.GUID); err != nil {
		t.Fatalf("SetIdentityMapping (2): %v", err)
	}

	// ResolveMapping
	guid, err := s.ResolveMapping("github", "bob123")
	if err != nil {
		t.Fatalf("ResolveMapping: %v", err)
	}
	if guid != u.GUID {
		t.Fatalf("ResolveMapping: got %q, want %q", guid, u.GUID)
	}

	// ResolveMapping not found
	_, err = s.ResolveMapping("github", "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent mapping")
	}

	// GetMappingsForUser
	mappings, err := s.GetMappingsForUser(u.GUID)
	if err != nil {
		t.Fatalf("GetMappingsForUser: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("GetMappingsForUser: got %d, want 2", len(mappings))
	}

	// ListAllMappings
	all, err := s.ListAllMappings()
	if err != nil {
		t.Fatalf("ListAllMappings: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListAllMappings: got %d, want 2", len(all))
	}

	// DeleteIdentityMapping
	if err := s.DeleteIdentityMapping("github", "bob123"); err != nil {
		t.Fatalf("DeleteIdentityMapping: %v", err)
	}
	_, err = s.ResolveMapping("github", "bob123")
	if err == nil {
		t.Fatal("expected error after deleting mapping")
	}

	// Reverse index should be updated.
	mappings, _ = s.GetMappingsForUser(u.GUID)
	if len(mappings) != 1 {
		t.Fatalf("after delete, GetMappingsForUser: got %d, want 1", len(mappings))
	}

	// Delete the last mapping; reverse index entry should be removed.
	s.DeleteIdentityMapping("google", "bob@gmail.com")
	mappings, _ = s.GetMappingsForUser(u.GUID)
	if len(mappings) != 0 {
		t.Fatalf("after deleting all, GetMappingsForUser: got %d, want 0", len(mappings))
	}
}

func TestSetIdentityMapping_Duplicate(t *testing.T) {
	s := openTestStore(t)
	u := &User{DisplayName: "Dup", Email: "dup@example.com"}
	s.CreateUser(u)

	s.SetIdentityMapping("gh", "id1", u.GUID)
	s.SetIdentityMapping("gh", "id1", u.GUID) // duplicate; should not create extra entries

	mappings, _ := s.GetMappingsForUser(u.GUID)
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping after duplicate set, got %d", len(mappings))
	}
}

// ---- Roles & Permissions ----

func TestRolesAndPermissions(t *testing.T) {
	s := openTestStore(t)

	guid := "user-1"

	// SetUserRoles
	if err := s.SetUserRoles(guid, []string{"admin", "editor"}); err != nil {
		t.Fatalf("SetUserRoles: %v", err)
	}

	// GetUserRoles
	roles, err := s.GetUserRoles(guid)
	if err != nil {
		t.Fatalf("GetUserRoles: %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("GetUserRoles: got %d, want 2", len(roles))
	}

	// GetUserRoles for nonexistent returns nil (no error)
	roles, err = s.GetUserRoles("nonexistent-guid")
	if err != nil {
		t.Fatalf("GetUserRoles (empty): %v", err)
	}
	if roles != nil {
		t.Fatalf("expected nil roles for nonexistent user, got %v", roles)
	}

	// SetUserPermissions
	if err := s.SetUserPermissions(guid, []string{"read", "write", "delete"}); err != nil {
		t.Fatalf("SetUserPermissions: %v", err)
	}

	// GetUserPermissions
	perms, err := s.GetUserPermissions(guid)
	if err != nil {
		t.Fatalf("GetUserPermissions: %v", err)
	}
	if len(perms) != 3 {
		t.Fatalf("GetUserPermissions: got %d, want 3", len(perms))
	}
}

func TestDefaultRoles(t *testing.T) {
	s := openTestStore(t)

	// Initially nil
	roles, err := s.GetDefaultRoles()
	if err != nil {
		t.Fatalf("GetDefaultRoles: %v", err)
	}
	if roles != nil {
		t.Fatalf("expected nil default roles, got %v", roles)
	}

	// SetDefaultRoles
	if err := s.SetDefaultRoles([]string{"member"}); err != nil {
		t.Fatalf("SetDefaultRoles: %v", err)
	}

	roles, err = s.GetDefaultRoles()
	if err != nil {
		t.Fatalf("GetDefaultRoles (after set): %v", err)
	}
	if len(roles) != 1 || roles[0] != "member" {
		t.Fatalf("expected [member], got %v", roles)
	}
}

func TestRolePermissions(t *testing.T) {
	s := openTestStore(t)

	mapping := map[string][]string{
		"admin":  {"read", "write", "delete"},
		"viewer": {"read"},
	}
	if err := s.SetRolePermissions(mapping); err != nil {
		t.Fatalf("SetRolePermissions: %v", err)
	}

	got, err := s.GetRolePermissions()
	if err != nil {
		t.Fatalf("GetRolePermissions: %v", err)
	}
	if len(got["admin"]) != 3 {
		t.Fatalf("expected 3 admin perms, got %d", len(got["admin"]))
	}

	// ResolvePermissions
	resolved, err := s.ResolvePermissions([]string{"admin"}, []string{"custom"})
	if err != nil {
		t.Fatalf("ResolvePermissions: %v", err)
	}
	// Should have read, write, delete, custom = 4
	if len(resolved) != 4 {
		t.Fatalf("expected 4 resolved perms, got %d: %v", len(resolved), resolved)
	}
}

// ---- Refresh Tokens ----

func TestRefreshTokens(t *testing.T) {
	s := openTestStore(t)

	rt := &RefreshToken{
		TokenID:   "tok-1",
		FamilyID:  "fam-1",
		UserGUID:  "user-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	// SaveRefreshToken
	if err := s.SaveRefreshToken(rt); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	// GetRefreshToken
	got, err := s.GetRefreshToken("tok-1")
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if got.FamilyID != "fam-1" {
		t.Fatalf("got FamilyID=%q, want fam-1", got.FamilyID)
	}
	if got.Used {
		t.Fatal("expected Used=false")
	}

	// GetRefreshToken not found
	_, err = s.GetRefreshToken("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}

	// MarkRefreshTokenUsed
	if err := s.MarkRefreshTokenUsed("tok-1"); err != nil {
		t.Fatalf("MarkRefreshTokenUsed: %v", err)
	}
	got, _ = s.GetRefreshToken("tok-1")
	if !got.Used {
		t.Fatal("expected Used=true after MarkRefreshTokenUsed")
	}

	// MarkRefreshTokenUsed not found
	err = s.MarkRefreshTokenUsed("nonexistent")
	if err == nil {
		t.Fatal("expected error marking nonexistent token")
	}

	// RevokeTokenFamily
	rt2 := &RefreshToken{TokenID: "tok-2", FamilyID: "fam-1", UserGUID: "user-1",
		ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now()}
	rt3 := &RefreshToken{TokenID: "tok-3", FamilyID: "fam-2", UserGUID: "user-1",
		ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now()}
	s.SaveRefreshToken(rt2)
	s.SaveRefreshToken(rt3)

	if err := s.RevokeTokenFamily("fam-1"); err != nil {
		t.Fatalf("RevokeTokenFamily: %v", err)
	}

	// fam-1 tokens should be gone.
	_, err = s.GetRefreshToken("tok-1")
	if err == nil {
		t.Fatal("expected tok-1 to be revoked")
	}
	_, err = s.GetRefreshToken("tok-2")
	if err == nil {
		t.Fatal("expected tok-2 to be revoked")
	}

	// fam-2 token should still exist.
	got, err = s.GetRefreshToken("tok-3")
	if err != nil {
		t.Fatalf("tok-3 should survive: %v", err)
	}
	if got.FamilyID != "fam-2" {
		t.Fatal("tok-3 has wrong family")
	}
}

// ---- User Merge / Unmerge ----

func TestMergeUsers(t *testing.T) {
	s := openTestStore(t)

	u1 := &User{DisplayName: "User1", Email: "u1@example.com"}
	u2 := &User{DisplayName: "User2", Email: "u2@example.com"}
	s.CreateUser(u1)
	s.CreateUser(u2)

	// Set up identity mappings on source users.
	s.SetIdentityMapping("gh", "u1gh", u1.GUID)
	s.SetIdentityMapping("google", "u2google", u2.GUID)

	// Set up roles/permissions on source users.
	s.SetUserRoles(u1.GUID, []string{"admin"})
	s.SetUserRoles(u2.GUID, []string{"editor"})
	s.SetUserPermissions(u1.GUID, []string{"read"})
	s.SetUserPermissions(u2.GUID, []string{"write"})

	// Merge
	merged, err := s.MergeUsers([]string{u1.GUID, u2.GUID}, "MergedUser", "merged@example.com")
	if err != nil {
		t.Fatalf("MergeUsers: %v", err)
	}
	if merged.GUID == "" {
		t.Fatal("expected merged user to have a GUID")
	}

	// Source users should have MergedInto set.
	src1, _ := s.GetUser(u1.GUID)
	if src1.MergedInto != merged.GUID {
		t.Fatalf("u1.MergedInto=%q, want %q", src1.MergedInto, merged.GUID)
	}
	src2, _ := s.GetUser(u2.GUID)
	if src2.MergedInto != merged.GUID {
		t.Fatalf("u2.MergedInto=%q, want %q", src2.MergedInto, merged.GUID)
	}

	// ResolveUser should follow the chain.
	resolved, err := s.ResolveUser(u1.GUID)
	if err != nil {
		t.Fatalf("ResolveUser after merge: %v", err)
	}
	if resolved.GUID != merged.GUID {
		t.Fatalf("ResolveUser: got %q, want %q", resolved.GUID, merged.GUID)
	}

	// Identity mappings should point to the merged user.
	guid, _ := s.ResolveMapping("gh", "u1gh")
	if guid != merged.GUID {
		t.Fatal("identity mapping not transferred to merged user")
	}
	guid, _ = s.ResolveMapping("google", "u2google")
	if guid != merged.GUID {
		t.Fatal("identity mapping not transferred to merged user")
	}

	// Merged user should have combined roles.
	roles, _ := s.GetUserRoles(merged.GUID)
	if len(roles) < 2 {
		t.Fatalf("expected at least 2 merged roles, got %d", len(roles))
	}

	// Merged user should have combined permissions.
	perms, _ := s.GetUserPermissions(merged.GUID)
	if len(perms) < 2 {
		t.Fatalf("expected at least 2 merged perms, got %d", len(perms))
	}
}

func TestUnmergeUser(t *testing.T) {
	s := openTestStore(t)

	u := &User{DisplayName: "ToMerge", Email: "tm@example.com"}
	s.CreateUser(u)

	// Manually set MergedInto.
	u.MergedInto = "some-target"
	s.UpdateUser(u)

	if err := s.UnmergeUser(u.GUID); err != nil {
		t.Fatalf("UnmergeUser: %v", err)
	}
	got, _ := s.GetUser(u.GUID)
	if got.MergedInto != "" {
		t.Fatal("expected MergedInto to be cleared")
	}
}

func TestUnmergeUser_NotMerged(t *testing.T) {
	s := openTestStore(t)

	u := &User{DisplayName: "NotMerged", Email: "nm@example.com"}
	s.CreateUser(u)

	err := s.UnmergeUser(u.GUID)
	if err == nil {
		t.Fatal("expected error unmerging a non-merged user")
	}
}

func TestUnmergeUser_NotFound(t *testing.T) {
	s := openTestStore(t)
	err := s.UnmergeUser("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
}

// ---- Audit Log ----

func TestAuditLog(t *testing.T) {
	s := openTestStore(t)

	// WriteAuditLog
	e1 := &AuditEntry{Event: "login", Actor: "user-1", IP: "1.2.3.4",
		Timestamp: time.Now().UTC().Add(-2 * time.Hour),
		Data:      map[string]interface{}{"method": "password"}}
	e2 := &AuditEntry{Event: "login", Actor: "user-2", IP: "5.6.7.8",
		Timestamp: time.Now().UTC().Add(-1 * time.Hour)}
	e3 := &AuditEntry{Event: "logout", Actor: "user-1", IP: "1.2.3.4",
		Timestamp: time.Now().UTC()}

	for _, e := range []*AuditEntry{e1, e2, e3} {
		if err := s.WriteAuditLog(e); err != nil {
			t.Fatalf("WriteAuditLog: %v", err)
		}
	}

	// QueryAuditLog: all entries (default limit=100)
	entries, err := s.QueryAuditLog(AuditQuery{})
	if err != nil {
		t.Fatalf("QueryAuditLog: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("QueryAuditLog (all): got %d, want 3", len(entries))
	}

	// Filter by event
	entries, _ = s.QueryAuditLog(AuditQuery{Event: "login"})
	if len(entries) != 2 {
		t.Fatalf("QueryAuditLog (event=login): got %d, want 2", len(entries))
	}

	// Filter by actor
	entries, _ = s.QueryAuditLog(AuditQuery{UserID: "user-1"})
	if len(entries) != 2 {
		t.Fatalf("QueryAuditLog (actor=user-1): got %d, want 2", len(entries))
	}

	// Limit
	entries, _ = s.QueryAuditLog(AuditQuery{Limit: 1})
	if len(entries) != 1 {
		t.Fatalf("QueryAuditLog (limit=1): got %d, want 1", len(entries))
	}

	// Offset
	entries, _ = s.QueryAuditLog(AuditQuery{Limit: 10, Offset: 1})
	if len(entries) != 2 {
		t.Fatalf("QueryAuditLog (offset=1): got %d, want 2", len(entries))
	}

	// Time range filter
	entries, _ = s.QueryAuditLog(AuditQuery{
		From: time.Now().UTC().Add(-90 * time.Minute),
		To:   time.Now().UTC().Add(-30 * time.Minute),
	})
	if len(entries) != 1 {
		t.Fatalf("QueryAuditLog (time range): got %d, want 1", len(entries))
	}
}

func TestPruneAuditLog(t *testing.T) {
	s := openTestStore(t)

	old := &AuditEntry{Event: "old", Actor: "sys",
		Timestamp: time.Now().UTC().Add(-48 * time.Hour)}
	recent := &AuditEntry{Event: "recent", Actor: "sys",
		Timestamp: time.Now().UTC()}
	s.WriteAuditLog(old)
	s.WriteAuditLog(recent)

	// Prune entries older than 24 hours.
	if err := s.PruneAuditLog(24 * time.Hour); err != nil {
		t.Fatalf("PruneAuditLog: %v", err)
	}

	entries, _ := s.QueryAuditLog(AuditQuery{})
	if len(entries) != 1 {
		t.Fatalf("after prune: got %d entries, want 1", len(entries))
	}
	if entries[0].Event != "recent" {
		t.Fatalf("surviving entry should be 'recent', got %q", entries[0].Event)
	}
}

// ---- Backup / Restore ----

func TestBackupAndRestore(t *testing.T) {
	s := openTestStore(t)

	// Create some data.
	u := &User{DisplayName: "BackupUser", Email: "bu@example.com"}
	s.CreateUser(u)

	// BackupWriter into a buffer.
	var buf bytes.Buffer
	if err := s.BackupWriter(&buf); err != nil {
		t.Fatalf("BackupWriter: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("backup is empty")
	}

	// Delete data.
	s.DeleteUser(u.GUID)

	// Verify data is gone.
	_, err := s.GetUser(u.GUID)
	if err == nil {
		t.Fatal("expected user to be deleted before restore")
	}

	// Restore from the buffer.
	if err := s.Restore(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Data should be back.
	gotU, err := s.GetUser(u.GUID)
	if err != nil {
		t.Fatalf("GetUser after Restore: %v", err)
	}
	if gotU.DisplayName != "BackupUser" {
		t.Fatalf("restored user name=%q, want BackupUser", gotU.DisplayName)
	}
}

func TestBackupToFile(t *testing.T) {
	s := openTestStore(t)

	u := &User{DisplayName: "FileBackupUser"}
	s.CreateUser(u)

	backupPath := t.TempDir() + "/backup.db"
	if err := s.Backup(backupPath); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// The backup file should be a valid BoltDB. Open it directly.
	s3 := &Store{}
	if err := s3.reopen(backupPath); err != nil {
		t.Fatalf("reopen backup: %v", err)
	}
	defer s3.Close()
}

// ---- Edge Cases ----

func TestDeleteIdentityMapping_Nonexistent(t *testing.T) {
	s := openTestStore(t)
	// Should not error.
	if err := s.DeleteIdentityMapping("x", "y"); err != nil {
		t.Fatalf("DeleteIdentityMapping nonexistent: %v", err)
	}
}

func TestGetMappingsForUser_NoMappings(t *testing.T) {
	s := openTestStore(t)
	mappings, err := s.GetMappingsForUser("no-such-user")
	if err != nil {
		t.Fatalf("GetMappingsForUser: %v", err)
	}
	if mappings != nil {
		t.Fatalf("expected nil, got %v", mappings)
	}
}

func TestMergeUsers_SourceNotFound(t *testing.T) {
	s := openTestStore(t)
	_, err := s.MergeUsers([]string{"nonexistent"}, "X", "x@example.com")
	if err == nil {
		t.Fatal("expected error merging nonexistent source user")
	}
}

func TestRevokeTokenFamily_Empty(t *testing.T) {
	s := openTestStore(t)
	// Should not error when no tokens exist.
	if err := s.RevokeTokenFamily("nope"); err != nil {
		t.Fatalf("RevokeTokenFamily empty: %v", err)
	}
}

func TestListUsers_Empty(t *testing.T) {
	s := openTestStore(t)
	users, err := s.ListUsers()
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if users != nil {
		t.Fatalf("expected nil for empty list, got %v", users)
	}
}
