package handler

import (
	"testing"
	"time"

	"simpleauth/internal/store"
)

// These cover the non-directory branches of resolveNegotiateUser. The directory
// branch delegates to resolveKerberosUser (shared with /login/sso) and needs a
// live LDAP server, so it is exercised end to end against a Samba AD DC rather
// than here.

func createNegotiateTestUser(t *testing.T, s store.Store, u *store.User) {
	t.Helper()
	u.CreatedAt = time.Now().UTC()
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create user: %v", err)
	}
}

func TestResolveNegotiateUser_ExplicitKerberosMappingWins(t *testing.T) {
	h, s := testSetup(t)
	createNegotiateTestUser(t, s, &store.User{GUID: "mapped", DisplayName: "John Doe"})
	if err := s.SetIdentityMapping("kerberos", "jdoe@GREEN.ORG", "mapped"); err != nil {
		t.Fatalf("map: %v", err)
	}

	guid, _, err := h.resolveNegotiateUser("jdoe", "jdoe@GREEN.ORG")
	if err != nil || guid != "mapped" {
		t.Fatalf("explicit kerberos mapping must resolve: guid=%q err=%v", guid, err)
	}
}

func TestResolveNegotiateUser_RealmlessMappingResolves(t *testing.T) {
	h, s := testSetup(t)
	createNegotiateTestUser(t, s, &store.User{GUID: "mapped", DisplayName: "John Doe"})
	if err := s.SetIdentityMapping("kerberos", "jdoe", "mapped"); err != nil {
		t.Fatalf("map: %v", err)
	}

	guid, _, err := h.resolveNegotiateUser("jdoe", "jdoe@GREEN.ORG")
	if err != nil || guid != "mapped" {
		t.Fatalf("realm-less kerberos mapping must resolve: guid=%q err=%v", guid, err)
	}
}

func TestResolveNegotiateUser_WithoutDirectoryKeepsLegacyMatch(t *testing.T) {
	h, s := testSetup(t)
	createNegotiateTestUser(t, s, &store.User{GUID: "legacy", DisplayName: "jdoe"})

	guid, _, err := h.resolveNegotiateUser("jdoe", "jdoe@GREEN.ORG")
	if err != nil || guid != "legacy" {
		t.Fatalf("without a directory the display-name match must still resolve: guid=%q err=%v", guid, err)
	}
	if mapped, err := s.ResolveMapping("kerberos", "jdoe@GREEN.ORG"); err != nil || mapped != "legacy" {
		t.Fatalf("legacy match must record a kerberos mapping for next time: %q %v", mapped, err)
	}
}

func TestResolveNegotiateUser_UnknownPrincipalFails(t *testing.T) {
	h, s := testSetup(t)
	createNegotiateTestUser(t, s, &store.User{GUID: "someone", DisplayName: "John Doe", Email: "jdoe@green.org"})

	if guid, _, err := h.resolveNegotiateUser("jdoe", "jdoe@GREEN.ORG"); err == nil {
		t.Fatalf("a principal with no mapping, no directory entry and no exact match must fail, got %q", guid)
	}
}

func TestResolveNegotiateUser_AppLocalUserNeverMatched(t *testing.T) {
	h, s := testSetup(t)
	createNegotiateTestUser(t, s, &store.User{GUID: "app-owned", OwnerAppID: "shop", DisplayName: "jdoe"})

	if guid, _, err := h.resolveNegotiateUser("jdoe", "jdoe@GREEN.ORG"); err == nil {
		t.Fatalf("an app-local user must never be bound to a Kerberos principal (M12), got %q", guid)
	}
}
