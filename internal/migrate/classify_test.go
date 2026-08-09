package migrate

import (
	"fmt"
	"strings"
	"testing"

	"simpleauth/internal/store"
)

// TestClassifyDirectoryBeatsLocalPassword is the H16 regression.
//
// An AD-backed user who ALSO carries a local password hash must migrate as a
// DIRECTORY user (policy only, re-bound from the central's AD), not as an
// app-local shadow keyed by that credential. The old precedence tested
// PasswordHash first, so such a user's password travelled to the central and the
// resulting account outlived AD-side disablement — and, because Classify never
// blocks a local user, an entire AD population misclassified this way sailed past
// the "central is on a different AD" guard.
func TestClassifyDirectoryBeatsLocalPassword(t *testing.T) {
	s := open(t)
	// Exactly what the reset-password path (SA-7) or a break-glass admin produces:
	// a directory user carrying a local hash, with both ldap and local mappings.
	must(t, s.CreateUser(&store.User{
		GUID: "g-dual", DisplayName: "Dual", SAMAccountName: "dual",
		PasswordHash: "$2a$10$notarealhashbutlongenoughxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}))
	must(t, s.SetIdentityMapping("ldap", "dual", "g-dual"))
	must(t, s.SetIdentityMapping("local", "dual", "g-dual"))
	must(t, s.SetUserRoles("g-dual", []string{"admin"}))

	u, err := s.GetUser("g-dual")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	entry, ok := classifyUser(s, u, nil)
	if !ok {
		t.Fatal("user should be classifiable")
	}
	if entry.Kind != KindAD {
		t.Fatalf("a directory user with a local hash must classify as AD, got %q (H16)", entry.Kind)
	}
	if entry.Key != "dual" {
		t.Fatalf("key should be the sAMAccountName, got %q", entry.Key)
	}
	if entry.PasswordHash != "" {
		t.Fatal("a directory user's local password hash must NOT travel in the bundle (H16)")
	}
	if !entry.HadLocalPassword {
		t.Fatal("HadLocalPassword must flag that a local credential existed and was left behind")
	}
}

// TestClassifyImportedLDAPUserWithoutSAM covers the gap SAMAccountName alone
// leaves: handleImportLDAPUsers creates an "ldap"-mapped user with NO
// SAMAccountName, and it stays empty until first login. Such a user must still
// classify as directory, keyed off the mapping.
func TestClassifyImportedLDAPUserWithoutSAM(t *testing.T) {
	s := open(t)
	must(t, s.CreateUser(&store.User{GUID: "g-imp", DisplayName: "Imported"}))
	must(t, s.SetIdentityMapping("ldap", "imported", "g-imp"))
	must(t, s.SetUserRoles("g-imp", []string{"viewer"}))

	u, _ := s.GetUser("g-imp")
	entry, ok := classifyUser(s, u, nil)
	if !ok {
		t.Fatal("imported LDAP user should be classifiable")
	}
	if entry.Kind != KindAD || entry.Key != "imported" {
		t.Fatalf("want AD/imported, got %q/%q", entry.Kind, entry.Key)
	}
}

// TestClassifyGenuineLocalUserUnchanged guards against over-correction: a user
// with only a local mapping and a password is still a local user.
func TestClassifyGenuineLocalUserUnchanged(t *testing.T) {
	s := open(t)
	must(t, s.CreateUser(&store.User{
		GUID: "g-loc", DisplayName: "Local", Email: "l@x.test",
		PasswordHash: "$2a$10$stillnotarealhashxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}))
	must(t, s.SetIdentityMapping("local", "localuser", "g-loc"))
	must(t, s.SetUserRoles("g-loc", []string{"clerk"}))

	u, _ := s.GetUser("g-loc")
	entry, ok := classifyUser(s, u, nil)
	if !ok {
		t.Fatal("local user should be classifiable")
	}
	if entry.Kind != KindLocal {
		t.Fatalf("want local, got %q", entry.Kind)
	}
	if entry.Key != "localuser" {
		t.Fatalf("want key localuser, got %q", entry.Key)
	}
	if entry.PasswordHash == "" {
		t.Fatal("a genuine local user's hash must still travel — that is how they log in on the central")
	}
}

// TestClassifyAppLocalUserIsNeverDirectory pins the OwnerAppID short-circuit: an
// app-local user is local by construction, whatever mappings hang off the record.
func TestClassifyAppLocalUserIsNeverDirectory(t *testing.T) {
	s := open(t)
	must(t, s.CreateUser(&store.User{
		GUID: "g-app", DisplayName: "AppUser", OwnerAppID: "shop",
		SAMAccountName: "stray", // must be ignored
		PasswordHash:   "$2a$10$appuserhashxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}))
	must(t, s.SetIdentityMapping("applocal:shop", "shopper", "g-app"))
	must(t, s.SetUserRoles("g-app", []string{"buyer"}))

	u, _ := s.GetUser("g-app")
	entry, ok := classifyUser(s, u, nil)
	if !ok {
		t.Fatal("app-local user should be classifiable")
	}
	if entry.Kind != KindLocal {
		t.Fatalf("an app-local user must never classify as directory, got %q", entry.Kind)
	}
	if entry.Key != "shopper" {
		t.Fatalf("want key shopper, got %q", entry.Key)
	}
}

// TestDirectoryKeyIsDeterministic pins backend-independent selection:
// GetMappingsForUser returns insertion order on Bolt and unordered rows on
// Postgres, and a user commonly carries both a UPN and a sAMAccountName form. The
// bare sAMAccountName must win, regardless of insertion order.
func TestDirectoryKeyIsDeterministic(t *testing.T) {
	for _, order := range [][]string{
		{"dana@corp.local", "dana"},
		{"dana", "dana@corp.local"},
	} {
		s := open(t)
		must(t, s.CreateUser(&store.User{GUID: "g-d", DisplayName: "Dana"}))
		for _, ext := range order {
			must(t, s.SetIdentityMapping("ldap", ext, "g-d"))
		}
		u, _ := s.GetUser("g-d")
		got, err := directoryKey(s, u)
		if err != nil {
			t.Fatalf("directoryKey: %v", err)
		}
		if got != "dana" {
			t.Fatalf("insertion order %v: directoryKey = %q, want the bare sAMAccountName form %q", order, got, "dana")
		}
	}
}

// TestClassifyNoIdentityIsSkipped — a user with neither a directory identity nor
// a password has nothing portable.
func TestClassifyNoIdentityIsSkipped(t *testing.T) {
	s := open(t)
	must(t, s.CreateUser(&store.User{GUID: "g-non", DisplayName: "Nobody"}))
	u, _ := s.GetUser("g-non")
	if _, ok := classifyUser(s, u, nil); ok {
		t.Fatal("a user with no directory identity and no password must be skipped")
	}
}

// TestClassifyReportsNoRolesHonestly pins the preflight/Apply accounting gap: a
// user with no effective roles is not migrated by Apply, so the dry run must not
// promise them.
func TestClassifyReportsNoRolesHonestly(t *testing.T) {
	c := open(t)
	must(t, c.CreateApp(&store.App{AppID: "target", Audience: "target"}))

	b := &Bundle{
		SchemaRev: SchemaRev,
		Users: []UserEntry{
			{Kind: KindLocal, Key: "with-roles", Roles: []string{"clerk"}, PasswordHash: "x"},
			{Kind: KindLocal, Key: "no-roles", PasswordHash: "x"},
		},
	}
	rep, err := Classify(b, c, "target", "simpleauth")
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if rep.LocalUsers != 1 {
		t.Fatalf("only the role-carrying user migrates; LocalUsers = %d, want 1", rep.LocalUsers)
	}
	if rep.NoRoles != 1 {
		t.Fatalf("NoRoles = %d, want 1", rep.NoRoles)
	}
	var noted bool
	for _, n := range rep.Notes {
		// Assert the note actually explains the gap, not merely that some note
		// starting with "1" exists — the operator has to understand WHY the count
		// they were shown is lower than the number of users in the bundle.
		if strings.Contains(n, "no effective roles") && strings.Contains(n, "do NOT migrate") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected a note explaining the non-migrating user, got: %v", rep.Notes)
	}
}

// errStore makes GetMappingsForUser fail so we can pin that classification fails
// CLOSED. Swallowing that error meant "no directory identity", which classified
// the user as LOCAL and exported their password hash — found by adversarial
// review of the first cut of this fix.
type errStore struct{ store.Store }

func (errStore) GetMappingsForUser(string) ([]store.IdentityMapping, error) {
	return nil, errTestMappings
}

var errTestMappings = fmt.Errorf("simulated store failure")

func TestClassifyFailsClosedOnMappingError(t *testing.T) {
	base := open(t)
	// Email matters: localUsername falls back to it, so WITHOUT the fail-closed
	// guard the local branch succeeds and exports the hash. Omit it and the user
	// is skipped for an unrelated reason and the test cannot fail.
	must(t, base.CreateUser(&store.User{
		GUID: "g-err", DisplayName: "Err", Email: "err@corp.test",
		PasswordHash: "$2a$10$hashthatmustnotescapexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}))
	u, _ := base.GetUser("g-err")

	// No SAMAccountName, so classification must consult mappings — which fail.
	entry, ok := classifyUser(errStore{base}, u, nil)
	if ok {
		t.Fatalf("classification must fail closed when the directory lookup errors, got %+v", entry)
	}
	if entry.PasswordHash != "" {
		t.Fatal("a password hash escaped into the bundle on a store error (H16)")
	}
}

// TestClassifyDirectoryProviderVariants covers the provider forms an adversarial
// review found missing: build.md documents multi-directory deployments as
// `ldap:corp` / `ldap:partner`, and handleSetMapping accepts an arbitrary provider
// string, so an exact match on "ldap" left every such deployment unfixed — their
// directory users classified as local and had their password hash exported.
func TestClassifyDirectoryProviderVariants(t *testing.T) {
	directory := []string{"ldap", "kerberos", "ldap:corp", "ldap:partner", "kerberos:CORP.LOCAL"}
	for _, prov := range directory {
		s := open(t)
		must(t, s.CreateUser(&store.User{
			GUID: "g-" + prov, DisplayName: "D", Email: "d@corp.test",
			PasswordHash: "$2a$10$mustnotescapexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		}))
		must(t, s.SetIdentityMapping(prov, "dana", "g-"+prov))
		u, _ := s.GetUser("g-" + prov)

		entry, ok := classifyUser(s, u, nil)
		if !ok {
			t.Errorf("provider %q: user should classify", prov)
			continue
		}
		if entry.Kind != KindAD {
			t.Errorf("provider %q: want KindAD, got %q — a directory user would export their hash", prov, entry.Kind)
		}
		if entry.PasswordHash != "" {
			t.Errorf("provider %q: password hash escaped into the bundle", prov)
		}
	}

	// And the credential-bearing providers must NOT be treated as directory.
	for _, prov := range []string{"local", "applocal:shop"} {
		if isDirectoryProvider(prov) {
			t.Errorf("provider %q must not count as a directory identity", prov)
		}
	}
}
