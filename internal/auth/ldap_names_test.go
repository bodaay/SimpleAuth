package auth

import (
	"slices"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestLDAPReadsGivenAndFamilyName(t *testing.T) {
	cfg := &LDAPConfig{UsernameAttr: "sAMAccountName", GivenNameAttr: "givenName", FamilyNameAttr: "sn"}

	attrs := ldapAttrs(cfg)
	if !slices.Contains(attrs, "givenName") || !slices.Contains(attrs, "sn") {
		t.Fatalf("search must request the name attributes, got %v", attrs)
	}

	entry := ldap.NewEntry("CN=Salem Almarri,CN=Users,DC=green,DC=org", map[string][]string{
		"sAMAccountName": {"salem"},
		"givenName":      {"سالم"},
		"sn":             {"المري"},
	})
	got := entryToResult(entry, cfg)
	if got.GivenName != "سالم" || got.FamilyName != "المري" {
		t.Fatalf("given/family name not read from the entry: %q/%q", got.GivenName, got.FamilyName)
	}
}

func TestLDAPNameAttributesOptional(t *testing.T) {
	cfg := &LDAPConfig{UsernameAttr: "sAMAccountName"}
	if attrs := ldapAttrs(cfg); slices.Contains(attrs, "") {
		t.Fatalf("unset name attributes must not add empty attribute names: %v", attrs)
	}
	got := entryToResult(ldap.NewEntry("CN=x", map[string][]string{"sAMAccountName": {"x"}, "givenName": {"X"}}), cfg)
	if got.GivenName != "" || got.FamilyName != "" {
		t.Fatalf("unmapped attributes must not populate names: %q/%q", got.GivenName, got.FamilyName)
	}
}
