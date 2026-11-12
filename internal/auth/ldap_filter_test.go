package auth

import "testing"

// The link lookup searches with the sign-in's own filter (custom_filter, else
// username_attr), limited to person entries so a group or other object named
// like a user is never taken for one.
func TestSignInAndLinkFilters(t *testing.T) {
	cases := []struct {
		cfg              LDAPConfig
		name             string
		signIn, linkWant string
	}{
		{LDAPConfig{}, "jdoe", "(sAMAccountName=jdoe)", "(&(objectClass=person)(sAMAccountName=jdoe))"},
		{LDAPConfig{UsernameAttr: "uid"}, "jdoe", "(uid=jdoe)", "(&(objectClass=person)(uid=jdoe))"},
		{LDAPConfig{CustomFilter: "(&(memberOf=CN=App,DC=corp,DC=test)(sAMAccountName={{username}}))"}, "jdoe",
			"(&(memberOf=CN=App,DC=corp,DC=test)(sAMAccountName=jdoe))",
			"(&(objectClass=person)(&(memberOf=CN=App,DC=corp,DC=test)(sAMAccountName=jdoe)))"},
		{LDAPConfig{}, "a*b)(x", `(sAMAccountName=a\2ab\29\28x)`, `(&(objectClass=person)(sAMAccountName=a\2ab\29\28x))`},
	}
	for _, c := range cases {
		cfg := c.cfg
		if got := signInFilter(&cfg, c.name); got != c.signIn {
			t.Errorf("signInFilter(%+v, %q) = %q, want %q", c.cfg, c.name, got, c.signIn)
		}
		if got := linkFilter(&cfg, c.name); got != c.linkWant {
			t.Errorf("linkFilter(%+v, %q) = %q, want %q", c.cfg, c.name, got, c.linkWant)
		}
	}
}
