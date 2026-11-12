package store

import (
	"errors"
	"testing"
)

// GetUser and ResolveMapping tell "does not exist" (ErrNotFound) apart from a
// store failure, and keep their messages.
func TestNotFoundIsDistinguishable(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.GetUser("no-such-guid")
	if !errors.Is(err, ErrNotFound) || err.Error() != "user not found: no-such-guid" {
		t.Fatalf("GetUser: %v (is ErrNotFound: %v)", err, errors.Is(err, ErrNotFound))
	}
	_, err = s.ResolveMapping("ldap", "nobody")
	if !errors.Is(err, ErrNotFound) || err.Error() != "mapping not found: ldap:nobody" {
		t.Fatalf("ResolveMapping: %v (is ErrNotFound: %v)", err, errors.Is(err, ErrNotFound))
	}
	if errors.Is(errors.New("disk I/O error"), ErrNotFound) {
		t.Fatal("an unrelated error matched ErrNotFound")
	}
}
