package handler

import (
	"strings"
	"testing"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// No admin response that carries user records may carry a password hash or
// the password history (docs/ARCHITECTURE.md: "omitted in API responses").
func TestAdminUserResponsesCarryNoPasswordHashes(t *testing.T) {
	h, s := testSetup(t)
	hash, err := auth.HashPassword("current-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	old, err := auth.HashPassword("older-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{DisplayName: "Hash Holder", Email: "holder@example.test", PasswordHash: hash, PasswordHistory: []string{old}}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	s.SetIdentityMapping("local", "holder", u.GUID)

	for _, c := range []struct{ method, path string }{
		{"GET", "/api/admin/users"},
		{"GET", "/api/admin/users?include=identities"},
		{"GET", "/api/admin/users/" + u.GUID},
		{"GET", "/api/admin/users/" + u.GUID + "?include=identities"},
		{"PUT", "/api/admin/users/" + u.GUID},
	} {
		var body interface{}
		if c.method == "PUT" {
			body = map[string]interface{}{"display_name": "Hash Holder"}
		}
		w := doJSON(h, c.method, c.path, body, adminHeaders())
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", c.method, c.path, w.Code, w.Body.String())
		}
		got := w.Body.String()
		if !strings.Contains(got, u.GUID) {
			t.Fatalf("%s %s: the user is not in the response: %s", c.method, c.path, got)
		}
		for label, leak := range map[string]string{
			"the password_hash field": "password_hash", "the password_history field": "password_history",
			"the current hash": hash, "an older hash": old,
		} {
			if strings.Contains(got, leak) {
				t.Errorf("%s %s: the response carries %s", c.method, c.path, label)
			}
		}
	}

	// The responses never touch what is stored: sign-in with the password works.
	if got, _ := s.GetUser(u.GUID); got.PasswordHash != hash || len(got.PasswordHistory) != 1 {
		t.Fatal("answering a request changed the stored password hash or history")
	}
	w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": "holder", "password": "current-pass-1"}, nil)
	if w.Code != 200 {
		t.Fatalf("sign-in after the requests: %d %s", w.Code, w.Body.String())
	}
}
