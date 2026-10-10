package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestLoginPagesSubmitOnce pins the one-submit guard on both credential forms.
// A second Sign In while the first is still redirecting replaces the first
// navigation; the relying party has already spent its one-time state on the
// first code, so the second callback fails (OpenProject answers a bare 401).
// The guard is browser-side, so this checks it is wired into each page.
func TestLoginPagesSubmitOnce(t *testing.T) {
	h, _ := testSetup(t)

	const cb = "https://once.example/cb"
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "once", "audience": "once", "redirect_uris": []string{cb},
	}, adminHeaders())
	if w.Code != http.StatusCreated {
		t.Fatalf("create app: %d %s", w.Code, w.Body.String())
	}

	authorize := url.Values{}
	authorize.Set("client_id", "once")
	authorize.Set("redirect_uri", cb)
	authorize.Set("response_type", "code")

	pages := map[string]string{
		"hosted /login":  "/login?manual=1",
		"OIDC authorize": "/realms/test-issuer/protocol/openid-connect/auth?" + authorize.Encode(),
	}
	for name, path := range pages {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, want := range []string{
			`if (loginForm.dataset.submitted) { e.preventDefault(); return; }`,
			`loginButton.disabled = true;`,
			`window.addEventListener('pageshow'`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: login form is missing the one-submit guard (%q)", name, want)
			}
		}
	}
}
