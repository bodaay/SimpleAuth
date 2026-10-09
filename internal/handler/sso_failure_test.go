package handler

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var metaRefreshURL = regexp.MustCompile(`content="0;url=([^"]+)"`)

func ssoGet(h *Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
	return rec
}

func oidcSSOQuery(appID, cb string) url.Values {
	q := url.Values{}
	q.Set("oidc", "1")
	q.Set("client_id", appID)
	q.Set("redirect_uri", cb)
	q.Set("state", "the-state")
	q.Set("nonce", "the-nonce")
	q.Set("scope", "openid email")
	q.Set("code_challenge", s256("v"))
	q.Set("code_challenge_method", "S256")
	return q
}

// negotiateRetryURL sends the first, header-less /login/sso request and returns
// the meta-refresh URL a browser without Kerberos credentials follows.
func negotiateRetryURL(t *testing.T, h *Handler, q url.Values) *url.URL {
	t.Helper()
	rec := ssoGet(h, "/login/sso?"+q.Encode())
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Negotiate" {
		t.Fatalf("expected a 401 Negotiate challenge, got %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	m := metaRefreshURL.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("challenge body has no meta-refresh retry: %s", rec.Body.String())
	}
	u, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatalf("parse retry URL: %v", err)
	}
	return u
}

func withKeytab(t *testing.T, h *Handler) {
	t.Helper()
	h.cfg.KRB5Keytab = filepath.Join(t.TempDir(), "krb5.keytab")
}

// The retry used to keep only redirect_uri, so it resolved the default app and an
// OIDC failure lost state, nonce and the PKCE challenge on the way back.
func TestSSONegotiateRetryKeepsAuthorizeRequest(t *testing.T) {
	h, _ := testSetup(t)
	withKeytab(t, h)
	cb := mkPKCEApp(t, h, "shop9")
	sent := oidcSSOQuery("shop9", cb)

	retry := negotiateRetryURL(t, h, sent).Query()
	for _, k := range []string{"oidc", "client_id", "redirect_uri", "state", "nonce", "scope", "code_challenge", "code_challenge_method"} {
		if retry.Get(k) != sent.Get(k) {
			t.Errorf("retry dropped or altered %q: want %q, got %q", k, sent.Get(k), retry.Get(k))
		}
	}
	if retry.Get("sso_attempt") != "1" {
		t.Error("retry must mark sso_attempt=1 so the failure is detected")
	}
}

// A failed OIDC SSO attempt must come back to SimpleAuth's authorize page with the
// whole request — not to the client's redirect_uri with a bare ?error=, which has
// no state and is rejected by OIDC clients as a CSRF mismatch.
func TestSSOFailureReturnsToAuthorizePageWithState(t *testing.T) {
	h, _ := testSetup(t)
	withKeytab(t, h)
	cb := mkPKCEApp(t, h, "shop10")
	sent := oidcSSOQuery("shop10", cb)

	retry := negotiateRetryURL(t, h, sent)
	rec := ssoGet(h, retry.RequestURI())
	if rec.Code != http.StatusFound {
		t.Fatalf("failed SSO must redirect, got %d %s", rec.Code, rec.Body.String())
	}
	lu, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.HasPrefix(lu.String(), cb) || !strings.Contains(lu.Path, "/protocol/openid-connect/auth") {
		t.Fatalf("failed SSO must return to SimpleAuth's authorize page, got %q", lu.String())
	}
	got := lu.Query()
	for _, k := range []string{"client_id", "redirect_uri", "state", "nonce", "scope", "code_challenge", "code_challenge_method"} {
		if got.Get(k) != sent.Get(k) {
			t.Errorf("failure redirect dropped or altered %q: want %q, got %q", k, sent.Get(k), got.Get(k))
		}
	}
	if got.Get("error") == "" {
		t.Error("failure redirect must carry the error message for the login page")
	}
}

func TestSSOFailureWithoutKerberosKeepsAuthorizeRequest(t *testing.T) {
	h, _ := testSetup(t)
	cb := mkPKCEApp(t, h, "shop11")
	sent := oidcSSOQuery("shop11", cb)

	rec := ssoGet(h, "/login/sso?"+sent.Encode())
	lu, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || !strings.Contains(lu.Path, "/protocol/openid-connect/auth") {
		t.Fatalf("expected a redirect to the authorize page, got %d %q", rec.Code, lu)
	}
	if lu.Query().Get("state") != "the-state" || lu.Query().Get("code_challenge") != sent.Get("code_challenge") {
		t.Errorf("Kerberos-not-configured failure dropped the authorize request: %q", lu.RawQuery)
	}
}

// Without oidc=1 the hosted flow keeps its redirect to the app with ?error=. The
// retry now carries client_id, so an app whose redirect_uri is only in its own
// allowlist gets that error instead of a 400 from the default app.
func TestSSOFailureHostedFlowStillRedirectsToApp(t *testing.T) {
	h, _ := testSetup(t)
	withKeytab(t, h)
	cb := mkPKCEApp(t, h, "shop12")
	sent := url.Values{"client_id": {"shop12"}, "redirect_uri": {cb}}

	retry := negotiateRetryURL(t, h, sent)
	if retry.Query().Get("client_id") != "shop12" {
		t.Fatalf("hosted retry dropped client_id: %q", retry.RawQuery)
	}
	rec := ssoGet(h, retry.RequestURI())
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, cb+"?error=") {
		t.Fatalf("hosted SSO failure must redirect to the app with ?error=, got %d %q %s", rec.Code, loc, rec.Body.String())
	}
}
