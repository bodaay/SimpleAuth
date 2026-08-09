package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// s256 returns the PKCE S256 challenge for a verifier (RFC 7636 §4.2).
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// mkPKCEApp registers an app with its own redirect allowlist plus a local user,
// and returns the callback URL.
func mkPKCEApp(t *testing.T, h *Handler, appID string) string {
	t.Helper()
	cb := "https://" + appID + ".example/cb"
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": appID, "audience": appID, "allow_local_users": true,
		"redirect_uris": []string{cb},
	}, adminHeaders())
	if w.Code != http.StatusCreated {
		t.Fatalf("create app %s: %d %s", appID, w.Code, w.Body.String())
	}
	var app map[string]interface{}
	parseJSON(t, w, &app)
	doJSON(h, "POST", "/api/app/users", map[string]interface{}{
		"username": "buyer", "password": "buypass1",
	}, basicAuth(appID, app["app_secret"].(string)))
	return cb
}

// postAuthz submits the authorize credential form and returns the recorder.
func postAuthz(t *testing.T, h *Handler, authzPath string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("_csrf", "tok123")
	req := httptest.NewRequest("POST", authzPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "__csrf", Value: "tok123"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestOIDCPKCESurvivesFailedLogin is the H13 regression: mistyping a password
// once must not disable PKCE for the rest of the login.
//
// Before the fix, renderOIDCLoginError rebuilt the authorize URL by hand and
// omitted code_challenge/code_challenge_method. The retry page therefore stamped
// empty hidden fields, the successful retry stored OIDCAuthCode.CodeChallenge="",
// and the token endpoint's `if ac.CodeChallenge != ""` guard became false — so
// the code redeemed with NO code_verifier at all, undoing M6.
func TestOIDCPKCESurvivesFailedLogin(t *testing.T) {
	h, _ := testSetup(t)
	const realm = "test-issuer"
	const authzPath = "/realms/" + realm + "/protocol/openid-connect/auth"
	const tokenPath = "/realms/" + realm + "/protocol/openid-connect/token"
	cb := mkPKCEApp(t, h, "shop4")

	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := s256(verifier)

	// 1. A failed attempt, carrying PKCE.
	bad := url.Values{}
	bad.Set("client_id", "shop4")
	bad.Set("redirect_uri", cb)
	bad.Set("scope", "openid")
	bad.Set("state", "st8")
	bad.Set("nonce", "nc9")
	bad.Set("code_challenge", challenge)
	bad.Set("code_challenge_method", "S256")
	bad.Set("username", "buyer")
	bad.Set("password", "WRONG-PASSWORD")
	rec := postAuthz(t, h, authzPath, bad)
	if rec.Code != http.StatusFound {
		t.Fatalf("failed login should redirect, got %d %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")

	// The error redirect must carry PKCE back to the login page.
	lu, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse error redirect: %v", err)
	}
	lq := lu.Query()
	if lq.Get("code_challenge") != challenge {
		t.Fatalf("error redirect dropped code_challenge (H13): %q", loc)
	}
	if lq.Get("code_challenge_method") != "S256" {
		t.Fatalf("error redirect dropped code_challenge_method: %q", loc)
	}
	// ...and must NOT carry credentials into a URL.
	for _, leak := range []string{"username", "password", "_csrf"} {
		if lq.Get(leak) != "" {
			t.Fatalf("error redirect leaked %q into the Location header: %q", leak, loc)
		}
	}

	// 2. Follow the redirect: the retry page must re-stamp the challenge.
	greq := httptest.NewRequest("GET", loc, nil)
	grec := httptest.NewRecorder()
	h.ServeHTTP(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("retry page: %d %s", grec.Code, grec.Body.String())
	}
	if !strings.Contains(grec.Body.String(), `name="code_challenge" value="`+challenge+`"`) {
		t.Fatal("retry page must re-stamp code_challenge into the form (H13)")
	}

	// 3. The successful retry — using the fields the retry page actually rendered.
	good := url.Values{}
	for k, v := range lq {
		if k == "error" || k == "response_type" {
			continue
		}
		good.Set(k, v[0])
	}
	good.Set("username", "buyer")
	good.Set("password", "buypass1")
	prec := postAuthz(t, h, authzPath, good)
	if prec.Code != http.StatusFound {
		t.Fatalf("retry login: %d %s", prec.Code, prec.Body.String())
	}
	cbURL, _ := url.Parse(prec.Header().Get("Location"))
	code := cbURL.Query().Get("code")
	if code == "" {
		t.Fatalf("expected an auth code, got %q", prec.Header().Get("Location"))
	}

	// 4. THE POINT: that code must still require a verifier.
	noVerifier := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb}}
	nreq := httptest.NewRequest("POST", tokenPath, strings.NewReader(noVerifier.Encode()))
	nreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	nrec := httptest.NewRecorder()
	h.ServeHTTP(nrec, nreq)
	if nrec.Code == http.StatusOK {
		t.Fatal("code redeemed with NO code_verifier after a failed login — PKCE was dropped (H13)")
	}

	// And the correct verifier must still work. The code above was consumed on
	// the failed attempt, so drive a fresh round trip for the positive case.
	good2 := url.Values{}
	for k, v := range good {
		good2.Set(k, v[0])
	}
	prec2 := postAuthz(t, h, authzPath, good2)
	cbURL2, _ := url.Parse(prec2.Header().Get("Location"))
	code2 := cbURL2.Query().Get("code")
	if code2 == "" {
		t.Fatalf("second round trip produced no code: %q", prec2.Header().Get("Location"))
	}
	withVerifier := url.Values{
		"grant_type": {"authorization_code"}, "code": {code2},
		"redirect_uri": {cb}, "code_verifier": {verifier},
	}
	vreq := httptest.NewRequest("POST", tokenPath, strings.NewReader(withVerifier.Encode()))
	vreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vrec := httptest.NewRecorder()
	h.ServeHTTP(vrec, vreq)
	if vrec.Code != http.StatusOK {
		t.Fatalf("correct code_verifier must succeed, got %d %s", vrec.Code, vrec.Body.String())
	}
}

// TestOIDCLoginErrorPreservesAuthorizeRequest pins the whole allowlist, not just
// PKCE — every parameter the client sent must survive the error hop, so a future
// parameter added to oidcAuthzRequest cannot be silently dropped at this hop.
func TestOIDCLoginErrorPreservesAuthorizeRequest(t *testing.T) {
	h, _ := testSetup(t)
	const authzPath = "/realms/test-issuer/protocol/openid-connect/auth"
	cb := mkPKCEApp(t, h, "shop5")

	form := url.Values{}
	form.Set("client_id", "shop5")
	form.Set("redirect_uri", cb)
	form.Set("state", "the-state")
	form.Set("nonce", "the-nonce")
	form.Set("scope", "openid email")
	form.Set("code_challenge", s256("v"))
	form.Set("code_challenge_method", "S256")
	form.Set("username", "buyer")
	form.Set("password", "nope")

	rec := postAuthz(t, h, authzPath, form)
	lu, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := lu.Query()
	for _, k := range []string{"client_id", "redirect_uri", "state", "nonce", "scope", "code_challenge", "code_challenge_method"} {
		if q.Get(k) != form.Get(k) {
			t.Errorf("error redirect dropped or altered %q: want %q, got %q", k, form.Get(k), q.Get(k))
		}
	}
	if q.Get("error") == "" {
		t.Error("error redirect must carry the error message")
	}
	// The target is SimpleAuth's own authorize endpoint, never the client's
	// redirect_uri — the empty-credentials branch reaches here before redirect_uri
	// is allowlist-checked, so bouncing to it would be an open redirect.
	if !strings.Contains(lu.Path, "/protocol/openid-connect/auth") {
		t.Errorf("error must return to SimpleAuth's authorize page, got %q", lu.Path)
	}
}

// TestOIDCLoginErrorWithNoCredentials covers the branch that reaches
// renderOIDCLoginError BEFORE redirect_uri has been validated: it must still
// land on SimpleAuth's own page and must not reflect an unvalidated destination.
func TestOIDCLoginErrorWithNoCredentials(t *testing.T) {
	h, _ := testSetup(t)
	const authzPath = "/realms/test-issuer/protocol/openid-connect/auth"
	mkPKCEApp(t, h, "shop6")

	form := url.Values{}
	form.Set("client_id", "shop6")
	form.Set("redirect_uri", "https://evil.example/steal")
	// username and password deliberately absent
	rec := postAuthz(t, h, authzPath, form)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if strings.HasPrefix(loc, "https://evil.example") {
		t.Fatalf("open redirect: bounced to an unvalidated redirect_uri: %q", loc)
	}
	if !strings.Contains(loc, "/protocol/openid-connect/auth") {
		t.Fatalf("expected SimpleAuth's own authorize page, got %q", loc)
	}
}

// TestLogoutPreservesClientID pins the handleLogout half of the same defect
// class: GET /login 400s on an unknown client_id and validates redirect_uri
// against THAT app's allowlist, so dropping client_id dead-ends the documented
// logout round trip for any app with its own redirect_uris.
func TestLogoutPreservesClientID(t *testing.T) {
	h, _ := testSetup(t)
	cb := mkPKCEApp(t, h, "shop7")

	req := httptest.NewRequest("GET", "/logout?client_id=shop7&redirect_uri="+url.QueryEscape(cb), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("logout should redirect, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "client_id=shop7") {
		t.Fatalf("logout must carry client_id onto the login page, got %q", loc)
	}

	// And the resulting login page must actually render (not 400) — the whole
	// point: the app's own redirect_uri is only allowlisted for the app itself.
	greq := httptest.NewRequest("GET", loc, nil)
	grec := httptest.NewRecorder()
	h.ServeHTTP(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("post-logout login page must render, got %d %s", grec.Code, grec.Body.String())
	}
}
