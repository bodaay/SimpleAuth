package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"simpleauth/internal/auth"
)

// The OIDC authorization-code flow minted access tokens with no `groups` claim:
// issueOIDCTokens and the refresh grant passed nil groups to
// buildOIDCAccessClaims. Both userinfo endpoints read groups from the token, so
// a code-flow user's directory groups appeared nowhere, while a direct login's
// token carried them.
//
// A direct login's groups are the directory's groups for the person, as bare
// CNs (entryToResult), never filtered per app; syncUserFromLDAP stores exactly
// that set on the user during the same login. The code flow therefore takes the
// person's stored groups when it mints a token: the same set, from the same
// source, in the same form, and the same set resolveTokenRoles reads for the
// app's group assignments.
//
// Unit tests have no directory, so these users sign in with a password and get
// their groups through syncUserFromLDAP, the only writer of User.Groups.

const grpRealm = "test-issuer"
const grpVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// grpApp registers a named app with its own redirect allowlist and the given
// per-app authz, and returns its callback URL and app secret.
func grpApp(t *testing.T, h *Handler, appID string, requireAssignment bool, authz map[string]interface{}) (string, string) {
	t.Helper()
	cb := "https://" + appID + ".example/cb"
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": appID, "audience": appID, "redirect_uris": []string{cb},
		"require_assignment": requireAssignment,
	}, adminHeaders())
	if w.Code != http.StatusCreated {
		t.Fatalf("create app %s: %d %s", appID, w.Code, w.Body.String())
	}
	var app map[string]interface{}
	parseJSON(t, w, &app)
	if authz != nil {
		if w := doJSON(h, "PUT", "/api/admin/apps/"+appID+"/authz", authz, adminHeaders()); w.Code != http.StatusOK {
			t.Fatalf("set %s authz: %d %s", appID, w.Code, w.Body.String())
		}
	}
	return cb, app["app_secret"].(string)
}

// grpUser creates a global user who signs in with a password and stores the
// given directory groups the way every directory login does.
func grpUser(t *testing.T, h *Handler, username string, groups ...string) string {
	t.Helper()
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"username": username, "password": "pass1234", "display_name": username,
	}, adminHeaders())
	if w.Code != http.StatusCreated {
		t.Fatalf("create user %s: %d %s", username, w.Code, w.Body.String())
	}
	var u map[string]interface{}
	parseJSON(t, w, &u)
	guid := u["guid"].(string)
	grpSync(t, h, guid, username, groups)
	return guid
}

// grpSetGroups replaces a user's stored directory groups through
// syncUserFromLDAP, as the next directory login would.
func grpSetGroups(t *testing.T, h *Handler, guid string, groups ...string) {
	t.Helper()
	u, err := h.store.GetUser(guid)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	grpSync(t, h, guid, u.SAMAccountName, groups)
}

func grpSync(t *testing.T, h *Handler, guid, sam string, groups []string) {
	t.Helper()
	u, err := h.store.GetUser(guid)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	h.syncUserFromLDAP(u, &auth.LDAPResult{Username: sam, DisplayName: u.DisplayName, Groups: groups})
	got, err := h.store.GetUser(guid)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if got.SAMAccountName != sam || !slices.Equal(got.Groups, groups) {
		t.Fatalf("stored sam=%q groups=%v, want %q %v", got.SAMAccountName, got.Groups, sam, groups)
	}
}

// grpCodeFlow drives authorize (credential POST) → code → token exchange with
// PKCE and returns the token endpoint's JSON response.
func grpCodeFlow(t *testing.T, h *Handler, appID, cb, username string) map[string]interface{} {
	t.Helper()
	form := url.Values{}
	form.Set("client_id", appID)
	form.Set("redirect_uri", cb)
	form.Set("scope", "openid profile email")
	form.Set("state", "st")
	form.Set("nonce", "nc")
	form.Set("code_challenge", s256(grpVerifier))
	form.Set("code_challenge_method", "S256")
	form.Set("username", username)
	form.Set("password", "pass1234")
	rec := postAuthz(t, h, "/realms/"+grpRealm+"/protocol/openid-connect/auth", form)
	cbURL, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse callback: %v", err)
	}
	code := cbURL.Query().Get("code")
	if code == "" {
		t.Fatalf("no auth code: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	return grpToken(t, h, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {cb}, "code_verifier": {grpVerifier},
	})
}

// grpToken posts a grant to the OIDC token endpoint and returns the JSON answer.
func grpToken(t *testing.T, h *Handler, form url.Values) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest("POST", "/realms/"+grpRealm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token %s: %d %s", form.Get("grant_type"), rec.Code, rec.Body.String())
	}
	var tokens map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("token response: %v", err)
	}
	return tokens
}

// grpRefresh redeems a refresh token at the OIDC refresh_token grant.
func grpRefresh(t *testing.T, h *Handler, refreshToken string) map[string]interface{} {
	t.Helper()
	return grpToken(t, h, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

// grpGet calls a bearer-protected GET endpoint and returns its JSON answer.
func grpGet(t *testing.T, h *Handler, path, accessToken string) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s response: %v", path, err)
	}
	return out
}

// grpStrings reads a JSON string array member. ok is false when the member is
// absent; a present null reads as (nil, true).
func grpStrings(t *testing.T, m map[string]interface{}, key string) ([]string, bool) {
	t.Helper()
	v, ok := m[key]
	if !ok || v == nil {
		return nil, ok
	}
	arr, isArr := v.([]interface{})
	if !isArr {
		t.Fatalf("%s is %T (%v), want a string array", key, v, v)
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, isStr := e.(string)
		if !isStr {
			t.Fatalf("%s holds %T (%v), want strings", key, e, e)
		}
		out = append(out, s)
	}
	return out, true
}

// grpAssertGroups checks that an access token's `groups` claim, the OIDC
// userinfo answer and /api/auth/userinfo all hold exactly want, in order.
func grpAssertGroups(t *testing.T, h *Handler, label, accessToken string, want []string) {
	t.Helper()
	sources := []struct {
		name string
		m    map[string]interface{}
	}{
		{"access token", decodeJWTPayload(t, accessToken)},
		{"OIDC userinfo", grpGet(t, h, "/realms/"+grpRealm+"/protocol/openid-connect/userinfo", accessToken)},
		{"/api/auth/userinfo", grpGet(t, h, "/api/auth/userinfo", accessToken)},
	}
	for _, src := range sources {
		got, present := grpStrings(t, src.m, "groups")
		if !present || !slices.Equal(got, want) {
			t.Errorf("%s: %s groups = %v (present=%v), want exactly %v", label, src.name, got, present, want)
		}
	}
}

// grpAssertNoGroups checks the answers a direct login gives a user with no
// groups: no `groups` claim in the token, no `groups` member in OIDC userinfo,
// and `groups: null` from /api/auth/userinfo (which always lists the member).
func grpAssertNoGroups(t *testing.T, h *Handler, label, accessToken string) {
	t.Helper()
	if v, ok := decodeJWTPayload(t, accessToken)["groups"]; ok {
		t.Errorf("%s: access token carries groups %v, want the claim omitted", label, v)
	}
	if v, ok := grpGet(t, h, "/realms/"+grpRealm+"/protocol/openid-connect/userinfo", accessToken)["groups"]; ok {
		t.Errorf("%s: OIDC userinfo carries groups %v, want the member omitted", label, v)
	}
	info := grpGet(t, h, "/api/auth/userinfo", accessToken)
	if v, ok := info["groups"]; !ok || v != nil {
		t.Errorf("%s: /api/auth/userinfo groups = %v (present=%v), want null", label, v, ok)
	}
}

// TestOIDCCodeFlowCarriesGroups: a person signed in through the code flow gets
// their stored directory groups in the access token, the OIDC userinfo answer
// and /api/auth/userinfo, exactly and unfiltered by the app (a direct login
// never filters groups per app; only roles are per app).
func TestOIDCCodeFlowCarriesGroups(t *testing.T) {
	h, _ := testSetup(t)
	cb, _ := grpApp(t, h, "cortex", true, map[string]interface{}{
		"roles":             []string{"analyst"},
		"group_assignments": map[string][]string{"CORTEX-Analysts": {"analyst"}},
	})
	grpUser(t, h, "an", "CORTEX-Analysts", "Team-B")
	grpUser(t, h, "other", "Domain Admins")

	tokens := grpCodeFlow(t, h, "cortex", cb, "an")
	at := tokens["access_token"].(string)
	grpAssertGroups(t, h, "code exchange", at, []string{"CORTEX-Analysts", "Team-B"})

	// Roles stay per app and group-derived, from the same stored set.
	if roles := tokenRoles(t, at); !slices.Equal(roles, []string{"analyst"}) {
		t.Errorf("roles = %v, want [analyst]", roles)
	}
	// The id_token's contents are unchanged: no groups there.
	if v, ok := decodeJWTPayload(t, tokens["id_token"].(string))["groups"]; ok {
		t.Errorf("id_token carries groups %v; its contents must not change", v)
	}
}

// TestOIDCRefreshCarriesCurrentGroups: every OIDC refresh grant re-reads the
// person's stored groups, so a refreshed token carries the current set, and a
// person the directory has removed from every group gets no groups at all,
// never the set they signed in with.
func TestOIDCRefreshCarriesCurrentGroups(t *testing.T) {
	h, _ := testSetup(t)
	cb, _ := grpApp(t, h, "cortexr", false, map[string]interface{}{
		"roles":             []string{"analyst"},
		"group_assignments": map[string][]string{"CORTEX-Analysts": {"analyst"}},
	})
	guid := grpUser(t, h, "an", "CORTEX-Analysts", "Team-B")
	grpUser(t, h, "other", "Domain Admins")

	tokens := grpCodeFlow(t, h, "cortexr", cb, "an")
	grpAssertGroups(t, h, "code exchange", tokens["access_token"].(string), []string{"CORTEX-Analysts", "Team-B"})

	// Unchanged groups: the refreshed token carries them.
	refreshed := grpRefresh(t, h, tokens["refresh_token"].(string))
	grpAssertGroups(t, h, "refresh, unchanged", refreshed["access_token"].(string), []string{"CORTEX-Analysts", "Team-B"})

	// The directory moved the person from Team-B to Team-C since sign-in.
	grpSetGroups(t, h, guid, "CORTEX-Analysts", "Team-C")
	refreshed = grpRefresh(t, h, refreshed["refresh_token"].(string))
	grpAssertGroups(t, h, "refresh after a move", refreshed["access_token"].(string), []string{"CORTEX-Analysts", "Team-C"})

	// The directory removed the person from every group.
	grpSetGroups(t, h, guid)
	refreshed = grpRefresh(t, h, refreshed["refresh_token"].(string))
	grpAssertNoGroups(t, h, "refresh after removal from every group", refreshed["access_token"].(string))
	if roles := tokenRoles(t, refreshed["access_token"].(string)); len(roles) != 0 {
		t.Errorf("roles after removal = %v, want none", roles)
	}
}

// TestOIDCCodeFlowOmitsGroupsForUserWithNone: a person with no groups gets the
// same answers from the code flow as from a direct login: no claim, no OIDC
// userinfo member, null from /api/auth/userinfo. Never another user's set.
func TestOIDCCodeFlowOmitsGroupsForUserWithNone(t *testing.T) {
	h, _ := testSetup(t)
	cb, _ := grpApp(t, h, "plain", false, nil)
	grpUser(t, h, "nogroups")
	grpUser(t, h, "an", "CORTEX-Analysts", "Team-B")

	// The direct login's answers for this person.
	w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "nogroups", "password": "pass1234", "app_id": "plain",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("direct login: %d %s", w.Code, w.Body.String())
	}
	var direct map[string]interface{}
	parseJSON(t, w, &direct)
	grpAssertNoGroups(t, h, "direct login", direct["access_token"].(string))

	// The code flow and its refresh give the same answers.
	tokens := grpCodeFlow(t, h, "plain", cb, "nogroups")
	grpAssertNoGroups(t, h, "code exchange", tokens["access_token"].(string))
	refreshed := grpRefresh(t, h, tokens["refresh_token"].(string))
	grpAssertNoGroups(t, h, "refresh", refreshed["access_token"].(string))
}

// TestOIDCPasswordGrantCarriesGroups: the OIDC password grant mints through
// issueOIDCTokens, as the code exchange does, so its token carries the same
// groups a direct password login's token does.
func TestOIDCPasswordGrantCarriesGroups(t *testing.T) {
	h, _ := testSetup(t)
	_, secret := grpApp(t, h, "cortexp", false, nil)
	grpUser(t, h, "an", "CORTEX-Analysts", "Team-B")
	grpUser(t, h, "other", "Domain Admins")

	tokens := grpToken(t, h, url.Values{
		"grant_type": {"password"}, "client_id": {"cortexp"}, "client_secret": {secret},
		"username": {"an"}, "password": {"pass1234"},
	})
	grpAssertGroups(t, h, "password grant", tokens["access_token"].(string), []string{"CORTEX-Analysts", "Team-B"})
}
