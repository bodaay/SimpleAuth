package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// oidcCodeFlowTokens drives authorize → code → token for the app-local "buyer"
// user that mkPKCEApp creates, and returns the token endpoint's JSON response.
func oidcCodeFlowTokens(t *testing.T, h *Handler, appID, cb string) map[string]interface{} {
	t.Helper()
	const realm = "test-issuer"
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	form := url.Values{}
	form.Set("client_id", appID)
	form.Set("redirect_uri", cb)
	form.Set("scope", "openid profile email")
	form.Set("state", "st")
	form.Set("nonce", "nc")
	form.Set("code_challenge", s256(verifier))
	form.Set("code_challenge_method", "S256")
	form.Set("username", "buyer")
	form.Set("password", "buypass1")
	rec := postAuthz(t, h, "/realms/"+realm+"/protocol/openid-connect/auth", form)
	cbURL, _ := url.Parse(rec.Header().Get("Location"))
	code := cbURL.Query().Get("code")
	if code == "" {
		t.Fatalf("no auth code: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	exchange := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {cb}, "code_verifier": {verifier},
	}
	req := httptest.NewRequest("POST", "/realms/"+realm+"/protocol/openid-connect/token", strings.NewReader(exchange.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	trec := httptest.NewRecorder()
	h.ServeHTTP(trec, req)
	if trec.Code != http.StatusOK {
		t.Fatalf("token exchange: %d %s", trec.Code, trec.Body.String())
	}
	var tokens map[string]interface{}
	if err := json.Unmarshal(trec.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("token response: %v", err)
	}
	return tokens
}

func oidcUserinfo(t *testing.T, h *Handler, accessToken string) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest("GET", "/realms/test-issuer/protocol/openid-connect/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo: %d %s", rec.Code, rec.Body.String())
	}
	var info map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("userinfo response: %v", err)
	}
	return info
}

func setBuyerNames(t *testing.T, s store.Store, appID, given, family string) {
	t.Helper()
	guid, err := s.ResolveMapping("applocal:"+appID, "buyer")
	if err != nil {
		t.Fatalf("resolve buyer: %v", err)
	}
	u, err := s.GetUser(guid)
	if err != nil {
		t.Fatalf("get buyer: %v", err)
	}
	u.DisplayName, u.GivenName, u.FamilyName = given+" "+family, given, family
	if err := s.UpdateUser(u); err != nil {
		t.Fatalf("update buyer: %v", err)
	}
}

// OIDC relying parties (OpenProject among them) build a user's first and last name
// from the standard profile claims; with only `name` they put the whole display
// name into the first name and ask the user for a last name on first login.
func TestOIDCTokensCarryGivenAndFamilyName(t *testing.T) {
	h, s := testSetup(t)
	cb := mkPKCEApp(t, h, "names1")
	setBuyerNames(t, s, "names1", "سالم", "المري")

	tokens := oidcCodeFlowTokens(t, h, "names1", cb)
	sources := map[string]map[string]interface{}{
		"id_token":     decodeJWTPayload(t, tokens["id_token"].(string)),
		"access_token": decodeJWTPayload(t, tokens["access_token"].(string)),
		"userinfo":     oidcUserinfo(t, h, tokens["access_token"].(string)),
	}
	for source, claims := range sources {
		if claims["given_name"] != "سالم" || claims["family_name"] != "المري" {
			t.Errorf("%s: given_name=%v family_name=%v", source, claims["given_name"], claims["family_name"])
		}
	}
}

func TestOIDCTokensOmitUnknownNames(t *testing.T) {
	h, _ := testSetup(t)
	cb := mkPKCEApp(t, h, "names2")

	tokens := oidcCodeFlowTokens(t, h, "names2", cb)
	idToken := decodeJWTPayload(t, tokens["id_token"].(string))
	info := oidcUserinfo(t, h, tokens["access_token"].(string))
	for _, claims := range []map[string]interface{}{idToken, info} {
		if _, ok := claims["given_name"]; ok {
			t.Errorf("given_name must be omitted when unknown, got %v", claims["given_name"])
		}
		if _, ok := claims["family_name"]; ok {
			t.Errorf("family_name must be omitted when unknown, got %v", claims["family_name"])
		}
	}
}

func TestOIDCDiscoveryAdvertisesNameClaims(t *testing.T) {
	h, _ := testSetup(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/realms/test-issuer/.well-known/openid-configuration", nil))
	var doc struct {
		ClaimsSupported []string `json:"claims_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("discovery: %d %v", rec.Code, err)
	}
	for _, want := range []string{"given_name", "family_name"} {
		found := false
		for _, c := range doc.ClaimsSupported {
			found = found || c == want
		}
		if !found {
			t.Errorf("claims_supported is missing %q: %v", want, doc.ClaimsSupported)
		}
	}
}

func TestLDAPConfigDefaultsNameAttributes(t *testing.T) {
	cfg := ldapConfigFromStore(&store.LDAPConfig{})
	if cfg.GivenNameAttr != "givenName" || cfg.FamilyNameAttr != "sn" {
		t.Errorf("unset name attributes must default to AD's givenName/sn, got %q/%q", cfg.GivenNameAttr, cfg.FamilyNameAttr)
	}
	custom := ldapConfigFromStore(&store.LDAPConfig{GivenNameAttr: "firstName", FamilyNameAttr: "lastName"})
	if custom.GivenNameAttr != "firstName" || custom.FamilyNameAttr != "lastName" {
		t.Errorf("configured name attributes must be kept, got %q/%q", custom.GivenNameAttr, custom.FamilyNameAttr)
	}
}

func TestSyncUserFromLDAPUpdatesNames(t *testing.T) {
	h, s := testSetup(t)
	u := &store.User{DisplayName: "John Doe", SAMAccountName: "jdoe"}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create: %v", err)
	}

	h.syncUserFromLDAP(u, &auth.LDAPResult{Username: "jdoe", DisplayName: "John Doe", GivenName: "John", FamilyName: "Doe"})
	got, _ := s.GetUser(u.GUID)
	if got.GivenName != "John" || got.FamilyName != "Doe" {
		t.Fatalf("sync must store the directory names, got %q/%q", got.GivenName, got.FamilyName)
	}

	h.syncUserFromLDAP(got, &auth.LDAPResult{Username: "jdoe", DisplayName: "John Doe-Smith", GivenName: "John", FamilyName: "Doe-Smith"})
	got, _ = s.GetUser(u.GUID)
	if got.FamilyName != "Doe-Smith" {
		t.Fatalf("a renamed directory account must update family_name, got %q", got.FamilyName)
	}
}
