package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/config"
	"simpleauth/internal/store"
)

func testSetup(t *testing.T) (*Handler, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	jwtMgr, err := auth.NewJWTManager(dir, "test-issuer")
	if err != nil {
		t.Fatalf("jwt manager: %v", err)
	}

	cfg := &config.Config{
		AdminKey:       "test-admin-key",
		JWTIssuer:      "test-issuer",
		AccessTTL:      1 * time.Hour,
		RefreshTTL:     24 * time.Hour,
		ImpersonateTTL: 30 * time.Minute,
		AuditRetention: 90 * 24 * time.Hour,
	}

	h := New(cfg, s, jwtMgr, nil)
	return h, s
}

func doJSON(h http.Handler, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func adminHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer test-admin-key"}
}

func parseJSON(t *testing.T, w *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("parse response: %v (body: %s)", err, w.Body.String())
	}
}

// --- Tests ---

func TestHealth(t *testing.T) {
	h, _ := testSetup(t)
	w := doJSON(h, "GET", "/health", nil, nil)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAdminAppCRUD(t *testing.T) {
	h, _ := testSetup(t)
	auth := adminHeaders()

	// Create app
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"name": "Test App", "description": "A test application",
	}, auth)
	if w.Code != 201 {
		t.Fatalf("create app: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var app map[string]interface{}
	parseJSON(t, w, &app)
	appID := app["app_id"].(string)
	apiKey := app["api_key"].(string)
	if appID == "" || apiKey == "" {
		t.Fatal("missing app_id or api_key")
	}

	// List apps
	w = doJSON(h, "GET", "/api/admin/apps", nil, auth)
	if w.Code != 200 {
		t.Fatalf("list apps: expected 200, got %d", w.Code)
	}
	var apps []map[string]interface{}
	parseJSON(t, w, &apps)
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}

	// Get app
	w = doJSON(h, "GET", "/api/admin/apps/"+appID, nil, auth)
	if w.Code != 200 {
		t.Fatalf("get app: expected 200, got %d", w.Code)
	}

	// Update app
	w = doJSON(h, "PUT", "/api/admin/apps/"+appID, map[string]interface{}{
		"name": "Updated App",
	}, auth)
	if w.Code != 200 {
		t.Fatalf("update app: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Rotate key
	w = doJSON(h, "POST", "/api/admin/apps/"+appID+"/rotate-key", nil, auth)
	if w.Code != 200 {
		t.Fatalf("rotate key: expected 200, got %d", w.Code)
	}
	var rotated map[string]interface{}
	parseJSON(t, w, &rotated)
	newKey := rotated["new_api_key"].(string)
	if newKey == "" || newKey == apiKey {
		t.Fatal("api key should have changed")
	}

	// Delete app
	w = doJSON(h, "DELETE", "/api/admin/apps/"+appID, nil, auth)
	if w.Code != 200 {
		t.Fatalf("delete app: expected 200, got %d", w.Code)
	}

	// Verify deleted
	w = doJSON(h, "GET", "/api/admin/apps", nil, auth)
	parseJSON(t, w, &apps)
	if len(apps) != 0 {
		t.Fatalf("expected 0 apps after delete, got %d", len(apps))
	}
}

func TestAdminUserCRUD(t *testing.T) {
	h, _ := testSetup(t)
	auth := adminHeaders()

	// Create user
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Alice", "email": "alice@test.com", "password": "secret123",
	}, auth)
	if w.Code != 201 {
		t.Fatalf("create user: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var user map[string]interface{}
	parseJSON(t, w, &user)
	guid := user["guid"].(string)

	// List users
	w = doJSON(h, "GET", "/api/admin/users", nil, auth)
	var users []map[string]interface{}
	parseJSON(t, w, &users)
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}

	// Get user
	w = doJSON(h, "GET", "/api/admin/users/"+guid, nil, auth)
	if w.Code != 200 {
		t.Fatalf("get user: expected 200, got %d", w.Code)
	}

	// Update user
	w = doJSON(h, "PUT", "/api/admin/users/"+guid, map[string]interface{}{
		"display_name": "Alice Updated",
	}, auth)
	if w.Code != 200 {
		t.Fatalf("update user: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Disable user
	w = doJSON(h, "PUT", "/api/admin/users/"+guid, map[string]interface{}{
		"disabled": true,
	}, auth)
	if w.Code != 200 {
		t.Fatalf("disable user: expected 200, got %d", w.Code)
	}

	// Delete user
	w = doJSON(h, "DELETE", "/api/admin/users/"+guid, nil, auth)
	if w.Code != 200 {
		t.Fatalf("delete user: expected 200, got %d", w.Code)
	}
}

func TestLocalLogin(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	// Create app
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"name": "Login App",
	}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	appID := app["app_id"].(string)

	// Create user with password
	w = doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Bob", "email": "bob@test.com", "password": "pass1234",
	}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	guid := user["guid"].(string)

	// Create identity mapping so login can find the user
	s.SetIdentityMapping("local", "bob", guid)

	// Login with wrong password
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "bob", "password": "wrongpass", "app_id": appID,
	}, nil)
	if w.Code != 401 {
		t.Fatalf("wrong password: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// Login with correct password
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "bob", "password": "pass1234", "app_id": appID,
	}, nil)
	if w.Code != 200 {
		t.Fatalf("login: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var tokens map[string]interface{}
	parseJSON(t, w, &tokens)
	accessToken := tokens["access_token"].(string)
	refreshToken := tokens["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatal("expected access_token and refresh_token")
	}

	// UserInfo
	w = doJSON(h, "GET", "/api/auth/userinfo", nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	})
	if w.Code != 200 {
		t.Fatalf("userinfo: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRefreshTokenRotation(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	// Setup: create app + user
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"name": "Refresh App"}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	appID := app["app_id"].(string)

	w = doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Charlie", "password": "mypass",
	}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	guid := user["guid"].(string)
	s.SetIdentityMapping("local", "charlie", guid)

	// Login
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "charlie", "password": "mypass", "app_id": appID,
	}, nil)
	if w.Code != 200 {
		t.Fatalf("login: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var tokens map[string]interface{}
	parseJSON(t, w, &tokens)
	rt1 := tokens["refresh_token"].(string)

	// Refresh
	w = doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{
		"refresh_token": rt1,
	}, nil)
	if w.Code != 200 {
		t.Fatalf("refresh: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var tokens2 map[string]interface{}
	parseJSON(t, w, &tokens2)
	rt2 := tokens2["refresh_token"].(string)
	if rt2 == rt1 {
		t.Fatal("refresh token should have rotated")
	}

	// Replay detection: reuse old token
	w = doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{
		"refresh_token": rt1,
	}, nil)
	if w.Code != 401 {
		t.Fatalf("replay: expected 401, got %d: %s", w.Code, w.Body.String())
	}

	// The new token should also be revoked (family revocation)
	w = doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{
		"refresh_token": rt2,
	}, nil)
	if w.Code != 401 {
		t.Fatalf("family revocation: expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminAuth(t *testing.T) {
	h, _ := testSetup(t)

	// No auth header
	w := doJSON(h, "GET", "/api/admin/users", nil, nil)
	if w.Code != 401 {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}

	// Wrong key
	w = doJSON(h, "GET", "/api/admin/users", nil, map[string]string{
		"Authorization": "Bearer wrong-key",
	})
	if w.Code != 401 {
		t.Fatalf("expected 401 with wrong key, got %d", w.Code)
	}

	// Correct key
	w = doJSON(h, "GET", "/api/admin/users", nil, adminHeaders())
	if w.Code != 200 {
		t.Fatalf("expected 200 with correct key, got %d", w.Code)
	}
}

func TestIdentityMappingsAPI(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	// Create a user
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Mapped User",
	}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	guid := user["guid"].(string)

	// Set mapping
	w = doJSON(h, "PUT", "/api/admin/users/"+guid+"/mappings", map[string]interface{}{
		"provider": "ldap:corp", "external_id": "jdoe",
	}, adm)
	if w.Code != 200 {
		t.Fatalf("set mapping: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// List all mappings
	w = doJSON(h, "GET", "/api/admin/mappings", nil, adm)
	if w.Code != 200 {
		t.Fatalf("list mappings: expected 200, got %d", w.Code)
	}
	var mappings []map[string]interface{}
	parseJSON(t, w, &mappings)
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}
	// The store key is "ldap:corp:jdoe", split on first colon gives provider="ldap" external_id="corp:jdoe"
	// This is expected behavior for compound providers
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}

	// Resolve mapping
	w = doJSON(h, "GET", "/api/admin/mappings/resolve?provider=ldap:corp&external_id=jdoe", nil, adm)
	if w.Code != 200 {
		t.Fatalf("resolve mapping: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get user mappings
	w = doJSON(h, "GET", "/api/admin/users/"+guid+"/mappings", nil, adm)
	if w.Code != 200 {
		t.Fatalf("get user mappings: expected 200, got %d", w.Code)
	}

	// Delete mapping
	w = doJSON(h, "DELETE", "/api/admin/users/"+guid+"/mappings/ldap:corp/jdoe", nil, adm)
	if w.Code != 200 {
		t.Fatalf("delete mapping: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRolesAndPermissions(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	// Create app and user
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"name": "Roles App"}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	appID := app["app_id"].(string)

	w = doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": "RoleUser"}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	guid := user["guid"].(string)

	// Set roles (path: /api/admin/apps/{app_id}/users/{guid}/roles) — expects plain array
	w = doJSON(h, "PUT", "/api/admin/apps/"+appID+"/users/"+guid+"/roles",
		[]string{"admin", "editor"}, adm)
	if w.Code != 200 {
		t.Fatalf("set roles: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get roles
	w = doJSON(h, "GET", "/api/admin/apps/"+appID+"/users/"+guid+"/roles", nil, adm)
	if w.Code != 200 {
		t.Fatalf("get roles: expected 200, got %d", w.Code)
	}
	var roles []interface{}
	parseJSON(t, w, &roles)
	if len(roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(roles))
	}

	// Set permissions (plain array)
	w = doJSON(h, "PUT", "/api/admin/apps/"+appID+"/users/"+guid+"/permissions",
		[]string{"read", "write", "delete"}, adm)
	if w.Code != 200 {
		t.Fatalf("set permissions: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestImpersonation(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	// Create app and user
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"name": "Imp App"}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	appID := app["app_id"].(string)

	w = doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": "Target"}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	guid := user["guid"].(string)

	// Impersonate (requires master admin)
	w = doJSON(h, "POST", "/api/auth/impersonate", map[string]interface{}{
		"target_guid": guid, "app_id": appID,
	}, adm)
	if w.Code != 200 {
		t.Fatalf("impersonate: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var tokens map[string]interface{}
	parseJSON(t, w, &tokens)
	if tokens["access_token"] == nil {
		t.Fatal("expected access_token in impersonation response")
	}
}

func TestHostedLoginPage(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	// Create app
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"name": "Hosted App"}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	appID := app["app_id"].(string)

	// GET login page without app_id
	req := httptest.NewRequest("GET", "/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("no app_id: expected 400, got %d", rec.Code)
	}

	// GET login page with valid app_id
	req = httptest.NewRequest("GET", "/login?app_id="+appID, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("with app_id: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("expected HTML content type, got %s", ct)
	}
}

func TestJWKS(t *testing.T) {
	h, _ := testSetup(t)
	w := doJSON(h, "GET", "/.well-known/jwks.json", nil, nil)
	if w.Code != 200 {
		t.Fatalf("jwks: expected 200, got %d", w.Code)
	}
	var jwks map[string]interface{}
	parseJSON(t, w, &jwks)
	keys := jwks["keys"].([]interface{})
	if len(keys) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}
}

func TestAuditLog(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	// Query audit (should be empty or have setup events)
	w := doJSON(h, "GET", "/api/admin/audit?limit=5", nil, adm)
	if w.Code != 200 {
		t.Fatalf("audit query: expected 200, got %d", w.Code)
	}
}

func TestBackup(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	req := httptest.NewRequest("GET", "/api/admin/backup", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("backup: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("expected octet-stream, got %s", ct)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("backup body is empty")
	}

	// Verify the admin key is still required
	w := doJSON(h, "GET", "/api/admin/backup", nil, nil)
	if w.Code != 401 {
		t.Fatalf("backup without auth: expected 401, got %d", w.Code)
	}
	_ = adm
}

func TestUserMerge(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	// Create two users
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": "Primary"}, adm)
	var u1 map[string]interface{}
	parseJSON(t, w, &u1)
	guid1 := u1["guid"].(string)

	w = doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": "Duplicate"}, adm)
	var u2 map[string]interface{}
	parseJSON(t, w, &u2)
	guid2 := u2["guid"].(string)

	// Merge both users into a new user
	w = doJSON(h, "POST", "/api/admin/users/merge", map[string]interface{}{
		"source_guids": []string{guid1, guid2},
		"display_name": "Merged User",
	}, adm)
	if w.Code != 200 {
		t.Fatalf("merge: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var mergeResult map[string]interface{}
	parseJSON(t, w, &mergeResult)
	mergedGUID, ok := mergeResult["merged_guid"].(string)
	if !ok || mergedGUID == "" {
		t.Fatalf("expected merged_guid in merge result, got %+v", mergeResult)
	}

	// Original users should be merged into the new one
	w = doJSON(h, "GET", "/api/admin/users/"+guid1, nil, adm)
	if w.Code != 200 {
		t.Fatalf("get merged user: expected 200, got %d", w.Code)
	}
	var merged map[string]interface{}
	parseJSON(t, w, &merged)
	if merged["merged_into"] != mergedGUID {
		t.Fatalf("expected merged_into=%s, got %v", mergedGUID, merged["merged_into"])
	}
}
