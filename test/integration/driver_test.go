//go:build integration

// Package integration drives the multi-container topology in docker-compose.yml.
// It is excluded from the normal build/test by the `integration` tag; run it with
// `make test` (which stands up the stack and points ITEST_CA_FILE at the CA).
package integration

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"simpleauth/internal/migrate"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

var (
	centralURL      = env("ITEST_CENTRAL_URL", "https://127.0.0.1:9443")
	centralInternal = env("ITEST_CENTRAL_INTERNAL", "https://central:8080")
	standaloneURL   = env("ITEST_STANDALONE_URL", "http://127.0.0.1:9447")
	standaloneADURL = env("ITEST_STANDALONE_AD_URL", "http://127.0.0.1:9445")
	centralKey      = env("ITEST_CENTRAL_KEY", "central-admin-key")
	standaloneKey   = env("ITEST_STANDALONE_KEY", "local-admin-key")
	standaloneADKey = env("ITEST_STANDALONE_AD_KEY", "ad-admin-key")
)

// node is a thin admin-API client for one SimpleAuth instance.
type node struct {
	base, key string
	c         *http.Client
}

// request is the single request path for a node; auth stamps the credentials
// (admin bearer for do/must, app Basic for doBasic).
func (n *node) request(t *testing.T, method, path string, body any, auth func(*http.Request)) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, n.base+path, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != nil {
		auth(req)
	}
	resp, err := n.c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func (n *node) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	return n.request(t, method, path, body, func(req *http.Request) {
		if n.key != "" {
			req.Header.Set("Authorization", "Bearer "+n.key)
		}
	})
}

// doBasic issues a request authenticated with app credentials (HTTP Basic)
// instead of the admin bearer key — the /api/app/* self-service flow.
func (n *node) doBasic(t *testing.T, method, path, id, secret string) (int, []byte) {
	t.Helper()
	return n.request(t, method, path, nil, func(req *http.Request) {
		req.SetBasicAuth(id, secret)
	})
}

func (n *node) must(t *testing.T, method, path string, body any) []byte {
	t.Helper()
	code, data := n.do(t, method, path, body)
	if code < 200 || code >= 300 {
		t.Fatalf("%s %s -> %d: %s", method, path, code, data)
	}
	return data
}

// decode unmarshals a JSON response body, failing the test on malformed JSON
// rather than letting a zero value produce a misleading assertion failure later.
func decode(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode response %q: %v", data, err)
	}
}

// caClient trusts the integration CA so the host-side driver can validate the
// central's HTTPS cert.
func caClient() *http.Client {
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(env("ITEST_CA_FILE", "test/integration/certs/ca.crt")); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

func waitReady(t *testing.T, name, base string, c *http.Client) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := c.Get(base + "/health"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s not ready at %s", name, base)
}

func tokenClaims(t *testing.T, jwt string) (roles, perms, aud []string) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		t.Fatalf("malformed jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode jwt payload: %v", err)
	}
	var c struct {
		Roles []string `json:"roles"`
		Perms []string `json:"permissions"`
		Aud   any      `json:"aud"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	switch a := c.Aud.(type) {
	case string:
		aud = []string{a}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				aud = append(aud, s)
			}
		}
	}
	return c.Roles, c.Perms, aud
}

func has(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// login performs a SINGLE login attempt and returns the access token. Use it
// for deterministic (local-account) logins; use loginRetry only for LDAP-backed
// logins that may race the directory's bootstrap.
func login(t *testing.T, n *node, username, password, appID string) string {
	t.Helper()
	body := map[string]any{"username": username, "password": password}
	if appID != "" {
		body["app_id"] = appID
	}
	var r struct {
		AccessToken string `json:"access_token"`
	}
	decode(t, n.must(t, "POST", "/api/auth/login", body), &r)
	if r.AccessToken == "" {
		t.Fatalf("login %q: no access token in response", username)
	}
	return r.AccessToken
}

// mintToken mints a single-use migration token for an app on the central.
func mintToken(t *testing.T, central *node, appID string) string {
	t.Helper()
	var tok struct {
		Token string `json:"migration_token"`
	}
	decode(t, central.must(t, "POST", "/api/admin/apps/"+appID+"/migration-token", nil), &tok)
	if tok.Token == "" {
		t.Fatalf("no migration token for %s", appID)
	}
	return tok.Token
}

// migPayload mints a fresh token and builds the migrate-to-central request body.
func migPayload(t *testing.T, central *node, appID string, carrySecret bool) map[string]any {
	t.Helper()
	mig := map[string]any{"central_url": centralInternal, "app_id": appID, "token": mintToken(t, central, appID)}
	if carrySecret {
		mig["carry_secret"] = true
	}
	return mig
}

// newMigTarget creates a fresh app on the central and returns the migration
// payload a standalone posts to move into it.
func newMigTarget(t *testing.T, central *node, appID string, carrySecret bool) map[string]any {
	t.Helper()
	central.must(t, "POST", "/api/admin/apps", map[string]any{"app_id": appID, "audience": appID})
	return migPayload(t, central, appID, carrySecret)
}

// newMigTargetFrom creates the central target app AND first gives the SOURCE's
// home app a deliberate audience.
//
// A stock standalone's home app carries the default audience "simpleauth" — which
// is also the CENTRAL's default-app audience. Since H15 the central refuses a
// bundle claiming it, because that is the no-effort version of the audience
// takeover: the migrated app would mint tokens the central's global directory app
// consumers accept. Real migrations must therefore set a deliberate audience on
// the source before packaging; these tests model that rather than relying on the
// collision the old code silently allowed.
func newMigTargetFrom(t *testing.T, central, source *node, appID string, carrySecret bool) map[string]any {
	t.Helper()
	source.must(t, "PUT", "/api/admin/apps/simpleauth", map[string]any{"audience": appID + "-src-aud"})
	return newMigTarget(t, central, appID, carrySecret)
}

// TestLocalToCentralMigration: a local-accounts standalone migrates into a fresh
// app on the central over real cross-container TLS; the migrated user then logs
// in AGAINST THE CENTRAL with the same password and gets the right roles/perms.
func TestLocalToCentralMigration(t *testing.T) {
	central := &node{centralURL, centralKey, caClient()}
	standalone := &node{standaloneURL, standaloneKey, &http.Client{Timeout: 20 * time.Second}}

	waitReady(t, "central", centralURL, central.c)
	waitReady(t, "standalone-local", standaloneURL, standalone.c)

	// --- seed the standalone: role catalog + a local user with a role ---
	standalone.must(t, "PUT", "/api/admin/permissions", []string{"invoice:read", "invoice:write"})
	standalone.must(t, "PUT", "/api/admin/role-permissions", map[string][]string{
		"clerk": {"invoice:read"},
		"admin": {"invoice:read", "invoice:write"},
	})
	var u struct {
		GUID string `json:"guid"`
	}
	decode(t, standalone.must(t, "POST", "/api/admin/users", map[string]any{
		"display_name": "Alice", "password": "alicepass123",
	}), &u)
	standalone.must(t, "PUT", "/api/admin/users/"+u.GUID+"/mappings", map[string]any{"provider": "local", "external_id": "alice"})
	standalone.must(t, "PUT", "/api/admin/users/"+u.GUID+"/roles", []string{"admin"})
	// Give the standalone's home app a distinctive audience so we can prove the
	// migration CARRIES it onto the target (the consumer app keeps its own aud).
	standalone.must(t, "PUT", "/api/admin/apps/simpleauth", map[string]any{"audience": "standalone-app-aud"})

	// --- central: create the target app + mint a single-use migration token ---
	central.must(t, "POST", "/api/admin/apps", map[string]any{"app_id": "billing", "audience": "billing"})
	tok := mintToken(t, central, "billing")

	// --- guard: a cleartext http push to the (non-loopback) central is refused ---
	if code, _ := standalone.do(t, "POST", "/api/admin/migrate-to-central/preflight", map[string]any{
		"central_url": "http://central:8080", "app_id": "billing", "token": tok,
	}); code != http.StatusBadRequest {
		t.Fatalf("cleartext http migration push must be 400, got %d", code)
	}

	mig := map[string]any{"central_url": centralInternal, "app_id": "billing", "token": tok, "carry_secret": true}

	// --- preflight (dry run) over real TLS ---
	var rep migrate.Report
	json.Unmarshal(standalone.must(t, "POST", "/api/admin/migrate-to-central/preflight", mig), &rep)
	if !rep.OK() || rep.LocalUsers != 1 {
		t.Fatalf("preflight: want 1 local user and nothing blocked; got %+v", rep)
	}

	// --- commit ---
	var res migrate.ApplyResult
	json.Unmarshal(standalone.must(t, "POST", "/api/admin/migrate-to-central/commit", mig), &res)
	if res.AssignmentsSet != 1 || res.LocalUsersCreated != 1 {
		t.Fatalf("commit result: %+v", res)
	}

	// --- the import landed on the central ---
	var az struct {
		UserAssignments map[string][]string `json:"user_assignments"`
	}
	json.Unmarshal(central.must(t, "GET", "/api/admin/apps/billing/authz", nil), &az)
	if got := az.UserAssignments["alice"]; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("central billing assignment for alice = %v, want [admin]", got)
	}

	// --- the migrated user authenticates AGAINST THE CENTRAL (carried hash) ---
	var login struct {
		AccessToken string `json:"access_token"`
	}
	json.Unmarshal(central.must(t, "POST", "/api/auth/login", map[string]any{
		"username": "alice", "password": "alicepass123", "app_id": "billing",
	}), &login)
	roles, perms, aud := tokenClaims(t, login.AccessToken)
	if !has(roles, "admin") {
		t.Fatalf("central token roles = %v, want admin", roles)
	}
	if !has(perms, "invoice:write") {
		t.Fatalf("central token perms = %v, want invoice:write", perms)
	}
	// aud is the CARRIED source audience, not "billing" — that is the guarantee
	// that lets the consumer app keep its existing token validation after cutover.
	if !has(aud, "standalone-app-aud") {
		t.Fatalf("central token aud = %v, want carried source audience standalone-app-aud", aud)
	}
	t.Logf("OK: standalone-local migrated into central; alice authenticates on central roles=%v perms=%v aud=%v (carried)", roles, perms, aud)
}
