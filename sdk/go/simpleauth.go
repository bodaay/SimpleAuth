// Package simpleauth provides a Go SDK for SimpleAuth, an OIDC-compatible
// authentication server. It includes token acquisition, JWT verification with
// JWKS caching, user helpers, and HTTP middleware.
package simpleauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// Options configures a new Client.
type Options struct {
	URL               string // SimpleAuth server URL (e.g. "https://auth.example.com")
	AppID             string // Application / client ID
	AppSecret         string // Application API key / client secret
	Realm             string // OIDC realm (default "simpleauth")
	InsecureSkipVerify bool  // Allow self-signed TLS certificates
}

// TokenResponse is the OAuth2 token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// User represents the claims extracted from a verified JWT.
type User struct {
	Sub              string   `json:"sub"`
	Name             string   `json:"name,omitempty"`
	Email            string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Roles            []string `json:"roles,omitempty"`
	Permissions      []string `json:"permissions,omitempty"`
	Groups           []string `json:"groups,omitempty"`
	Department       string   `json:"department,omitempty"`
	Company          string   `json:"company,omitempty"`
	JobTitle         string   `json:"job_title,omitempty"`
	AppID            string   `json:"app_id,omitempty"`
}

// HasRole returns true if the user has the given role.
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission returns true if the user has the given permission.
func (u *User) HasPermission(perm string) bool {
	for _, p := range u.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// HasAnyRole returns true if the user has at least one of the given roles.
func (u *User) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if u.HasRole(role) {
			return true
		}
	}
	return false
}

// UserInfo holds the response from the OIDC userinfo endpoint.
type UserInfo struct {
	Sub              string `json:"sub"`
	Name             string `json:"name,omitempty"`
	Email            string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	EmailVerified    bool   `json:"email_verified,omitempty"`
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client is the main entry point for interacting with SimpleAuth.
type Client struct {
	baseURL   string
	realm     string
	appID     string
	appSecret string
	http      *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	keysAt    time.Time
	keysTTL   time.Duration
}

// New creates a new SimpleAuth client with the given options.
func New(opts Options) *Client {
	realm := opts.Realm
	if realm == "" {
		realm = "simpleauth"
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	return &Client{
		baseURL:   strings.TrimRight(opts.URL, "/"),
		realm:     realm,
		appID:     opts.AppID,
		appSecret: opts.AppSecret,
		http:      &http.Client{Transport: transport, Timeout: 30 * time.Second},
		keys:      make(map[string]*rsa.PublicKey),
		keysTTL:   1 * time.Hour,
	}
}

// ---------------------------------------------------------------------------
// Token acquisition
// ---------------------------------------------------------------------------

func (c *Client) tokenURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)
}

func (c *Client) basicAuth() string {
	return base64.StdEncoding.EncodeToString([]byte(c.appID + ":" + c.appSecret))
}

func (c *Client) postToken(ctx context.Context, form url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("simpleauth: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+c.basicAuth())

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: token request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("simpleauth: token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("simpleauth: decode token response: %w", err)
	}
	return &tok, nil
}

// Login performs a resource-owner password credentials grant.
func (c *Client) Login(ctx context.Context, username, password string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
	}
	return c.postToken(ctx, form)
}

// Refresh exchanges a refresh token for a new token set.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	return c.postToken(ctx, form)
}

// ClientCredentials performs a client credentials grant.
func (c *Client) ClientCredentials(ctx context.Context) (*TokenResponse, error) {
	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	return c.postToken(ctx, form)
}

// ExchangeCode exchanges an authorization code for tokens.
func (c *Client) ExchangeCode(ctx context.Context, code, redirectURI string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	return c.postToken(ctx, form)
}

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

// UserInfo calls the OIDC userinfo endpoint.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	u := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", c.baseURL, c.realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("simpleauth: userinfo returned %d: %s", resp.StatusCode, string(body))
	}

	var info UserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("simpleauth: decode userinfo: %w", err)
	}
	return &info, nil
}

// ---------------------------------------------------------------------------
// Admin: roles & permissions
// ---------------------------------------------------------------------------

func (c *Client) adminRequest(ctx context.Context, method, path string, payload interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("simpleauth: marshal payload: %w", err)
		}
		bodyReader = strings.NewReader(string(data))
	}

	u := fmt.Sprintf("%s%s", c.baseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: create request: %w", err)
	}
	req.Header.Set("Authorization", "Basic "+c.basicAuth())
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: admin request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("simpleauth: admin endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// GetUserRoles returns the roles assigned to a user.
func (c *Client) GetUserRoles(ctx context.Context, guid string) ([]string, error) {
	body, err := c.adminRequest(ctx, http.MethodGet, fmt.Sprintf("/admin/users/%s/roles", guid), nil)
	if err != nil {
		return nil, err
	}
	var roles []string
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, fmt.Errorf("simpleauth: decode roles: %w", err)
	}
	return roles, nil
}

// SetUserRoles replaces the roles for a user.
func (c *Client) SetUserRoles(ctx context.Context, guid string, roles []string) error {
	_, err := c.adminRequest(ctx, http.MethodPut, fmt.Sprintf("/admin/users/%s/roles", guid), roles)
	return err
}

// GetUserPermissions returns the permissions assigned to a user.
func (c *Client) GetUserPermissions(ctx context.Context, guid string) ([]string, error) {
	body, err := c.adminRequest(ctx, http.MethodGet, fmt.Sprintf("/admin/users/%s/permissions", guid), nil)
	if err != nil {
		return nil, err
	}
	var perms []string
	if err := json.Unmarshal(body, &perms); err != nil {
		return nil, fmt.Errorf("simpleauth: decode permissions: %w", err)
	}
	return perms, nil
}

// SetUserPermissions replaces the permissions for a user.
func (c *Client) SetUserPermissions(ctx context.Context, guid string, perms []string) error {
	_, err := c.adminRequest(ctx, http.MethodPut, fmt.Sprintf("/admin/users/%s/permissions", guid), perms)
	return err
}

// ---------------------------------------------------------------------------
// JWKS fetching & caching
// ---------------------------------------------------------------------------

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (c *Client) certsURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.baseURL, c.realm)
}

func (c *Client) fetchJWKS() error {
	resp, err := c.http.Get(c.certsURL())
	if err != nil {
		return fmt.Errorf("simpleauth: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("simpleauth: JWKS endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("simpleauth: decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			return fmt.Errorf("simpleauth: parse RSA key kid=%s: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.keysAt = time.Now()
	c.mu.Unlock()
	return nil
}

func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// getKey returns the RSA public key for the given kid. It uses the cache when
// possible and re-fetches from the JWKS endpoint on cache miss or expiry.
func (c *Client) getKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	expired := time.Since(c.keysAt) > c.keysTTL
	c.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	// Cache miss or expired — re-fetch.
	if err := c.fetchJWKS(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("simpleauth: unknown signing key kid=%s", kid)
	}
	return key, nil
}

// ---------------------------------------------------------------------------
// JWT verification (RS256, stdlib only)
// ---------------------------------------------------------------------------

// jwtHeader is the minimal JOSE header we need.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// Verify parses and cryptographically verifies a JWT (RS256). It returns the
// decoded User claims on success.
func (c *Client) Verify(tokenString string) (*User, error) {
	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("simpleauth: malformed JWT: expected 3 parts")
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("simpleauth: decode JWT header: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("simpleauth: parse JWT header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("simpleauth: unsupported JWT algorithm %q", hdr.Alg)
	}

	// Decode signature.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("simpleauth: decode JWT signature: %w", err)
	}

	// Fetch public key.
	pubKey, err := c.getKey(hdr.Kid)
	if err != nil {
		return nil, err
	}

	// Verify RS256: RSASSA-PKCS1-v1_5 using SHA-256.
	signed := []byte(parts[0] + "." + parts[1])
	hash := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig); err != nil {
		return nil, fmt.Errorf("simpleauth: invalid JWT signature: %w", err)
	}

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("simpleauth: decode JWT payload: %w", err)
	}

	// Check expiration.
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err == nil {
		if expInt, err := claims.Exp.Int64(); err == nil {
			if time.Now().Unix() > expInt {
				return nil, errors.New("simpleauth: token has expired")
			}
		}
	}

	var user User
	if err := json.Unmarshal(payloadJSON, &user); err != nil {
		return nil, fmt.Errorf("simpleauth: decode JWT claims: %w", err)
	}
	return &user, nil
}

// ---------------------------------------------------------------------------
// HTTP middleware
// ---------------------------------------------------------------------------

type contextKey struct{}

// UserFromContext retrieves the authenticated User from the request context.
// Returns nil if no user is present (e.g. middleware was not applied).
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(contextKey{}).(*User)
	return u
}

// Middleware returns an http.Handler middleware that validates the Bearer token
// in the Authorization header and stores the resulting User in the request
// context. Unauthenticated requests receive a 401 response.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r)
		if token == "" {
			http.Error(w, `{"error":"missing or invalid Authorization header"}`, http.StatusUnauthorized)
			return
		}

		user, err := c.Verify(token)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), contextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole wraps a handler and rejects requests from users that lack the
// specified role with a 403 Forbidden response.
func (c *Client) RequireRole(role string, next http.Handler) http.Handler {
	return c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil || !user.HasRole(role) {
			http.Error(w, `{"error":"forbidden: missing required role"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RequirePermission wraps a handler and rejects requests from users that lack
// the specified permission with a 403 Forbidden response.
func (c *Client) RequirePermission(perm string, next http.Handler) http.Handler {
	return c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil || !user.HasPermission(perm) {
			http.Error(w, `{"error":"forbidden: missing required permission"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}
	return ""
}
