package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// registerOIDCRoutes registers standard OIDC endpoints.
func (h *Handler) registerOIDCRoutes() {
	realm := h.cfg.JWTIssuer

	// Native OIDC discovery
	h.mux.HandleFunc("GET /.well-known/openid-configuration", h.handleOIDCDiscovery)

	// Keycloak-compatible paths
	prefix := "/realms/" + realm + "/protocol/openid-connect"
	h.mux.HandleFunc("GET /realms/"+realm+"/.well-known/openid-configuration", h.handleOIDCDiscovery)
	h.mux.HandleFunc("GET "+prefix+"/auth", h.handleOIDCAuthorize)
	h.mux.HandleFunc("POST "+prefix+"/auth", h.handleOIDCAuthorize)
	h.mux.HandleFunc("POST "+prefix+"/token", h.handleOIDCToken)
	h.mux.HandleFunc("GET "+prefix+"/userinfo", h.handleOIDCUserInfo)
	h.mux.HandleFunc("POST "+prefix+"/userinfo", h.handleOIDCUserInfo)
	h.mux.HandleFunc("GET "+prefix+"/certs", h.handleJWKS)
	h.mux.HandleFunc("POST "+prefix+"/token/introspect", h.handleOIDCIntrospect)
	h.mux.HandleFunc("GET "+prefix+"/logout", h.handleOIDCLogout)
	h.mux.HandleFunc("POST "+prefix+"/logout", h.handleOIDCLogout)
}

// oidcBaseURL returns the base URL for OIDC endpoints.
// Respects X-Forwarded-Proto from trusted proxies for correct scheme detection.
func (h *Handler) oidcBaseURL(r *http.Request) string {
	scheme := "https"
	if h.cfg.TLSDisabled {
		scheme = "http"
	}
	// Only honor a forwarded scheme from a trusted proxy, mirroring getClientIP —
	// otherwise any client could spoof X-Forwarded-Proto.
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" && isTrustedProxy(extractIP(r.RemoteAddr), trustedCIDRs) {
		scheme = proto
	}
	host := r.Host
	// Pin the host to the configured canonical hostname when the request Host
	// header does not match it, so the issuer / discovery URLs and the `iss`
	// claim stamped into every OIDC token cannot be spoofed via an arbitrary
	// Host header (F23). When r.Host already matches the configured hostname the
	// request value (with whatever port it carried) is used unchanged.
	if h.cfg.Hostname != "" && !hostMatches(host, h.cfg.Hostname) {
		host = h.cfg.Hostname
		if (scheme == "https" && h.cfg.Port != "443") || (scheme == "http" && h.cfg.Port != "80") {
			host += ":" + h.cfg.Port
		}
	}
	if host == "" {
		host = h.cfg.Hostname
	}
	return scheme + "://" + host + h.cfg.BasePath
}

// hostMatches reports whether the request Host (which may include a port) refers
// to the configured hostname, case-insensitively.
func hostMatches(reqHost, configured string) bool {
	if reqHost == "" {
		return false
	}
	if hostOnly, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = hostOnly
	}
	return strings.EqualFold(reqHost, configured)
}

// oidcIssuer returns the OIDC issuer URL (Keycloak-style).
func (h *Handler) oidcIssuer(r *http.Request) string {
	return h.oidcBaseURL(r) + "/realms/" + h.cfg.JWTIssuer
}

// handleOIDCDiscovery returns the OpenID Connect discovery document.
func (h *Handler) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	base := h.oidcBaseURL(r)
	issuer := h.oidcIssuer(r)
	prefix := base + "/realms/" + h.cfg.JWTIssuer + "/protocol/openid-connect"

	// Advertise only what is actually enabled. Confidential grants and
	// client-secret auth appear only when a client secret is configured (C2).
	grantTypes := []string{"authorization_code", "refresh_token"}
	authMethods := []string{"none"}
	if h.oidcConfidentialEnabled() {
		grantTypes = append(grantTypes, "client_credentials", "password")
		authMethods = []string{"client_secret_basic", "client_secret_post"}
	}

	doc := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                prefix + "/auth",
		"token_endpoint":                        prefix + "/token",
		"userinfo_endpoint":                     prefix + "/userinfo",
		"jwks_uri":                              prefix + "/certs",
		"introspection_endpoint":                prefix + "/token/introspect",
		"end_session_endpoint":                  prefix + "/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 grantTypes,
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "roles"},
		"token_endpoint_auth_methods_supported": authMethods,
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "name", "email",
			"preferred_username", "realm_access", "resource_access",
			"department", "company", "job_title", "groups",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	jsonResp(w, doc, http.StatusOK)
}

// authenticateOIDCClient is the gate for PUBLIC client flows (authorization_code,
// refresh_token). These are protected by single-use codes + PKCE and by stored,
// rotating refresh tokens, so no client secret is required — consistent with the
// single-app public-client model.
func (h *Handler) authenticateOIDCClient(r *http.Request) error {
	return nil
}

// oidcConfidentialEnabled reports whether confidential grants (password,
// client_credentials) and token introspection are enabled. They require a
// client secret (AUTH_CLIENT_SECRET) to be configured.
func (h *Handler) oidcConfidentialEnabled() bool {
	return h.cfg.ClientSecret != ""
}

// requireConfidentialClient enforces client authentication for confidential
// endpoints (password + client_credentials grants and introspection). It
// requires AUTH_CLIENT_SECRET to be set; if it is not, these flows are DISABLED.
// The presented secret (client_secret_post or HTTP Basic) is compared in
// constant time. Closes C2 (open password/client_credentials) and C3 (open
// introspection).
func (h *Handler) requireConfidentialClient(r *http.Request) error {
	if !h.oidcConfidentialEnabled() {
		return fmt.Errorf("grant disabled: set a client secret (AUTH_CLIENT_SECRET) to enable confidential grants")
	}
	presented := r.FormValue("client_secret")
	if presented == "" {
		if _, pw, ok := r.BasicAuth(); ok {
			presented = pw
		}
	}
	if presented == "" || !timingSafeEqual(presented, h.cfg.ClientSecret) {
		return fmt.Errorf("invalid client credentials")
	}
	return nil
}

// verifyPKCE validates a PKCE code_verifier against the stored code_challenge
// (RFC 7636). S256 is preferred; "plain"/empty compares verbatim. Comparisons
// are constant-time.
func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" {
		return false
	}
	// Only S256 is supported and advertised. "plain"/empty are a downgrade (the
	// stored challenge equals the verifier in cleartext), so they are rejected
	// here and at the authorize endpoint (F55).
	if method != "S256" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// handleOIDCAuthorize handles the OAuth2 authorization endpoint.
func (h *Handler) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		h.showOIDCLoginPage(w, r)
		return
	}

	// POST — process login form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}
	// Reject cross-origin submissions: the OIDC authorize POST must carry the
	// __csrf cookie + matching _csrf field issued by showOIDCLoginPage (F30).
	if !validateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	scope := r.FormValue("scope")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		h.renderOIDCLoginError(w, r, "Username and password are required")
		return
	}

	// Resolve the app (v2) — client_id identifies the app; empty → default app.
	app, err := h.resolveApp(clientID)
	if err != nil {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	if redirectURI != "" && !h.appAllowsRedirect(app, redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}
	// Enforce the single PKCE method we advertise (S256); reject a downgrade to
	// plain/empty when a challenge is present (F55).
	if codeChallenge != "" && codeChallengeMethod != "S256" {
		http.Error(w, "unsupported code_challenge_method (only S256 is supported)", http.StatusBadRequest)
		return
	}

	ip := getClientIP(r)
	if !h.loginLimiter.allow(ip) {
		h.renderOIDCLoginError(w, r, "Too many login attempts")
		return
	}

	userGUID, _, err := h.authenticateUser(username, password, app)
	if err != nil {
		h.audit("login_failed", "", ip, map[string]interface{}{
			"username": username, "reason": err.Error(), "flow": "oidc",
		})
		h.renderOIDCLoginError(w, r, "Invalid credentials")
		return
	}

	user, err := h.store.ResolveUser(userGUID)
	if err != nil {
		h.renderOIDCLoginError(w, r, "User not found")
		return
	}
	if user.Disabled {
		h.renderOIDCLoginError(w, r, "Account disabled")
		return
	}

	// Seed shared SSO session cookie (no-op if feature disabled)
	h.issueSessionCookie(w, r, user.GUID)

	h.audit("oidc_authorize", user.GUID, ip, map[string]interface{}{
		"flow": "authorization_code",
	})

	h.issueOIDCCodeRedirect(w, r, user, app.AppID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod)
}

// issueOIDCCodeRedirect mints an OIDC auth code for `user` and redirects the
// browser to `redirectURI?code=...&state=...`. Used by both the normal POST
// login path and the session-cookie fast path. appID binds the code (and the
// tokens it yields) to the app (v2 audience-scoped tokens).
func (h *Handler) issueOIDCCodeRedirect(w http.ResponseWriter, r *http.Request, user *store.User, appID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod string) {
	// When the client omitted redirect_uri, fall back to the APP's OWN first
	// registered URI — never the global default. Otherwise a named app's code
	// (and the audience-scoped tokens it yields) is delivered to a cross-app
	// global URI the app never registered (F28). The resolved value is persisted
	// into the auth code below so the token-exchange redirect_uri match applies.
	if redirectURI == "" {
		if app, err := h.resolveApp(appID); err == nil && len(app.RedirectURIs) > 0 {
			redirectURI = app.RedirectURIs[0]
		} else {
			redirectURI = h.getDefaultRedirectURI()
		}
	}

	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	code := hex.EncodeToString(codeBytes)

	ac := &store.OIDCAuthCode{
		Code:                code,
		UserGUID:            user.GUID,
		AppID:               appID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now(),
	}
	if err := h.store.SaveOIDCAuthCode(ac); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redirectTarget := redirectURI
	sep := "?"
	if strings.Contains(redirectTarget, "?") {
		sep = "&"
	}
	redirectTarget += sep + "code=" + url.QueryEscape(code)
	if state != "" {
		redirectTarget += "&state=" + url.QueryEscape(state)
	}
	// Re-validate at the SINK. redirectURI is allowlist-checked by every caller
	// before we get here, and again below when the code is redeemed — but this is
	// the moment an auth code leaves the server, so prove the destination one more
	// time rather than trusting that every present and future caller did.
	if app, err := h.resolveApp(appID); err != nil || !h.appAllowsRedirect(app, redirectURI) {
		log.Printf("[oidc] refusing code delivery to a non-allowlisted redirect_uri app=%q", appID)
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

// oidcAuthzRequest is the set of authorize-request parameters that MUST survive
// every hop of the interactive login flow:
//
//	GET /auth?…  →  hidden form fields  →  (failed attempt) error redirect  →  retry POST
//	             →  Kerberos SSO link   →  /login/sso
//
// Drop one at any hop and the retry silently proceeds with WEAKER parameters than
// the client asked for. That is not hypothetical: renderOIDCLoginError used to
// rebuild the URL by hand with fmt.Sprintf and omitted code_challenge, so one
// mistyped password disabled PKCE for the rest of the login — the retry stored an
// empty challenge and the token endpoint's `if ac.CodeChallenge != ""` guard then
// required no code_verifier at all, undoing M6 (H13).
//
// Keep this type as the single definition of the authorize request: adding a
// parameter here makes every hop carry it. And note what it deliberately is NOT —
// a copy of r.Form. The authorize POST body carries `username` and `password`;
// blanket-copying it into a redirect would put live credentials in a Location
// header, the browser's history, and every proxy log on the path.
type oidcAuthzRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
}

// parseOIDCAuthzRequest reads the authorize parameters from either hop: FormValue
// covers the query string on the GET and the parsed body on the credential POST.
func parseOIDCAuthzRequest(r *http.Request) oidcAuthzRequest {
	return oidcAuthzRequest{
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		Scope:               r.FormValue("scope"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		Prompt:              r.FormValue("prompt"),
	}
}

// values renders the request back onto a query string. Empty parameters are
// omitted rather than emitted blank, so the retry URL keeps the shape of the
// original authorize request.
func (a oidcAuthzRequest) values() url.Values {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("client_id", a.ClientID)
	set("redirect_uri", a.RedirectURI)
	set("state", a.State)
	set("nonce", a.Nonce)
	set("scope", a.Scope)
	// Both halves of PKCE travel together or not at all: a challenge that arrives
	// without its method is rejected by the authorize POST (F55/L7), so carrying
	// one without the other converts a silent downgrade into a hard 400.
	if a.CodeChallenge != "" {
		q.Set("code_challenge", a.CodeChallenge)
		q.Set("code_challenge_method", a.CodeChallengeMethod)
	}
	set("prompt", a.Prompt)
	return q
}

func (h *Handler) showOIDCLoginPage(w http.ResponseWriter, r *http.Request) {
	authz := parseOIDCAuthzRequest(r)

	app, err := h.resolveApp(authz.ClientID)
	if err != nil {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}

	redirectURI := authz.RedirectURI
	if redirectURI != "" && !h.appAllowsRedirect(app, redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	state := authz.State
	nonce := authz.Nonce
	scope := authz.Scope
	codeChallenge := authz.CodeChallenge
	codeChallengeMethod := authz.CodeChallengeMethod
	prompt := authz.Prompt
	// `error` is the error CHANNEL, not part of the authorize request — it is set
	// by renderOIDCLoginError and never round-tripped from the client.
	errorMsg := r.URL.Query().Get("error")

	// Session SSO: if the browser has a valid session cookie AND the client
	// didn't ask for prompt=login, skip the login page and issue an auth code
	// directly. This is the OIDC equivalent of the hosted-login auto-redirect.
	if errorMsg == "" && prompt != "login" {
		if guid := h.resolveSessionCookie(w, r); guid != "" {
			if user, err := h.store.ResolveUser(guid); err == nil && !user.Disabled {
				h.issueOIDCCodeRedirect(w, r, user, app.AppID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod)
				return
			}
		}
	}

	realm := h.cfg.JWTIssuer
	action := h.cfg.BasePath + "/realms/" + realm + "/protocol/openid-connect/auth"

	appName := h.getDeploymentName()
	if appName == "" {
		appName = "your application"
	}

	ssoEnabled := h.getKeytabPath() != ""
	ssoLink := ""
	if ssoEnabled {
		// Built from the same allowlist as the error redirect, so a parameter
		// added to oidcAuthzRequest is carried here automatically instead of
		// needing to be remembered at a second hand-concatenated site.
		q := authz.values()
		q.Set("oidc", "1")
		// Carry the RESOLVED client_id so handleSSOLogin (auth.go) resolves the
		// INITIATING app rather than falling back to the default app — otherwise
		// the SPNEGO path mints a wrong-audience token or dead-ends on redirect
		// validation. This deliberately OVERWRITES whatever the client sent,
		// exactly as the hidden client_id field below does.
		q.Set("client_id", app.AppID)
		// prompt is a login-page concept; the SPNEGO endpoint has no use for it.
		q.Del("prompt")
		ssoLink = h.url("/login/sso") + "?" + q.Encode()
	}

	// Only auto-redirect when SSO is enabled, there is no error, and we have not
	// already tried — mirroring hosted_login.go. The __sso_attempted breaker is
	// required now that ssoLink carries client_id: redirectToLoginError can
	// resolve the initiating app and bounce the failure to ITS callback, so an RP
	// that re-initiates authorize on error would otherwise loop.
	autoSSO := false
	ssoAttempted := false
	if c, err := r.Cookie("__sso_attempted"); err == nil && c.Value == "1" {
		ssoAttempted = true
	}
	if ssoEnabled && errorMsg == "" && !ssoAttempted {
		if rs := h.runtimeSettings.get(); rs != nil && rs.AutoSSO {
			autoSSO = true
		}
	}

	ssoEnabledStr := ""
	if ssoEnabled {
		ssoEnabledStr = "1"
	}
	autoSSOStr := ""
	if autoSSO {
		autoSSOStr = "1"
	}

	ssoDelay := 3
	if rs := h.runtimeSettings.get(); rs != nil && rs.AutoSSODelay > 0 {
		ssoDelay = rs.AutoSSODelay
	}

	// CSRF: set a token cookie and embed it as a hidden field so the POST branch
	// of handleOIDCAuthorize can reject cross-origin form submissions (login CSRF
	// / session fixation, F30) — mirroring the hosted-login form.
	csrfToken := generateCSRFToken()
	h.setCSRFCookie(w, csrfToken)

	// ClientID is the RESOLVED app's id — never a hardcoded default. The POST
	// branch re-resolves the app from this field, so stamping anything else binds
	// the auth code (and every token it yields) to the wrong app.
	data := oidcLoginData{
		Action:              action,
		ClientID:            app.AppID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               nonce,
		Scope:               scope,
		AppName:             appName,
		ErrorMsg:            errorMsg,
		SSOLink:             ssoLink,
		SSOEnabled:          ssoEnabledStr,
		AutoSSO:             autoSSOStr,
		SSODelay:            ssoDelay,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		CSRFToken:           csrfToken,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := oidcLoginTmpl.Execute(w, data); err != nil {
		log.Printf("[oidc] render login page: %v", err)
	}
}

// handleOIDCToken handles the OAuth2 token endpoint.
func (h *Handler) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oidcError(w, "invalid_request", "invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	log.Printf("[oidc] Token request: grant_type=%s", grantType)

	switch grantType {
	case "authorization_code":
		h.handleOIDCTokenAuthCode(w, r)
	case "client_credentials":
		h.handleOIDCTokenClientCredentials(w, r)
	case "password":
		h.handleOIDCTokenPassword(w, r)
	case "refresh_token":
		h.handleOIDCTokenRefresh(w, r)
	default:
		oidcError(w, "unsupported_grant_type", "grant_type must be authorization_code, client_credentials, password, or refresh_token", http.StatusBadRequest)
	}
}

func (h *Handler) handleOIDCTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	if err := h.authenticateOIDCClient(r); err != nil {
		oidcError(w, "invalid_client", err.Error(), http.StatusUnauthorized)
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" {
		oidcError(w, "invalid_request", "code is required", http.StatusBadRequest)
		return
	}

	ac, err := h.store.ConsumeOIDCAuthCode(code)
	if err != nil {
		oidcError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}

	if ac.RedirectURI != "" && ac.RedirectURI != redirectURI {
		oidcError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	// PKCE (RFC 7636): when a code_challenge was bound to the code at authorize
	// time, require a matching code_verifier so an intercepted code cannot be
	// redeemed by anyone else (M6).
	if ac.CodeChallenge != "" {
		if !verifyPKCE(r.FormValue("code_verifier"), ac.CodeChallenge, ac.CodeChallengeMethod) {
			oidcError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
			return
		}
	}

	user, err := h.store.ResolveUser(ac.UserGUID)
	if err != nil {
		oidcError(w, "server_error", "user not found", http.StatusInternalServerError)
		return
	}

	app, err := h.resolveApp(ac.AppID)
	if err != nil {
		oidcError(w, "invalid_grant", "unknown client", http.StatusBadRequest)
		return
	}

	log.Printf("[oidc] Auth code exchange user=%q guid=%s app=%q ip=%s", h.resolvePreferredUsername(user), user.GUID, app.AppID, getClientIP(r))
	h.issueOIDCTokens(w, r, user, ac.Scope, ac.Nonce, app)
}

func (h *Handler) handleOIDCTokenPassword(w http.ResponseWriter, r *http.Request) {
	// Resource Owner Password Credentials is a confidential grant — the app
	// authenticates with its own app_secret (the default client falls back to
	// AUTH_CLIENT_SECRET), and the resulting token is scoped to that app (C2 + M11).
	app, err := h.authenticateConfidentialClient(r)
	if err != nil {
		oidcError(w, "invalid_client", err.Error(), http.StatusUnauthorized)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	scope := r.FormValue("scope")

	if username == "" || password == "" {
		oidcError(w, "invalid_request", "username and password required", http.StatusBadRequest)
		return
	}

	ip := getClientIP(r)
	if !h.loginLimiter.allow(ip) {
		oidcError(w, "invalid_request", "too many login attempts", http.StatusTooManyRequests)
		return
	}

	log.Printf("[oidc] Password grant user=%q app=%q ip=%s", username, app.AppID, ip)
	userGUID, _, err := h.authenticateUser(username, password, app)
	if err != nil {
		log.Printf("[oidc] Password grant failed user=%q ip=%s reason=%q", username, ip, err.Error())
		h.audit("login_failed", "", ip, map[string]interface{}{
			"username": username, "reason": err.Error(), "flow": "oidc_password",
		})
		oidcError(w, "invalid_grant", "invalid credentials", http.StatusUnauthorized)
		return
	}

	user, err := h.store.ResolveUser(userGUID)
	if err != nil {
		oidcError(w, "server_error", "user not found", http.StatusInternalServerError)
		return
	}
	if user.Disabled {
		oidcError(w, "invalid_grant", "account disabled", http.StatusUnauthorized)
		return
	}

	log.Printf("[oidc] Password grant success user=%q guid=%s app=%q ip=%s", username, user.GUID, app.AppID, ip)
	h.issueOIDCTokens(w, r, user, scope, "", app)
}

// presentedClientSecret extracts the client secret from client_secret_post or
// HTTP Basic.
func presentedClientSecret(r *http.Request) string {
	if s := r.FormValue("client_secret"); s != "" {
		return s
	}
	if _, pw, ok := r.BasicAuth(); ok {
		return pw
	}
	return ""
}

// authenticateConfidentialClient authenticates a confidential grant
// (client_credentials / password) and returns the app the resulting token must be
// scoped to. A registered app authenticates against ITS OWN app_secret, so a caller
// can only mint a token for the audience whose secret it actually holds — the single
// global secret no longer impersonates every app (M11). The secret-less default
// client falls back to the global AUTH_CLIENT_SECRET for v1 back-compat (disabled
// when unset).
func (h *Handler) authenticateConfidentialClient(r *http.Request) (*store.App, error) {
	app, err := h.resolveApp(r.FormValue("client_id"))
	if err != nil {
		return nil, fmt.Errorf("unknown client")
	}
	presented := presentedClientSecret(r)
	if presented == "" {
		return nil, fmt.Errorf("invalid client credentials")
	}
	if app.SecretHash != "" {
		if !auth.CheckPassword(app.SecretHash, presented) {
			return nil, fmt.Errorf("invalid client credentials")
		}
		return app, nil
	}
	if !h.oidcConfidentialEnabled() {
		return nil, fmt.Errorf("grant disabled: set a client secret (AUTH_CLIENT_SECRET) to enable confidential grants")
	}
	if !timingSafeEqual(presented, h.cfg.ClientSecret) {
		return nil, fmt.Errorf("invalid client credentials")
	}
	return app, nil
}

func (h *Handler) handleOIDCTokenClientCredentials(w http.ResponseWriter, r *http.Request) {
	// Throttle by IP before the secret check so this grant is not an unthrottled
	// app_secret brute-force oracle — M16 covered /api/app/token but not this
	// sibling OIDC surface (F31).
	if !h.loginLimiter.allow(getClientIP(r)) {
		oidcError(w, "invalid_request", "too many requests", http.StatusTooManyRequests)
		return
	}
	// client_credentials is a confidential grant — the app authenticates with its
	// own app_secret (the default client falls back to AUTH_CLIENT_SECRET), so the
	// minted token is scoped only to an audience the caller can authenticate for
	// (C2 + M11).
	app, err := h.authenticateConfidentialClient(r)
	if err != nil {
		oidcError(w, "invalid_client", err.Error(), http.StatusUnauthorized)
		return
	}

	// Client credentials — no user context, sub = app_id, aud = app (v2).
	issuer := h.oidcIssuer(r)
	claims := auth.Claims{
		Typ:   "Bearer",
		Scope: r.FormValue("scope"),
	}
	claims.Subject = app.AppID
	claims.Audience = []string{appAudience(app)}

	accessToken, err := h.jwt.IssueAccessTokenWithIssuer(claims, h.cfg.AccessTTL, issuer)
	if err != nil {
		oidcError(w, "server_error", "token generation failed", http.StatusInternalServerError)
		return
	}

	log.Printf("[oidc] Client credentials grant app=%s ip=%s", app.AppID, getClientIP(r))
	h.audit("oidc_token", app.AppID, getClientIP(r), map[string]interface{}{
		"grant_type": "client_credentials",
	})

	jsonResp(w, map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(h.cfg.AccessTTL.Seconds()),
		"scope":        claims.Scope,
	}, http.StatusOK)
}

func (h *Handler) handleOIDCTokenRefresh(w http.ResponseWriter, r *http.Request) {
	if err := h.authenticateOIDCClient(r); err != nil {
		oidcError(w, "invalid_client", err.Error(), http.StatusUnauthorized)
		return
	}

	refreshTokenStr := r.FormValue("refresh_token")
	if refreshTokenStr == "" {
		oidcError(w, "invalid_request", "refresh_token required", http.StatusBadRequest)
		return
	}

	claims, err := h.jwt.ValidateToken(refreshTokenStr)
	if err != nil {
		oidcError(w, "invalid_grant", "invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Atomically consume the refresh token (single-use) — closes the rotation
	// TOCTOU (H2).
	storedRT, err := h.store.ConsumeRefreshToken(claims.ID)
	if errors.Is(err, store.ErrRefreshTokenReused) {
		h.store.RevokeTokenFamily(storedRT.FamilyID)
		oidcError(w, "invalid_grant", "token reuse detected, all sessions revoked", http.StatusUnauthorized)
		return
	}
	if err != nil {
		oidcError(w, "invalid_grant", "refresh token not found", http.StatusUnauthorized)
		return
	}

	user, err := h.store.ResolveUser(claims.Subject)
	if err != nil {
		oidcError(w, "invalid_grant", "user not found", http.StatusUnauthorized)
		return
	}
	if user.Disabled {
		oidcError(w, "invalid_grant", "account disabled", http.StatusUnauthorized)
		return
	}
	// Honor the admin access-revocation kill switch on refresh too (M3).
	if revoked, _ := h.store.IsUserAccessRevoked(user.GUID); revoked {
		oidcError(w, "invalid_grant", "access revoked", http.StatusUnauthorized)
		return
	}

	// Refresh stays bound to the same app (v2): re-stamp the original audience,
	// and re-check per-app authorization (M3). Resolve the app first so a
	// disabled/deleted app returns a clean error instead of nil-dereferencing in
	// resolveTokenRoles (M10).
	app, err := h.resolveApp(storedRT.AppID)
	if err != nil {
		oidcError(w, "invalid_grant", "app unavailable", http.StatusUnauthorized)
		return
	}
	roles, perms, denied := h.resolveTokenRoles(app, user)
	if denied {
		oidcError(w, "access_denied", "not assigned to this app", http.StatusForbidden)
		return
	}

	issuer := h.oidcIssuer(r)
	accessClaims := h.buildOIDCAccessClaims(user, roles, perms, nil, "", app)
	accessToken, err := h.jwt.IssueAccessTokenWithIssuer(accessClaims, h.cfg.AccessTTL, issuer)
	if err != nil {
		oidcError(w, "server_error", "token generation failed", http.StatusInternalServerError)
		return
	}

	newRefreshToken, newTokenID, newFamilyID, err := h.jwt.IssueRefreshToken(user.GUID, storedRT.FamilyID, h.cfg.RefreshTTL)
	if err != nil {
		oidcError(w, "server_error", "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	rt := &store.RefreshToken{
		TokenID:   newTokenID,
		FamilyID:  newFamilyID,
		UserGUID:  user.GUID,
		ExpiresAt: time.Now().UTC().Add(h.cfg.RefreshTTL),
		CreatedAt: time.Now().UTC(),
		AppID:     storedRT.AppID,
		Audience:  storedRT.Audience,
	}
	if err := h.store.SaveRefreshToken(rt); err != nil {
		oidcError(w, "server_error", "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	jsonResp(w, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(h.cfg.AccessTTL.Seconds()),
		"scope":         r.FormValue("scope"),
	}, http.StatusOK)
}

// issueOIDCTokens generates access_token, refresh_token, and id_token for a user.
func (h *Handler) issueOIDCTokens(w http.ResponseWriter, r *http.Request, user *store.User, scope, nonce string, app *store.App) {
	roles, perms, denied := h.resolveTokenRoles(app, user)
	if denied {
		oidcError(w, "access_denied", "not assigned to this app", http.StatusForbidden)
		return
	}
	issuer := h.oidcIssuer(r)
	ip := getClientIP(r)

	// Access token with Keycloak-compatible claims (per-app audience in v2).
	accessClaims := h.buildOIDCAccessClaims(user, roles, perms, nil, scope, app)
	accessToken, err := h.jwt.IssueAccessTokenWithIssuer(accessClaims, h.cfg.AccessTTL, issuer)
	if err != nil {
		oidcError(w, "server_error", "token generation failed", http.StatusInternalServerError)
		return
	}

	// Refresh token
	refreshToken, tokenID, familyID, err := h.jwt.IssueRefreshToken(user.GUID, "", h.cfg.RefreshTTL)
	if err != nil {
		oidcError(w, "server_error", "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	rt := &store.RefreshToken{
		TokenID:   tokenID,
		FamilyID:  familyID,
		UserGUID:  user.GUID,
		ExpiresAt: time.Now().UTC().Add(h.cfg.RefreshTTL),
		CreatedAt: time.Now().UTC(),
	}
	rt.AppID = app.AppID
	rt.Audience = appAudience(app)
	if err := h.store.SaveRefreshToken(rt); err != nil {
		oidcError(w, "server_error", "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	// ID token — audience/azp = the app (v2). app is always non-nil here:
	// resolveApp never returns (nil, nil), and resolveTokenRoles above already
	// dereferenced it.
	idClientID := app.AppID
	idAud := appAudience(app)
	idClaims := auth.Claims{
		Name:              user.DisplayName,
		Email:             user.Email,
		PreferredUsername: user.Email,
		Nonce:             nonce,
		AtHash:            auth.ComputeAtHash(accessToken),
		Typ:               "ID",
		Azp:               idClientID,
	}
	if user.Email == "" {
		idClaims.PreferredUsername = user.DisplayName
	}
	idClaims.Subject = user.GUID
	idClaims.Audience = []string{idAud}

	idToken, err := h.jwt.IssueIDToken(idClaims, h.cfg.AccessTTL, issuer)
	if err != nil {
		oidcError(w, "server_error", "id token generation failed", http.StatusInternalServerError)
		return
	}

	h.audit("oidc_token", user.GUID, ip, map[string]interface{}{
		"flow": "oidc",
	})

	resp := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"id_token":      idToken,
		"token_type":    "Bearer",
		"expires_in":    int(h.cfg.AccessTTL.Seconds()),
		"scope":         scope,
	}
	if scope == "" {
		resp["scope"] = "openid profile email"
	}
	jsonResp(w, resp, http.StatusOK)
}

// buildOIDCAccessClaims constructs Keycloak-compatible access token claims.
// The audience, azp, and resource_access key are always the app (v2 per-app
// authorization); app is non-nil on every call path (resolveApp never returns
// (nil, nil), and both callers run resolveTokenRoles, which dereferences it,
// first).
func (h *Handler) buildOIDCAccessClaims(user *store.User, roles, perms, groups []string, scope string, app *store.App) auth.Claims {
	preferredUsername := user.Email
	if preferredUsername == "" {
		preferredUsername = user.DisplayName
	}

	clientID := app.AppID
	aud := appAudience(app)

	claims := auth.Claims{
		Name:              user.DisplayName,
		Email:             user.Email,
		Department:        user.Department,
		Company:           user.Company,
		JobTitle:          user.JobTitle,
		SAMAccountName:    user.SAMAccountName,
		Roles:             roles,
		Permissions:       perms,
		Groups:            groups,
		PreferredUsername: preferredUsername,
		Typ:               "Bearer",
		Azp:               clientID,
		Scope:             scope,
		RealmAccess:       &auth.RealmAccess{Roles: roles},
		ResourceAccess: map[string]*auth.ResourceAccess{
			clientID: {Roles: roles},
		},
	}
	claims.Subject = user.GUID
	claims.Audience = []string{aud}

	if scope == "" {
		claims.Scope = "openid profile email"
	}

	return claims
}

// handleOIDCUserInfo returns user claims from a valid access token.
func (h *Handler) handleOIDCUserInfo(w http.ResponseWriter, r *http.Request) {
	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		oidcError(w, "invalid_token", "missing access token", http.StatusUnauthorized)
		return
	}

	claims, err := h.validateAccessToken(tokenStr)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oidcError(w, "invalid_token", "invalid or revoked token", http.StatusUnauthorized)
		return
	}

	user, err := h.store.ResolveUser(claims.Subject)
	if err != nil {
		oidcError(w, "invalid_token", "user not found", http.StatusUnauthorized)
		return
	}

	resp := map[string]interface{}{
		"sub":                user.GUID,
		"name":               user.DisplayName,
		"preferred_username": user.Email,
		"email":              user.Email,
	}

	if user.Email == "" {
		resp["preferred_username"] = user.DisplayName
	}
	if user.Department != "" {
		resp["department"] = user.Department
	}
	if user.Company != "" {
		resp["company"] = user.Company
	}
	if user.JobTitle != "" {
		resp["job_title"] = user.JobTitle
	}
	if user.SAMAccountName != "" {
		resp["samaccountname"] = user.SAMAccountName
	}
	if claims.Roles != nil {
		resp["roles"] = claims.Roles
	}
	if claims.Groups != nil {
		resp["groups"] = claims.Groups
	}
	if claims.RealmAccess != nil {
		resp["realm_access"] = claims.RealmAccess
	}
	if claims.ResourceAccess != nil {
		resp["resource_access"] = claims.ResourceAccess
	}

	w.Header().Set("Content-Type", "application/json")
	jsonResp(w, resp, http.StatusOK)
}

// handleOIDCIntrospect validates a token and returns its claims.
func (h *Handler) handleOIDCIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oidcError(w, "invalid_request", "invalid form data", http.StatusBadRequest)
		return
	}

	// Introspection is a protected resource (RFC 7662) — requires client auth
	// so anonymous callers cannot probe token validity or read claims (C3).
	if err := h.requireConfidentialClient(r); err != nil {
		oidcError(w, "invalid_client", err.Error(), http.StatusUnauthorized)
		return
	}

	tokenStr := r.FormValue("token")
	if tokenStr == "" {
		jsonResp(w, map[string]interface{}{"active": false}, http.StatusOK)
		return
	}

	claims, err := h.validateAccessToken(tokenStr)
	if err != nil {
		jsonResp(w, map[string]interface{}{"active": false}, http.StatusOK)
		return
	}

	resp := map[string]interface{}{
		"active":     true,
		"sub":        claims.Subject,
		"iss":        claims.Issuer,
		"exp":        claims.ExpiresAt.Unix(),
		"iat":        claims.IssuedAt.Unix(),
		"token_type": "Bearer",
		"scope":      claims.Scope,
	}
	// client_id must describe the token's OWN app (RFC 7662 §2.2), not a hardcoded
	// default. azp is set to app.AppID at mint time by buildOIDCAccessClaims, so
	// every OIDC-minted access token carries it. Deliberately NO fallback to the
	// audience: `aud` is a free-form audience string (often a URL) and is not a
	// registered client_id, so reporting it would hand resource servers a value
	// that can never match their client registry. Tokens minted by paths that do
	// not set azp (v1 refresh, impersonation) simply omit the member.
	if claims.Azp != "" {
		resp["client_id"] = claims.Azp
	}
	// Keycloak encodes a single audience as a bare string, not a 1-element array;
	// match it, since migrated RPs string-compare this field.
	switch len(claims.Audience) {
	case 0:
	case 1:
		resp["aud"] = claims.Audience[0]
	default:
		resp["aud"] = []string(claims.Audience)
	}
	if claims.PreferredUsername != "" {
		resp["preferred_username"] = claims.PreferredUsername
	}
	if claims.Name != "" {
		resp["name"] = claims.Name
	}
	if claims.Email != "" {
		resp["email"] = claims.Email
	}

	jsonResp(w, resp, http.StatusOK)
}

// handleOIDCLogout handles end-session requests.
func (h *Handler) handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	idTokenHint := r.FormValue("id_token_hint")
	if idTokenHint == "" {
		idTokenHint = r.URL.Query().Get("id_token_hint")
	}
	postLogoutURI := r.FormValue("post_logout_redirect_uri")
	if postLogoutURI == "" {
		postLogoutURI = r.URL.Query().Get("post_logout_redirect_uri")
	}

	var hintApp *store.App
	if idTokenHint != "" {
		claims, err := h.jwt.ValidateToken(idTokenHint)
		// Only a genuine ID token may drive session revocation. The previous code
		// accepted ANY same-key token (access/refresh/app-mgmt), so an attacker
		// holding any one token for a subject could trigger a global session kill
		// for that user (F15/F56). An ID token is the RP-initiated-logout hint per
		// OIDC and is itself proof the user authenticated.
		if err == nil && claims.Typ == "ID" && claims.FamilyID == "" {
			if len(claims.Audience) > 0 {
				if a, aerr := h.resolveApp(claims.Audience[0]); aerr == nil {
					hintApp = a
				}
			}
			// Revoke all sessions for this user
			sessions, _ := h.store.ListUserSessions(claims.Subject)
			for _, s := range sessions {
				h.store.RevokeTokenFamily(s.FamilyID)
			}
			// Kill the shared SSO session for this user too
			h.store.DeleteUserSessions(claims.Subject)
			h.audit("oidc_logout", claims.Subject, getClientIP(r), nil)
		}
	}

	// Clear cookie on this browser regardless of id_token_hint
	h.deleteCurrentSession(w, r)

	// Only honor a post-logout redirect the relevant app actually allows;
	// redirecting to an arbitrary attacker-supplied URI is an open redirect (F27).
	if postLogoutURI != "" {
		app := hintApp
		if app == nil {
			if a, err := h.resolveApp(r.URL.Query().Get("client_id")); err == nil {
				app = a
			}
		}
		if app != nil && h.appAllowsRedirect(app, postLogoutURI) {
			http.Redirect(w, r, postLogoutURI, http.StatusFound)
			return
		}
		// Not allowed — fall through to the local logged-out page rather than
		// redirecting to an unvalidated destination.
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Logged Out</title></head><body><h1>You have been logged out.</h1></body></html>`)
}

// renderOIDCLoginError bounces the browser back to SimpleAuth's OWN authorize
// page with an error banner, carrying the WHOLE authorize request with it
// (oidcAuthzRequest) — most importantly the PKCE challenge, which this function
// used to drop (H13, an M6 bypass reachable by mistyping a password once).
//
// Two invariants:
//   - The target is always SimpleAuth's own authorize endpoint, never the
//     client's redirect_uri. The empty-credentials branch reaches here BEFORE
//     redirect_uri has been checked against the app's allowlist, so bouncing to
//     it would be an open redirect (the OIDC sibling of F29). showOIDCLoginPage
//     re-validates redirect_uri on the way back in.
//   - username / password / _csrf are NOT carried. Credentials must never enter
//     a URL, and showOIDCLoginPage mints a fresh CSRF token + cookie per render
//     (F30). This is why the fix is a typed allowlist rather than a copy of
//     r.Form — the request this runs on is a CREDENTIAL POST.
func (h *Handler) renderOIDCLoginError(w http.ResponseWriter, r *http.Request, msg string) {
	q := parseOIDCAuthzRequest(r).values()
	// This endpoint only ever issues codes (response_types_supported: ["code"]).
	q.Set("response_type", "code")
	q.Set("error", msg)

	realm := h.cfg.JWTIssuer
	u := h.url("/realms/"+realm+"/protocol/openid-connect/auth") + "?" + q.Encode()
	http.Redirect(w, r, u, http.StatusFound)
}

// oidcError returns a standard OAuth2 error response.
func oidcError(w http.ResponseWriter, errorCode, description string, status int) {
	jsonResp(w, map[string]string{
		"error":             errorCode,
		"error_description": description,
	}, status)
}

// OIDC login page template. Rendered with html/template, NOT fmt.Fprintf: every
// interpolated value here is attacker-influenced (client_id, redirect_uri, state,
// nonce, scope, code_challenge) and lands in three different escaping contexts —
// HTML attribute, href URL, and a JS string literal. html/template applies the
// correct escaper per context automatically; hand-rolled html.EscapeString does
// not distinguish them.
type oidcLoginData struct {
	Action              string
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	AppName             string
	ErrorMsg            string
	SSOLink             string
	SSOEnabled          string
	AutoSSO             string
	SSODelay            int
	CodeChallenge       string
	CodeChallengeMethod string
	CSRFToken           string
}

var oidcLoginTmpl = template.Must(template.New("oidcLogin").Parse(oidcLoginHTML))

const oidcLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In — SimpleAuth</title>
<style>
:root {
  --bg: #F7F5F3; --card: #FFFFFF; --text: #1A1F24; --muted: #A59F8A;
  --border: #D6D1CA; --burgundy: #8B153D; --burgundy-hover: #6E1030;
  --error-bg: #F8E4E4; --error-text: #8B153D;
  --gold-light: #F8E08E; --gold: #8F6A2A;
  --input-bg: #FFFFFF; --input-border: #C1A18D;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#222A31;--card:#2E3840;--text:#F2EFEC;--muted:#8A857D;
  --border:#475560;--burgundy:#8B153D;--burgundy-hover:#A42D55;
  --error-bg:rgba(139,21,61,0.2);--error-text:#D4A0A0;
  --gold:#8F6A2A;--input-bg:#2A333B;--input-border:#475560;
}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{width:420px;padding:40px;background:var(--card);border:1px solid var(--border);border-radius:16px;box-shadow:0 4px 16px rgba(51,63,72,0.1)}
.brand{text-align:center;margin-bottom:32px}
.brand h1{font-size:1.5rem;font-weight:700;margin-bottom:4px}
.brand p{color:var(--muted);font-size:0.875rem}
.gold-bar{height:3px;background:linear-gradient(90deg,var(--gold-light),var(--gold-dark));border-radius:999px;margin-bottom:24px}
.error{background:var(--error-bg);color:var(--error-text);padding:12px 16px;border-radius:8px;font-size:0.875rem;margin-bottom:16px}
label{display:block;font-size:0.875rem;font-weight:600;margin-bottom:8px}
input[type=text],input[type=password]{width:100%;padding:12px 16px;background:var(--input-bg);border:1px solid var(--input-border);border-radius:12px;font-size:0.875rem;font-family:inherit;color:var(--text);margin-bottom:16px}
input:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 3px rgba(143,106,42,0.2)}
.btn-primary{width:100%;padding:14px;background:var(--burgundy);color:#fff;border:none;border-radius:8px;font-size:0.95rem;font-weight:600;cursor:pointer;font-family:inherit;text-align:center;text-decoration:none;display:block}
.btn-primary:hover{background:var(--burgundy-hover)}
.btn-submit{width:100%;padding:12px;background:var(--burgundy);color:#fff;border:none;border-radius:8px;font-size:0.875rem;font-weight:600;cursor:pointer;font-family:inherit}
.btn-submit:hover{background:var(--burgundy-hover)}
.manual-toggle{display:block;width:100%;text-align:center;padding:10px;color:var(--muted);font-size:0.8rem;cursor:pointer;border:none;background:none;margin-top:16px;font-family:inherit}
.manual-toggle:hover{color:var(--text)}
.manual-form{display:none;margin-top:16px;padding-top:16px;border-top:1px solid var(--border)}
.manual-form.show{display:block}
.app-name{font-size:0.75rem;color:var(--muted);text-align:center;margin-top:16px}
.auto-sso{text-align:center;padding:20px 0}
.auto-sso-ring{position:relative;width:64px;height:64px;margin:0 auto 16px}
.auto-sso-ring svg{transform:rotate(-90deg)}
.auto-sso-ring circle.track{fill:none;stroke:var(--border);stroke-width:3}
.auto-sso-ring circle.progress{fill:none;stroke:var(--burgundy);stroke-width:3;stroke-linecap:round;stroke-dasharray:175;stroke-dashoffset:175;transition:stroke-dashoffset 0.3s ease}
.auto-sso-ring .countdown{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:1.25rem;font-weight:700;color:var(--text)}
.auto-sso p{color:var(--muted);font-size:0.9rem;margin-bottom:8px}
.auto-sso .cancel{color:var(--burgundy);font-size:0.75rem;cursor:pointer;border:none;background:none;font-family:inherit;opacity:0.7;transition:opacity 0.2s}
.auto-sso .cancel:hover{opacity:1}
</style>
</head>
<body>
<div class="card">
  <div class="brand"><h1>SimpleAuth</h1><p>Sign in to continue</p></div>
  <div class="gold-bar"></div>
  {{if .ErrorMsg}}<div class="error">{{.ErrorMsg}}</div>{{end}}
  <div id="sso-section" style="display:none">
    <a href="{{.SSOLink}}" class="btn-primary" id="sso-btn">Sign in with Single Sign-On</a>
    <button class="manual-toggle" onclick="document.getElementById('manual-form').classList.add('show');this.style.display='none'">
      Or sign in with username and password
    </button>
  </div>
  <div id="auto-sso-status" style="display:none">
    <div class="auto-sso">
      <div class="auto-sso-ring">
        <svg width="64" height="64" viewBox="0 0 64 64">
          <circle class="track" cx="32" cy="32" r="28"/>
          <circle class="progress" id="sso-progress" cx="32" cy="32" r="28"/>
        </svg>
        <span class="countdown" id="sso-countdown"></span>
      </div>
      <p>Signing in with SSO...</p>
      <button class="cancel" id="sso-cancel">cancel</button>
    </div>
  </div>
  <div id="manual-form" class="manual-form">
    <form method="POST" action="{{.Action}}">
      <input type="hidden" name="client_id" value="{{.ClientID}}">
      <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
      <input type="hidden" name="state" value="{{.State}}">
      <input type="hidden" name="nonce" value="{{.Nonce}}">
      <input type="hidden" name="scope" value="{{.Scope}}">
      <input type="hidden" name="response_type" value="code">
      <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
      <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
      <input type="hidden" name="_csrf" value="{{.CSRFToken}}">
      <label>Username</label>
      <input type="text" name="username" placeholder="Enter your username" autofocus required>
      <label>Password</label>
      <input type="password" name="password" placeholder="Enter your password" required>
      <button type="submit" class="btn-submit">Sign In</button>
    </form>
  </div>
  <div class="app-name">Signing into {{.AppName}}</div>
</div>
<script>
(function(){
  var ssoEnabled = "{{.SSOEnabled}}" === "1";
  var autoSSO = "{{.AutoSSO}}" === "1";
  var ssoLink = "{{.SSOLink}}";
  var ssoDelay = {{.SSODelay}};
  var hasError = document.querySelector('.error') !== null;
  var manualForm = document.getElementById('manual-form');

  function showManualOnly() {
    manualForm.classList.add('show');
    manualForm.style.borderTop = 'none';
    manualForm.style.marginTop = '0';
    manualForm.style.paddingTop = '0';
  }

  function cancelAutoSSO() {
    if (window._ssoTimer) clearInterval(window._ssoTimer);
    if (window._ssoTimeout) clearTimeout(window._ssoTimeout);
    document.getElementById('auto-sso-status').style.display = 'none';
    document.getElementById('sso-section').style.display = 'block';
    manualForm.classList.add('show');
  }

  if (ssoEnabled && !hasError) {
    if (autoSSO && ssoLink && ssoDelay > 0) {
      document.getElementById('auto-sso-status').style.display = 'block';
      document.getElementById('sso-cancel').onclick = cancelAutoSSO;
      var remaining = ssoDelay;
      var circle = document.getElementById('sso-progress');
      var countdownEl = document.getElementById('sso-countdown');
      var circumference = 2 * Math.PI * 28;
      countdownEl.textContent = remaining;
      window._ssoTimer = setInterval(function(){
        remaining--;
        if (remaining <= 0) { clearInterval(window._ssoTimer); countdownEl.textContent = ''; }
        else { countdownEl.textContent = remaining; }
        circle.style.strokeDashoffset = circumference * (1 - (ssoDelay - remaining) / ssoDelay);
      }, 1000);
      circle.style.strokeDasharray = circumference;
      circle.style.strokeDashoffset = circumference;
      window._ssoTimeout = setTimeout(function(){ window.location.href = ssoLink; }, ssoDelay * 1000);
    } else {
      document.getElementById('sso-section').style.display = 'block';
    }
  } else if (ssoEnabled && hasError) {
    document.getElementById('sso-section').style.display = 'block';
    manualForm.classList.add('show');
  } else if (hasError) {
    showManualOnly();
  } else {
    showManualOnly();
  }
})();
</script>
</body>
</html>`
