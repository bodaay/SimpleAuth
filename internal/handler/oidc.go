package handler

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// registerOIDCRoutes registers all OIDC/Keycloak-compatible endpoints.
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
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if h.cfg.TLSDisabled {
		scheme = "http"
	}
	host := r.Host
	if host == "" {
		host = h.cfg.Hostname
		if (scheme == "https" && h.cfg.Port != "443") || (scheme == "http" && h.cfg.Port != "80") {
			host += ":" + h.cfg.Port
		}
	}
	return scheme + "://" + host + h.cfg.BasePath
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

	doc := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                prefix + "/auth",
		"token_endpoint":                        prefix + "/token",
		"userinfo_endpoint":                     prefix + "/userinfo",
		"jwks_uri":                              prefix + "/certs",
		"introspection_endpoint":                prefix + "/token/introspect",
		"end_session_endpoint":                  prefix + "/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "password", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "roles"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
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

// authenticateOIDCClient extracts client credentials from the request.
// Deprecated: client_id/client_secret validation is skipped — SimpleAuth is single-app.
// These fields are accepted for backward compatibility but not enforced.
func (h *Handler) authenticateOIDCClient(r *http.Request) error {
	// Accept any client_id/client_secret — no validation in single-app mode.
	return nil
}

// oidcClientID returns the effective client_id for OIDC claims (azp, audience).
// Uses configured ClientID if set, otherwise defaults to "simpleauth".
func (h *Handler) oidcClientID() string {
	if h.cfg.ClientID != "" {
		return h.cfg.ClientID
	}
	return "simpleauth"
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

	_ = r.FormValue("client_id") // accepted for backward compat, not validated
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	scope := r.FormValue("scope")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		h.renderOIDCLoginError(w, r, "Username and password are required")
		return
	}

	if redirectURI != "" && !isAllowedRedirect(h.getRedirectURIs(), redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	ip := getClientIP(r)
	if !h.loginLimiter.allow(ip) {
		h.renderOIDCLoginError(w, r, "Too many login attempts")
		return
	}

	userGUID, _, err := h.authenticateUser(username, password)
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

	// Assign default roles
	h.assignDefaultRoles(user.GUID)

	// Generate authorization code
	codeBytes := make([]byte, 32)
	rand.Read(codeBytes)
	code := hex.EncodeToString(codeBytes)

	ac := &store.OIDCAuthCode{
		Code:        code,
		UserGUID:    user.GUID,
		RedirectURI: redirectURI,
		Scope:       scope,
		Nonce:       nonce,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		CreatedAt:   time.Now(),
	}
	if err := h.store.SaveOIDCAuthCode(ac); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.audit("oidc_authorize", user.GUID, ip, map[string]interface{}{
		"flow": "authorization_code",
	})

	// Redirect with code
	redirectTarget := redirectURI
	if redirectTarget == "" {
		redirectTarget = h.getDefaultRedirectURI()
	}
	sep := "?"
	if strings.Contains(redirectTarget, "?") {
		sep = "&"
	}
	redirectTarget += sep + "code=" + url.QueryEscape(code)
	if state != "" {
		redirectTarget += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

func (h *Handler) showOIDCLoginPage(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("client_id") // accepted for backward compat, not validated

	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI != "" && !isAllowedRedirect(h.getRedirectURIs(), redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	scope := r.URL.Query().Get("scope")
	errorMsg := r.URL.Query().Get("error")

	errorHTML := ""
	if errorMsg != "" {
		errorHTML = `<div class="error">` + errorMsg + `</div>`
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
		ssoLink = h.url("/login/sso") + "?oidc=1"
		if redirectURI != "" {
			ssoLink += "&redirect_uri=" + url.QueryEscape(redirectURI)
		}
		if state != "" {
			ssoLink += "&state=" + url.QueryEscape(state)
		}
		if nonce != "" {
			ssoLink += "&nonce=" + url.QueryEscape(nonce)
		}
	}

	autoSSO := false
	if ssoEnabled && errorMsg == "" {
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, oidcLoginHTML, action, h.oidcClientID(), redirectURI, state, nonce, scope, appName, errorHTML, ssoLink, ssoEnabledStr, autoSSOStr, ssoDelay)
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

	user, err := h.store.ResolveUser(ac.UserGUID)
	if err != nil {
		oidcError(w, "server_error", "user not found", http.StatusInternalServerError)
		return
	}

	log.Printf("[oidc] Auth code exchange user=%q guid=%s ip=%s", h.resolvePreferredUsername(user), user.GUID, getClientIP(r))
	h.issueOIDCTokens(w, r, user, ac.Scope, ac.Nonce)
}

func (h *Handler) handleOIDCTokenPassword(w http.ResponseWriter, r *http.Request) {
	if err := h.authenticateOIDCClient(r); err != nil {
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

	log.Printf("[oidc] Password grant user=%q ip=%s", username, ip)
	userGUID, _, err := h.authenticateUser(username, password)
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

	// Assign default roles
	h.assignDefaultRoles(user.GUID)

	log.Printf("[oidc] Password grant success user=%q guid=%s ip=%s", username, user.GUID, ip)
	h.issueOIDCTokens(w, r, user, scope, "")
}

func (h *Handler) handleOIDCTokenClientCredentials(w http.ResponseWriter, r *http.Request) {
	if err := h.authenticateOIDCClient(r); err != nil {
		oidcError(w, "invalid_client", err.Error(), http.StatusUnauthorized)
		return
	}

	// Client credentials — no user context, sub = client_id
	issuer := h.oidcIssuer(r)
	claims := auth.Claims{
		Typ:   "Bearer",
		Scope: r.FormValue("scope"),
	}
	claims.Subject = h.oidcClientID()
	claims.Audience = []string{h.oidcClientID()}

	accessToken, err := h.jwt.IssueAccessTokenWithIssuer(claims, h.cfg.AccessTTL, issuer)
	if err != nil {
		oidcError(w, "server_error", "token generation failed", http.StatusInternalServerError)
		return
	}

	log.Printf("[oidc] Client credentials grant client_id=%s ip=%s", h.oidcClientID(), getClientIP(r))
	h.audit("oidc_token", h.oidcClientID(), getClientIP(r), map[string]interface{}{
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

	storedRT, err := h.store.GetRefreshToken(claims.ID)
	if err != nil || storedRT == nil {
		oidcError(w, "invalid_grant", "refresh token not found", http.StatusUnauthorized)
		return
	}

	if storedRT.Used {
		h.store.RevokeTokenFamily(storedRT.FamilyID)
		oidcError(w, "invalid_grant", "token reuse detected, all sessions revoked", http.StatusUnauthorized)
		return
	}

	h.store.MarkRefreshTokenUsed(claims.ID)

	user, err := h.store.ResolveUser(claims.Subject)
	if err != nil {
		oidcError(w, "invalid_grant", "user not found", http.StatusUnauthorized)
		return
	}
	if user.Disabled {
		oidcError(w, "invalid_grant", "account disabled", http.StatusUnauthorized)
		return
	}

	roles, _ := h.store.GetUserRoles(user.GUID)
	perms, _ := h.store.GetUserPermissions(user.GUID)

	issuer := h.oidcIssuer(r)
	accessClaims := h.buildOIDCAccessClaims(user, roles, perms, nil, "")
	accessToken, err := h.jwt.IssueAccessTokenWithIssuer(accessClaims, h.cfg.AccessTTL, issuer)
	if err != nil {
		oidcError(w, "server_error", "token generation failed", http.StatusInternalServerError)
		return
	}

	newRefreshToken, newTokenID, err := h.jwt.IssueRefreshToken(user.GUID, storedRT.FamilyID, h.cfg.RefreshTTL)
	if err != nil {
		oidcError(w, "server_error", "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	rtClaims, _ := h.jwt.ValidateToken(newRefreshToken)
	rt := &store.RefreshToken{
		TokenID:   newTokenID,
		FamilyID:  rtClaims.FamilyID,
		UserGUID:  user.GUID,
		ExpiresAt: time.Now().UTC().Add(h.cfg.RefreshTTL),
		CreatedAt: time.Now().UTC(),
	}
	h.store.SaveRefreshToken(rt)

	jsonResp(w, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(h.cfg.AccessTTL.Seconds()),
		"scope":         r.FormValue("scope"),
	}, http.StatusOK)
}

// issueOIDCTokens generates access_token, refresh_token, and id_token for a user.
func (h *Handler) issueOIDCTokens(w http.ResponseWriter, r *http.Request, user *store.User, scope, nonce string) {
	roles, _ := h.store.GetUserRoles(user.GUID)
	perms := h.resolveUserPermissions(user.GUID, roles)
	issuer := h.oidcIssuer(r)
	ip := getClientIP(r)

	// Access token with Keycloak-compatible claims
	accessClaims := h.buildOIDCAccessClaims(user, roles, perms, nil, scope)
	accessToken, err := h.jwt.IssueAccessTokenWithIssuer(accessClaims, h.cfg.AccessTTL, issuer)
	if err != nil {
		oidcError(w, "server_error", "token generation failed", http.StatusInternalServerError)
		return
	}

	// Refresh token
	refreshToken, tokenID, err := h.jwt.IssueRefreshToken(user.GUID, "", h.cfg.RefreshTTL)
	if err != nil {
		oidcError(w, "server_error", "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	rtClaims, _ := h.jwt.ValidateToken(refreshToken)
	rt := &store.RefreshToken{
		TokenID:   tokenID,
		FamilyID:  rtClaims.FamilyID,
		UserGUID:  user.GUID,
		ExpiresAt: time.Now().UTC().Add(h.cfg.RefreshTTL),
		CreatedAt: time.Now().UTC(),
	}
	h.store.SaveRefreshToken(rt)

	// ID token
	idClaims := auth.Claims{
		Name:             user.DisplayName,
		Email:            user.Email,
		PreferredUsername: user.Email,
		Nonce:            nonce,
		AtHash:           auth.ComputeAtHash(accessToken),
		Typ:              "ID",
		Azp:              h.oidcClientID(),
	}
	if user.Email == "" {
		idClaims.PreferredUsername = user.DisplayName
	}
	idClaims.Subject = user.GUID
	idClaims.Audience = []string{h.cfg.ClientID}

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
func (h *Handler) buildOIDCAccessClaims(user *store.User, roles, perms, groups []string, scope string) auth.Claims {
	preferredUsername := user.Email
	if preferredUsername == "" {
		preferredUsername = user.DisplayName
	}

	claims := auth.Claims{
		Name:             user.DisplayName,
		Email:            user.Email,
		Department:       user.Department,
		Company:          user.Company,
		JobTitle:         user.JobTitle,
		Roles:            roles,
		Permissions:      perms,
		Groups:           groups,
		PreferredUsername: preferredUsername,
		Typ:              "Bearer",
		Azp:              h.oidcClientID(),
		Scope:            scope,
		RealmAccess:      &auth.RealmAccess{Roles: roles},
		ResourceAccess: map[string]*auth.ResourceAccess{
			h.oidcClientID(): {Roles: roles},
		},
	}
	claims.Subject = user.GUID
	claims.Audience = []string{h.oidcClientID()}

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

	if err := h.authenticateOIDCClient(r); err != nil {
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
		"client_id":  h.oidcClientID(),
		"scope":      claims.Scope,
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

	if idTokenHint != "" {
		claims, err := h.jwt.ValidateToken(idTokenHint)
		if err == nil {
			// Revoke all sessions for this user
			sessions, _ := h.store.ListUserSessions(claims.Subject)
			for _, s := range sessions {
				h.store.RevokeTokenFamily(s.FamilyID)
			}
			h.audit("oidc_logout", claims.Subject, getClientIP(r), nil)
		}
	}

	if postLogoutURI != "" {
		http.Redirect(w, r, postLogoutURI, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Logged Out</title></head><body><h1>You have been logged out.</h1></body></html>`)
}

// renderOIDCLoginError redirects back to the OIDC login page with an error.
func (h *Handler) renderOIDCLoginError(w http.ResponseWriter, r *http.Request, msg string) {
	realm := h.cfg.JWTIssuer
	u := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=%s&state=%s&nonce=%s&scope=%s&response_type=code&error=%s",
		h.cfg.BasePath, realm,
		url.QueryEscape(r.FormValue("client_id")),
		url.QueryEscape(r.FormValue("redirect_uri")),
		url.QueryEscape(r.FormValue("state")),
		url.QueryEscape(r.FormValue("nonce")),
		url.QueryEscape(r.FormValue("scope")),
		url.QueryEscape(msg),
	)
	http.Redirect(w, r, u, http.StatusFound)
}

// oidcError returns a standard OAuth2 error response.
func oidcError(w http.ResponseWriter, errorCode, description string, status int) {
	jsonResp(w, map[string]string{
		"error":             errorCode,
		"error_description": description,
	}, status)
}

// OIDC login page template
// oidcLoginHTML format args:
// %[1]s = form action, %[2]s = client_id, %[3]s = redirect_uri, %[4]s = state,
// %[5]s = nonce, %[6]s = scope, %[7]s = appName, %[8]s = errorHTML,
// %[9]s = ssoLink, %[10]s = ssoEnabled ("1"/""), %[11]s = autoSSO ("1"/""), %[12]d = delay
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
input[type=text],input[type=password]{width:100%%;padding:12px 16px;background:var(--input-bg);border:1px solid var(--input-border);border-radius:12px;font-size:0.875rem;font-family:inherit;color:var(--text);margin-bottom:16px}
input:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 3px rgba(143,106,42,0.2)}
.btn-primary{width:100%%;padding:14px;background:var(--burgundy);color:#fff;border:none;border-radius:8px;font-size:0.95rem;font-weight:600;cursor:pointer;font-family:inherit;text-align:center;text-decoration:none;display:block}
.btn-primary:hover{background:var(--burgundy-hover)}
.btn-submit{width:100%%;padding:12px;background:var(--burgundy);color:#fff;border:none;border-radius:8px;font-size:0.875rem;font-weight:600;cursor:pointer;font-family:inherit}
.btn-submit:hover{background:var(--burgundy-hover)}
.manual-toggle{display:block;width:100%%;text-align:center;padding:10px;color:var(--muted);font-size:0.8rem;cursor:pointer;border:none;background:none;margin-top:16px;font-family:inherit}
.manual-toggle:hover{color:var(--text)}
.manual-form{display:none;margin-top:16px;padding-top:16px;border-top:1px solid var(--border)}
.manual-form.show{display:block}
.app-name{font-size:0.75rem;color:var(--muted);text-align:center;margin-top:16px}
.auto-sso{text-align:center;padding:20px 0}
.auto-sso-ring{position:relative;width:64px;height:64px;margin:0 auto 16px}
.auto-sso-ring svg{transform:rotate(-90deg)}
.auto-sso-ring circle.track{fill:none;stroke:var(--border);stroke-width:3}
.auto-sso-ring circle.progress{fill:none;stroke:var(--burgundy);stroke-width:3;stroke-linecap:round;stroke-dasharray:175;stroke-dashoffset:175;transition:stroke-dashoffset 0.3s ease}
.auto-sso-ring .countdown{position:absolute;top:50%%;left:50%%;transform:translate(-50%%,-50%%);font-size:1.25rem;font-weight:700;color:var(--text)}
.auto-sso p{color:var(--muted);font-size:0.9rem;margin-bottom:8px}
.auto-sso .cancel{color:var(--burgundy);font-size:0.75rem;cursor:pointer;border:none;background:none;font-family:inherit;opacity:0.7;transition:opacity 0.2s}
.auto-sso .cancel:hover{opacity:1}
</style>
</head>
<body>
<div class="card">
  <div class="brand"><h1>SimpleAuth</h1><p>Sign in to continue</p></div>
  <div class="gold-bar"></div>
  %[8]s
  <div id="sso-section" style="display:none">
    <a href="%[9]s" class="btn-primary" id="sso-btn">Sign in with Single Sign-On</a>
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
    <form method="POST" action="%[1]s">
      <input type="hidden" name="client_id" value="%[2]s">
      <input type="hidden" name="redirect_uri" value="%[3]s">
      <input type="hidden" name="state" value="%[4]s">
      <input type="hidden" name="nonce" value="%[5]s">
      <input type="hidden" name="scope" value="%[6]s">
      <input type="hidden" name="response_type" value="code">
      <label>Username</label>
      <input type="text" name="username" placeholder="Enter your username" autofocus required>
      <label>Password</label>
      <input type="password" name="password" placeholder="Enter your password" required>
      <button type="submit" class="btn-submit">Sign In</button>
    </form>
  </div>
  <div class="app-name">Signing into %[7]s</div>
</div>
<script>
(function(){
  var ssoEnabled = "%[10]s" === "1";
  var autoSSO = "%[11]s" === "1";
  var ssoLink = "%[9]s";
  var ssoDelay = %[12]d;
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
