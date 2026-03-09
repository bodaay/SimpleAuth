package handler

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
	krbmsg "github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)

	if !h.loginLimiter.allow(ip) {
		w.Header().Set("Retry-After", string(rune(h.loginLimiter.retryAfter(ip)+'0')))
		jsonError(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		AppID    string `json:"app_id"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonError(w, "username and password required", http.StatusBadRequest)
		return
	}

	var userGUID string
	var ldapResult *auth.LDAPResult
	var ldapGroups []string
	var authenticated bool

	if req.AppID != "" {
		// Step 1: Try existing identity mapping
		guid, err := h.store.ResolveMapping("app:"+req.AppID, req.Username)
		if err == nil {
			userGUID = guid
		} else {
			// Step 2: Check app's provider_mappings
			app, appErr := h.store.GetApp(req.AppID)
			if appErr != nil {
				h.audit("login_failed", "", ip, map[string]interface{}{"username": req.Username, "app_id": req.AppID, "reason": "app not found"})
				jsonError(w, "invalid app_id", http.StatusBadRequest)
				return
			}

			if app.ProviderMappings != nil {
				userGUID, ldapResult = h.searchProviderMappings(app, req.Username)
			}
		}
	}

	if userGUID != "" {
		// Resolve merged users
		user, err := h.store.ResolveUser(userGUID)
		if err != nil {
			h.audit("login_failed", "", ip, map[string]interface{}{"username": req.Username, "reason": "user resolution failed"})
			jsonError(w, "user not found", http.StatusUnauthorized)
			return
		}
		userGUID = user.GUID

		if user.Disabled {
			h.audit("login_failed", userGUID, ip, map[string]interface{}{"username": req.Username, "reason": "user disabled"})
			jsonError(w, "account disabled", http.StatusForbidden)
			return
		}

		// Try LDAP auth via mapped LDAP providers
		mappings, _ := h.store.GetMappingsForUser(userGUID)
		for _, m := range mappings {
			if len(m.Provider) > 5 && m.Provider[:5] == "ldap:" {
				providerID := m.Provider[5:]
				provider, err := h.store.GetLDAPProvider(providerID)
				if err != nil {
					continue
				}
				cfg := ldapConfigFromProvider(provider)
				result, err := auth.LDAPAuthenticate(cfg, m.ExternalID, req.Password)
				if err == nil {
					ldapResult = result
					ldapGroups = result.Groups
					authenticated = true
					break
				}
			}
		}

		// Fallback: local password
		if !authenticated && user.PasswordHash != "" {
			if auth.CheckPassword(user.PasswordHash, req.Password) {
				authenticated = true
			}
		}
	} else {
		// No app_id or no mapping found — try LDAP directly
		providers, _ := h.store.ListLDAPProviders()
		sort.Slice(providers, func(i, j int) bool {
			return providers[i].Priority < providers[j].Priority
		})

		for _, p := range providers {
			cfg := ldapConfigFromProvider(p)
			result, err := auth.LDAPAuthenticate(cfg, req.Username, req.Password)
			if err == nil {
				ldapResult = result
				ldapGroups = result.Groups
				authenticated = true

				// Find or create user
				guid, mapErr := h.store.ResolveMapping("ldap:"+p.ProviderID, req.Username)
				if mapErr == nil {
					userGUID = guid
				} else {
					// Auto-create user
					newUser := &store.User{
						DisplayName: result.DisplayName,
						Email:       result.Email,
					}
					h.store.CreateUser(newUser)
					userGUID = newUser.GUID
					h.store.SetIdentityMapping("ldap:"+p.ProviderID, req.Username, userGUID)
					h.audit("user_created", userGUID, ip, map[string]interface{}{"provider": "ldap:" + p.ProviderID, "username": req.Username})
				}

				// Auto-create app mapping if app_id provided
				if req.AppID != "" {
					h.store.SetIdentityMapping("app:"+req.AppID, req.Username, userGUID)
				}
				break
			}
		}

		// Fallback: try local users (if no LDAP or LDAP failed)
		if !authenticated {
			users, _ := h.store.ListUsers()
			for _, u := range users {
				if u.PasswordHash != "" {
					// Check by username via identity mappings
					mappings, _ := h.store.GetMappingsForUser(u.GUID)
					for _, m := range mappings {
						if m.ExternalID == req.Username && auth.CheckPassword(u.PasswordHash, req.Password) {
							userGUID = u.GUID
							authenticated = true
							break
						}
					}
					if authenticated {
						break
					}
				}
			}
		}
	}

	if !authenticated {
		h.audit("login_failed", "", ip, map[string]interface{}{"username": req.Username, "app_id": req.AppID, "reason": "auth failed"})
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Resolve the final user (follow merges)
	finalUser, err := h.store.ResolveUser(userGUID)
	if err != nil {
		jsonError(w, "user resolution error", http.StatusInternalServerError)
		return
	}
	userGUID = finalUser.GUID

	// Update user info from LDAP if available
	if ldapResult != nil && (finalUser.DisplayName == "" || finalUser.Email == "") {
		if ldapResult.DisplayName != "" {
			finalUser.DisplayName = ldapResult.DisplayName
		}
		if ldapResult.Email != "" {
			finalUser.Email = ldapResult.Email
		}
		h.store.UpdateUser(finalUser)
	}

	// Assign default roles if first time in this app
	if req.AppID != "" {
		existingRoles, _ := h.store.GetUserRoles(userGUID, req.AppID)
		if len(existingRoles) == 0 {
			defaultRoles, _ := h.store.GetDefaultRoles(req.AppID)
			if len(defaultRoles) > 0 {
				h.store.SetUserRoles(userGUID, req.AppID, defaultRoles)
			}
		}
	}

	// Issue tokens
	h.issueTokenResponse(w, finalUser, req.AppID, ldapGroups, ip)
}

func (h *Handler) searchProviderMappings(app *store.App, username string) (string, *auth.LDAPResult) {
	providers, _ := h.store.ListLDAPProviders()
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].Priority < providers[j].Priority
	})

	for _, p := range providers {
		pm, ok := app.ProviderMappings["ldap:"+p.ProviderID]
		if !ok {
			continue
		}
		cfg := ldapConfigFromProvider(p)
		result, err := auth.LDAPSearchUser(cfg, pm.Field, username)
		if err != nil {
			continue
		}

		// Found the user in LDAP — find or create GUID
		ldapUsername := result.Username
		guid, err := h.store.ResolveMapping("ldap:"+p.ProviderID, ldapUsername)
		if err != nil {
			// Auto-create user
			newUser := &store.User{
				DisplayName: result.DisplayName,
				Email:       result.Email,
			}
			h.store.CreateUser(newUser)
			guid = newUser.GUID
			h.store.SetIdentityMapping("ldap:"+p.ProviderID, ldapUsername, guid)
		}
		// Auto-create app mapping
		h.store.SetIdentityMapping("app:"+app.AppID, username, guid)
		return guid, result
	}
	return "", nil
}

func (h *Handler) issueTokenResponse(w http.ResponseWriter, user *store.User, appID string, groups []string, ip string) {
	roles, _ := h.store.GetUserRoles(user.GUID, appID)
	perms, _ := h.store.GetUserPermissions(user.GUID, appID)

	claims := auth.Claims{
		Name:        user.DisplayName,
		Email:       user.Email,
		AppID:       appID,
		Roles:       roles,
		Permissions: perms,
		Groups:      groups,
	}
	claims.Subject = user.GUID

	accessToken, err := h.jwt.IssueAccessToken(claims, h.cfg.AccessTTL)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	refreshToken, tokenID, err := h.jwt.IssueRefreshToken(user.GUID, appID, "", h.cfg.RefreshTTL)
	if err != nil {
		jsonError(w, "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	// Parse to get family ID
	rtClaims, _ := h.jwt.ValidateToken(refreshToken)
	rt := &store.RefreshToken{
		TokenID:   tokenID,
		FamilyID:  rtClaims.FamilyID,
		UserGUID:  user.GUID,
		AppID:     appID,
		ExpiresAt: time.Now().UTC().Add(h.cfg.RefreshTTL),
		CreatedAt: time.Now().UTC(),
	}
	h.store.SaveRefreshToken(rt)

	h.audit("login_success", user.GUID, ip, map[string]interface{}{"app_id": appID})

	jsonResp(w, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    int(h.cfg.AccessTTL.Seconds()),
		"token_type":    "Bearer",
	}, http.StatusOK)
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	claims, err := h.jwt.ValidateToken(req.RefreshToken)
	if err != nil {
		jsonError(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Check if token exists and hasn't been used
	storedRT, err := h.store.GetRefreshToken(claims.ID)
	if err != nil {
		jsonError(w, "refresh token not found", http.StatusUnauthorized)
		return
	}

	if storedRT.Used {
		// Token reuse detected — revoke entire family
		h.store.RevokeTokenFamily(storedRT.FamilyID)
		h.audit("token_refresh", claims.Subject, getClientIP(r), map[string]interface{}{
			"event": "replay_detected", "family_id": storedRT.FamilyID,
		})
		jsonError(w, "token reuse detected, all sessions revoked", http.StatusUnauthorized)
		return
	}

	if time.Now().After(storedRT.ExpiresAt) {
		jsonError(w, "refresh token expired", http.StatusUnauthorized)
		return
	}

	// Mark old token as used
	h.store.MarkRefreshTokenUsed(claims.ID)

	// Get user
	user, err := h.store.ResolveUser(claims.Subject)
	if err != nil {
		jsonError(w, "user not found", http.StatusUnauthorized)
		return
	}
	if user.Disabled {
		jsonError(w, "account disabled", http.StatusForbidden)
		return
	}

	// Issue new tokens (same family)
	roles, _ := h.store.GetUserRoles(user.GUID, claims.AppID)
	perms, _ := h.store.GetUserPermissions(user.GUID, claims.AppID)

	newClaims := auth.Claims{
		Name:        user.DisplayName,
		Email:       user.Email,
		AppID:       claims.AppID,
		Roles:       roles,
		Permissions: perms,
	}
	newClaims.Subject = user.GUID

	accessToken, err := h.jwt.IssueAccessToken(newClaims, h.cfg.AccessTTL)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	newRefreshToken, newTokenID, err := h.jwt.IssueRefreshToken(user.GUID, claims.AppID, storedRT.FamilyID, h.cfg.RefreshTTL)
	if err != nil {
		jsonError(w, "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	newRT := &store.RefreshToken{
		TokenID:   newTokenID,
		FamilyID:  storedRT.FamilyID,
		UserGUID:  user.GUID,
		AppID:     claims.AppID,
		ExpiresAt: time.Now().UTC().Add(h.cfg.RefreshTTL),
		CreatedAt: time.Now().UTC(),
	}
	h.store.SaveRefreshToken(newRT)

	h.audit("token_refresh", user.GUID, getClientIP(r), map[string]interface{}{"app_id": claims.AppID})

	jsonResp(w, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
		"expires_in":    int(h.cfg.AccessTTL.Seconds()),
		"token_type":    "Bearer",
	}, http.StatusOK)
}

func (h *Handler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		jsonError(w, "missing authorization header", http.StatusUnauthorized)
		return
	}

	claims, err := h.jwt.ValidateToken(tokenStr)
	if err != nil {
		jsonError(w, "invalid token", http.StatusUnauthorized)
		return
	}

	user, err := h.store.ResolveUser(claims.Subject)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	jsonResp(w, map[string]interface{}{
		"guid":         user.GUID,
		"display_name": user.DisplayName,
		"email":        user.Email,
		"app_id":       claims.AppID,
		"roles":        claims.Roles,
		"permissions":  claims.Permissions,
		"groups":       claims.Groups,
	}, http.StatusOK)
}

func (h *Handler) handleImpersonate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetGUID string `json:"target_guid"`
		AppID      string `json:"app_id"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.TargetGUID == "" {
		jsonError(w, "target_guid required", http.StatusBadRequest)
		return
	}

	target, err := h.store.ResolveUser(req.TargetGUID)
	if err != nil {
		jsonError(w, "target user not found", http.StatusNotFound)
		return
	}

	roles, _ := h.store.GetUserRoles(target.GUID, req.AppID)
	perms, _ := h.store.GetUserPermissions(target.GUID, req.AppID)

	// Get admin GUID from the Authorization header (it's the master key, so we use "admin")
	adminActor := "admin"

	claims := auth.Claims{
		Name:           target.DisplayName,
		Email:          target.Email,
		AppID:          req.AppID,
		Roles:          roles,
		Permissions:    perms,
		Impersonated:   true,
		ImpersonatedBy: adminActor,
	}
	claims.Subject = target.GUID

	accessToken, err := h.jwt.IssueAccessToken(claims, h.cfg.ImpersonateTTL)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	ip := getClientIP(r)
	h.audit("impersonation", adminActor, ip, map[string]interface{}{
		"target_guid": target.GUID, "app_id": req.AppID,
	})

	jsonResp(w, map[string]interface{}{
		"access_token": accessToken,
		"expires_in":   int(h.cfg.ImpersonateTTL.Seconds()),
		"token_type":   "Bearer",
		"impersonated": true,
	}, http.StatusOK)
}

func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(h.jwt.JWKSHandler())
}

func extractBearerToken(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if len(a) > 7 && a[:7] == "Bearer " {
		return a[7:]
	}
	return ""
}

// authenticateUser performs the full auth flow and returns (userGUID, ldapGroups, error).
// Shared by API login and hosted login.
func (h *Handler) authenticateUser(username, password, appID string) (string, []string, error) {
	var userGUID string
	var ldapGroups []string
	var authenticated bool

	if appID != "" {
		// Try existing identity mapping
		guid, err := h.store.ResolveMapping("app:"+appID, username)
		if err == nil {
			userGUID = guid
		} else {
			// Check app's provider_mappings
			app, appErr := h.store.GetApp(appID)
			if appErr != nil {
				return "", nil, fmt.Errorf("invalid app_id")
			}
			if app.ProviderMappings != nil {
				guid, result := h.searchProviderMappings(app, username)
				if guid != "" {
					userGUID = guid
					if result != nil {
						ldapGroups = result.Groups
					}
				}
			}
		}
	}

	if userGUID != "" {
		user, err := h.store.ResolveUser(userGUID)
		if err != nil {
			return "", nil, fmt.Errorf("user resolution failed")
		}
		userGUID = user.GUID
		if user.Disabled {
			return "", nil, fmt.Errorf("account disabled")
		}

		// Try LDAP auth via mapped providers
		mappings, _ := h.store.GetMappingsForUser(userGUID)
		for _, m := range mappings {
			if len(m.Provider) > 5 && m.Provider[:5] == "ldap:" {
				providerID := m.Provider[5:]
				provider, err := h.store.GetLDAPProvider(providerID)
				if err != nil {
					continue
				}
				cfg := ldapConfigFromProvider(provider)
				result, err := auth.LDAPAuthenticate(cfg, m.ExternalID, password)
				if err == nil {
					ldapGroups = result.Groups
					authenticated = true
					break
				}
			}
		}

		// Fallback: local password
		if !authenticated && user.PasswordHash != "" {
			if auth.CheckPassword(user.PasswordHash, password) {
				authenticated = true
			}
		}
	} else {
		// No app_id or no mapping — try LDAP directly
		providers, _ := h.store.ListLDAPProviders()
		sort.Slice(providers, func(i, j int) bool {
			return providers[i].Priority < providers[j].Priority
		})
		for _, p := range providers {
			cfg := ldapConfigFromProvider(p)
			result, err := auth.LDAPAuthenticate(cfg, username, password)
			if err == nil {
				ldapGroups = result.Groups
				authenticated = true
				guid, mapErr := h.store.ResolveMapping("ldap:"+p.ProviderID, username)
				if mapErr == nil {
					userGUID = guid
				} else {
					newUser := &store.User{DisplayName: result.DisplayName, Email: result.Email}
					h.store.CreateUser(newUser)
					userGUID = newUser.GUID
					h.store.SetIdentityMapping("ldap:"+p.ProviderID, username, userGUID)
				}
				if appID != "" {
					h.store.SetIdentityMapping("app:"+appID, username, userGUID)
				}
				break
			}
		}

		// Fallback: local users
		if !authenticated {
			users, _ := h.store.ListUsers()
			for _, u := range users {
				if u.PasswordHash != "" {
					mappings, _ := h.store.GetMappingsForUser(u.GUID)
					for _, m := range mappings {
						if m.ExternalID == username && auth.CheckPassword(u.PasswordHash, password) {
							userGUID = u.GUID
							authenticated = true
							break
						}
					}
					if authenticated {
						break
					}
				}
			}
		}
	}

	if !authenticated {
		return "", nil, fmt.Errorf("invalid credentials")
	}
	return userGUID, ldapGroups, nil
}

// issueTokenPair creates access + refresh tokens and stores the refresh token.
func (h *Handler) issueTokenPair(user *store.User, appID string, roles, perms, groups []string) (string, string, int, error) {
	claims := auth.Claims{
		Name:        user.DisplayName,
		Email:       user.Email,
		AppID:       appID,
		Roles:       roles,
		Permissions: perms,
		Groups:      groups,
	}
	claims.Subject = user.GUID

	accessToken, err := h.jwt.IssueAccessToken(claims, h.cfg.AccessTTL)
	if err != nil {
		return "", "", 0, err
	}

	refreshToken, tokenID, err := h.jwt.IssueRefreshToken(user.GUID, appID, "", h.cfg.RefreshTTL)
	if err != nil {
		return "", "", 0, err
	}

	rtClaims, _ := h.jwt.ValidateToken(refreshToken)
	rt := &store.RefreshToken{
		TokenID:   tokenID,
		FamilyID:  rtClaims.FamilyID,
		UserGUID:  user.GUID,
		AppID:     appID,
		ExpiresAt: time.Now().UTC().Add(h.cfg.RefreshTTL),
		CreatedAt: time.Now().UTC(),
	}
	h.store.SaveRefreshToken(rt)

	return accessToken, refreshToken, int(h.cfg.AccessTTL.Seconds()), nil
}

// handleResetPassword allows an authenticated user to change their password.
// POST /api/auth/reset-password with Authorization: Bearer <access_token>
func (h *Handler) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	// Validate current token
	tokenStr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tokenStr == "" {
		jsonError(w, "authorization required", http.StatusUnauthorized)
		return
	}

	claims, err := h.jwt.ValidateToken(tokenStr)
	if err != nil {
		jsonError(w, "invalid token", http.StatusUnauthorized)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.NewPassword == "" {
		jsonError(w, "new_password required", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 6 {
		jsonError(w, "new_password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	user, err := h.store.ResolveUser(claims.Subject)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	// Verify current password if user has one set
	if user.PasswordHash != "" {
		if req.CurrentPassword == "" {
			jsonError(w, "current_password required", http.StatusBadRequest)
			return
		}
		if !auth.CheckPassword(user.PasswordHash, req.CurrentPassword) {
			jsonError(w, "current password is incorrect", http.StatusForbidden)
			return
		}
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		jsonError(w, "failed to hash password", http.StatusInternalServerError)
		return
	}
	user.PasswordHash = hash
	if err := h.store.UpdateUser(user); err != nil {
		jsonError(w, "failed to update password", http.StatusInternalServerError)
		return
	}

	ip := getClientIP(r)
	h.audit("password_changed", user.GUID, ip, nil)
	jsonResp(w, map[string]string{"status": "password updated"}, http.StatusOK)
}

// handleNegotiate handles Kerberos/SPNEGO authentication.
// GET /api/auth/negotiate?app_id=X
// Browser sends Authorization: Negotiate <base64-token>
func (h *Handler) handleNegotiate(w http.ResponseWriter, r *http.Request) {
	if h.cfg.KRB5Keytab == "" {
		jsonError(w, "Kerberos not configured", http.StatusNotImplemented)
		return
	}

	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		jsonError(w, "app_id query parameter required", http.StatusBadRequest)
		return
	}

	app, err := h.store.GetApp(appID)
	if err != nil {
		jsonError(w, "invalid app_id", http.StatusBadRequest)
		return
	}
	_ = app // used later for token issuance

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Negotiate ") {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		jsonError(w, "Kerberos authentication required", http.StatusUnauthorized)
		return
	}

	// Decode SPNEGO token
	tokenB64 := authHeader[10:]
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		jsonError(w, "invalid Negotiate token encoding", http.StatusBadRequest)
		return
	}

	// Load keytab
	kt, err := keytab.Load(h.cfg.KRB5Keytab)
	if err != nil {
		jsonError(w, "failed to load keytab", http.StatusInternalServerError)
		return
	}

	// Parse SPNEGO token
	var spnegoToken spnego.SPNEGOToken
	if err := spnegoToken.Unmarshal(tokenBytes); err != nil {
		jsonError(w, "invalid SPNEGO token", http.StatusUnauthorized)
		return
	}

	// Extract the Kerberos AP-REQ from the SPNEGO mechToken
	if len(spnegoToken.NegTokenInit.MechTokenBytes) == 0 {
		jsonError(w, "no mech token in SPNEGO", http.StatusUnauthorized)
		return
	}

	var apReq krbmsg.APReq
	if err := apReq.Unmarshal(spnegoToken.NegTokenInit.MechTokenBytes); err != nil {
		jsonError(w, "invalid AP-REQ", http.StatusUnauthorized)
		return
	}

	// Decrypt and validate the ticket
	if err = apReq.Ticket.DecryptEncPart(kt, nil); err != nil {
		jsonError(w, "Kerberos ticket validation failed", http.StatusUnauthorized)
		return
	}

	// Extract principal name
	principal := apReq.Ticket.SName.PrincipalNameString()
	// The client principal is in the encrypted part
	cname := apReq.Ticket.DecryptedEncPart.CName.PrincipalNameString()
	if cname == "" {
		cname = principal
	}

	// Strip realm if present (user@REALM -> user)
	username := cname
	if idx := strings.Index(cname, "@"); idx > 0 {
		username = cname[:idx]
	}

	ip := getClientIP(r)

	// Look up user by kerberos identity mapping
	userGUID, err := h.store.ResolveMapping("kerberos", cname)
	if err != nil {
		// Try without realm
		userGUID, err = h.store.ResolveMapping("kerberos", username)
	}
	if err != nil {
		// Auto-provision: look for a user with matching display name
		users, _ := h.store.ListUsers()
		for _, u := range users {
			if u.DisplayName == username || u.Email == username {
				userGUID = u.GUID
				// Create identity mapping for next time
				h.store.SetIdentityMapping("kerberos", cname, userGUID)
				break
			}
		}
		if userGUID == "" {
			h.audit("negotiate_failed", "", ip, map[string]interface{}{
				"principal": cname, "app_id": appID, "reason": "no matching user",
			})
			jsonError(w, "no user found for Kerberos principal: "+cname, http.StatusUnauthorized)
			return
		}
	}

	user, err := h.store.ResolveUser(userGUID)
	if err != nil {
		jsonError(w, "user not found", http.StatusUnauthorized)
		return
	}
	if user.Disabled {
		jsonError(w, "account disabled", http.StatusForbidden)
		return
	}

	// Issue tokens
	roles, _ := h.store.GetUserRoles(user.GUID, appID)
	perms, _ := h.store.GetUserPermissions(user.GUID, appID)
	accessToken, refreshToken, expiresIn, err := h.issueTokenPair(user, appID, roles, perms, nil)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	h.audit("login_success", user.GUID, ip, map[string]interface{}{
		"app_id": appID, "flow": "kerberos", "principal": cname,
	})

	jsonResp(w, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    expiresIn,
		"token_type":    "Bearer",
	}, http.StatusOK)
}
