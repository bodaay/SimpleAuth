package handler

import (
	"net/http"
	"sort"
	"time"

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
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}
