package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
	krbmsg "github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// kerberosMaxClockSkew bounds the acceptable difference between the Kerberos
// ticket/authenticator time and this server's clock. It also sizes the AP-REQ
// replay cache window. Standard Kerberos tolerance is 5 minutes — ensure the
// server, KDC, and clients are NTP-synced.
const kerberosMaxClockSkew = 5 * time.Minute

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)

	if !h.loginLimiter.allow(ip) {
		w.Header().Set("Retry-After", strconv.Itoa(h.loginLimiter.retryAfter(ip)))
		jsonError(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		AppID    string `json:"app_id"`
		ClientID string `json:"client_id"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonError(w, "username and password required", http.StatusBadRequest)
		return
	}

	// Resolve the app this token is for (v2 audience-scoped tokens). An empty
	// app_id/client_id resolves to the default app.
	clientID := req.AppID
	if clientID == "" {
		clientID = req.ClientID
	}
	app, err := h.resolveApp(clientID)
	if err != nil {
		jsonError(w, "unknown app", http.StatusBadRequest)
		return
	}

	log.Printf("[login] Attempt user=%q app=%q ip=%s", req.Username, app.AppID, ip)

	userGUID, ldapGroups, err := h.authenticateUser(req.Username, req.Password, app)
	if err != nil {
		log.Printf("[login] Failed user=%q ip=%s reason=%q", req.Username, ip, err.Error())
		h.audit("login_failed", "", ip, map[string]interface{}{"username": req.Username, "reason": err.Error()})
		// Return a uniform failure regardless of cause (unknown user, wrong
		// password, disabled, or locked) so an unauthenticated caller cannot
		// enumerate account state (M7). The specific reason is in the audit log
		// and visible to admins.
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Resolve the final user (follow merges)
	finalUser, err := h.store.ResolveUser(userGUID)
	if err != nil {
		jsonError(w, "user resolution error", http.StatusInternalServerError)
		return
	}

	log.Printf("[login] Success user=%q guid=%s name=%q ip=%s", req.Username, finalUser.GUID, finalUser.DisplayName, ip)

	// Check force password change — still issue tokens but flag the response
	if finalUser.ForcePasswordChange {
		roles, perms, denied := h.resolveTokenRoles(app, finalUser)
		if denied {
			jsonError(w, "access denied: not assigned to this app", http.StatusForbidden)
			return
		}
		accessToken, refreshToken, expiresIn, err := h.issueTokenPair(finalUser, roles, perms, ldapGroups, app)
		if err != nil {
			jsonError(w, "token generation failed", http.StatusInternalServerError)
			return
		}
		h.auditLogin(finalUser, ip, map[string]interface{}{"force_password_change": true})
		jsonResp(w, map[string]interface{}{
			"access_token":          accessToken,
			"refresh_token":         refreshToken,
			"expires_in":            expiresIn,
			"token_type":            "Bearer",
			"force_password_change": true,
		}, http.StatusOK)
		return
	}

	// Issue tokens
	h.issueTokenResponse(w, finalUser, ldapGroups, ip, app)
}

// authenticateUser performs the full auth flow and returns (userGUID, ldapGroups, error).
// Flow: local first -> LDAP fallback. Local users are SimpleAuth's own — they always take priority.
// On successful LDAP auth, user profile is synced from the LDAP result.
func (h *Handler) authenticateUser(username, password string, app *store.App) (string, []string, error) {
	var userGUID string
	var ldapGroups []string
	var ldapResult *auth.LDAPResult
	var authenticated bool
	var localUser *store.User // track for lockout accounting

	// Step 0: app-local users (v2 M5). At a given app, an app-local user of the
	// same name shadows any directory user — a customer named like an employee
	// never inherits employee access. App-local users authenticate locally only.
	if app != nil {
		if guid, err := h.store.ResolveMapping("applocal:"+app.AppID, username); err == nil {
			user, uerr := h.store.ResolveUser(guid)
			if uerr == nil && user.OwnerAppID == app.AppID {
				if user.Disabled {
					return "", nil, fmt.Errorf("account disabled")
				}
				if h.isAccountLocked(user) {
					return "", nil, fmt.Errorf("account locked")
				}
				if user.PasswordHash != "" && auth.CheckPassword(user.PasswordHash, password) {
					log.Printf("[auth] App-local auth success user=%q app=%q guid=%s", username, app.AppID, user.GUID)
					return user.GUID, nil, nil
				}
				h.recordFailedLogin(user)
				return "", nil, fmt.Errorf("invalid credentials")
			}
		}
	}

	// Step 1: Try local identity mapping + password (local users always take priority)
	guid, err := h.store.ResolveMapping("local", username)
	if err == nil {
		user, err := h.store.ResolveUser(guid)
		if err == nil {
			localUser = user
			if user.Disabled {
				return "", nil, fmt.Errorf("account disabled")
			}
			// Check account lockout
			if h.isAccountLocked(user) {
				return "", nil, fmt.Errorf("account locked")
			}
			if user.PasswordHash != "" && auth.CheckPassword(user.PasswordHash, password) {
				userGUID = user.GUID
				authenticated = true
				log.Printf("[auth] Local auth success user=%q guid=%s", username, user.GUID)
			}
		}
	}

	// Step 2: Fallback — try LDAP authentication (if configured and local didn't match)
	if !authenticated {
		ldapCfg, ldapErr := h.getLDAPConfigDecrypted()
		if ldapErr == nil {
			cfg := ldapConfigFromStore(ldapCfg)
			result, err := auth.LDAPAuthenticate(cfg, username, password)
			if err == nil {
				ldapGroups = result.Groups
				ldapResult = result
				authenticated = true
				log.Printf("[auth] LDAP auth success user=%q name=%q email=%q groups=%d", username, result.DisplayName, result.Email, len(result.Groups))

				// Resolve or JIT-provision user
				guid, mapErr := h.store.ResolveMapping("ldap", username)
				if mapErr == nil {
					userGUID = guid
					log.Printf("[auth] LDAP user resolved user=%q guid=%s", username, guid)
				} else {
					// JIT provisioning
					newUser := &store.User{
						DisplayName:    result.DisplayName,
						Email:          result.Email,
						Department:     result.Department,
						Company:        result.Company,
						JobTitle:       result.JobTitle,
						SAMAccountName: result.Username,
					}
					h.store.CreateUser(newUser)
					userGUID = newUser.GUID
					h.store.SetIdentityMapping("ldap", username, userGUID)
					h.store.SetIdentityMapping("local", username, userGUID)
					// Also map under the real sAMAccountName so future lookups
					// by the authoritative AD identifier work, regardless of
					// what string the user originally typed into the form.
					if result.Username != "" && result.Username != username {
						h.store.SetIdentityMapping("ldap", result.Username, userGUID)
						h.store.SetIdentityMapping("local", result.Username, userGUID)
					}
					log.Printf("[auth] JIT provisioned user=%q guid=%s name=%q email=%q sam=%q", username, newUser.GUID, result.DisplayName, result.Email, result.Username)
				}
			}
		}
	}

	if !authenticated {
		// Record failed login attempt for lockout tracking
		if localUser != nil {
			h.recordFailedLogin(localUser)
			log.Printf("[auth] Failed attempts=%d user=%q guid=%s", localUser.FailedLoginAttempts, username, localUser.GUID)
		}
		log.Printf("[auth] Authentication failed user=%q (no valid local or LDAP credentials)", username)
		return "", nil, fmt.Errorf("invalid credentials")
	}

	// Check disabled
	finalUser, err := h.store.ResolveUser(userGUID)
	if err != nil {
		return "", nil, fmt.Errorf("user resolution failed")
	}
	if finalUser.Disabled {
		return "", nil, fmt.Errorf("account disabled")
	}

	// Clear failed login attempts on successful auth
	if finalUser.FailedLoginAttempts > 0 {
		finalUser.FailedLoginAttempts = 0
		finalUser.LockedUntil = nil
		h.store.UpdateUser(finalUser)
	}

	// Sync profile from LDAP on every successful LDAP login
	if ldapResult != nil {
		h.syncUserFromLDAP(finalUser, ldapResult)
	}

	return finalUser.GUID, ldapGroups, nil
}

// isAccountLocked checks if a user account is currently locked due to failed login attempts.
func (h *Handler) isAccountLocked(user *store.User) bool {
	if h.getAccountLockoutThreshold() <= 0 {
		return false
	}
	if user.LockedUntil == nil {
		return false
	}
	if time.Now().After(*user.LockedUntil) {
		// Lock has expired — clear it
		user.FailedLoginAttempts = 0
		user.LockedUntil = nil
		h.store.UpdateUser(user)
		return false
	}
	return true
}

// recordFailedLogin increments the failed login counter and locks the account if threshold is reached.
func (h *Handler) recordFailedLogin(user *store.User) {
	user.FailedLoginAttempts++
	threshold := h.getAccountLockoutThreshold()
	if threshold > 0 && user.FailedLoginAttempts >= threshold {
		lockUntil := time.Now().Add(h.getAccountLockoutDuration())
		user.LockedUntil = &lockUntil
		log.Printf("[auth] Account locked guid=%s until=%s (threshold=%d)", user.GUID, lockUntil.Format(time.RFC3339), threshold)
	}
	h.store.UpdateUser(user)
}

// passwordPolicy returns the auth.PasswordPolicy derived from config.
func (h *Handler) passwordPolicy() auth.PasswordPolicy {
	if rs := h.runtimeSettings.get(); rs != nil {
		return auth.PasswordPolicy{
			MinLength:        rs.PasswordMinLength,
			RequireUppercase: rs.PasswordRequireUppercase,
			RequireLowercase: rs.PasswordRequireLowercase,
			RequireDigit:     rs.PasswordRequireDigit,
			RequireSpecial:   rs.PasswordRequireSpecial,
		}
	}
	return auth.PasswordPolicy{
		MinLength:        h.cfg.PasswordMinLength,
		RequireUppercase: h.cfg.PasswordRequireUppercase,
		RequireLowercase: h.cfg.PasswordRequireLowercase,
		RequireDigit:     h.cfg.PasswordRequireDigit,
		RequireSpecial:   h.cfg.PasswordRequireSpecial,
	}
}

// syncUserFromLDAP updates a user's profile fields from LDAP result (non-empty fields only).
// Also backfills SAMAccountName — this is the self-healing path for users who
// were provisioned before SAMAccountName existed on the User struct, or who
// were created via admin UI without LDAP enrichment.
func (h *Handler) syncUserFromLDAP(user *store.User, result *auth.LDAPResult) {
	changed := false
	if result.DisplayName != "" && result.DisplayName != user.DisplayName {
		user.DisplayName = result.DisplayName
		changed = true
	}
	if result.Email != "" && result.Email != user.Email {
		user.Email = result.Email
		changed = true
	}
	if result.Department != "" && result.Department != user.Department {
		user.Department = result.Department
		changed = true
	}
	if result.Company != "" && result.Company != user.Company {
		user.Company = result.Company
		changed = true
	}
	if result.JobTitle != "" && result.JobTitle != user.JobTitle {
		user.JobTitle = result.JobTitle
		changed = true
	}
	if result.Username != "" && result.Username != user.SAMAccountName {
		user.SAMAccountName = result.Username
		changed = true
	}
	// Persist the user's directory groups so per-app group assignments (v2 M3)
	// can be resolved at token issuance in every flow (not just the live login).
	// sync runs only after a successful bind, so an EMPTY group list is
	// authoritative: a user removed from all groups must have the stale set cleared,
	// otherwise group-derived per-app roles persist after de-grouping (M13).
	if strings.Join(result.Groups, "\x00") != strings.Join(user.Groups, "\x00") {
		user.Groups = result.Groups
		changed = true
	}
	if changed {
		h.store.UpdateUser(user)
	}
	// Opportunistic mapping backfill: make sure the real sAMAccountName is
	// also a valid lookup key, so future admin API calls and future JIT
	// collision checks work by the authoritative AD identity.
	if result.Username != "" {
		if existing, _ := h.store.ResolveMapping("ldap", result.Username); existing == "" {
			h.store.SetIdentityMapping("ldap", result.Username, user.GUID)
		}
		if existing, _ := h.store.ResolveMapping("local", result.Username); existing == "" {
			h.store.SetIdentityMapping("local", result.Username, user.GUID)
		}
	}
}

func (h *Handler) issueTokenResponse(w http.ResponseWriter, user *store.User, groups []string, ip string, app *store.App) {
	roles, perms, denied := h.resolveTokenRoles(app, user)
	if denied {
		jsonError(w, "access denied: not assigned to this app", http.StatusForbidden)
		return
	}

	accessToken, refreshToken, expiresIn, err := h.issueTokenPair(user, roles, perms, groups, app)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	h.auditLogin(user, ip, nil)

	jsonResp(w, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    expiresIn,
		"token_type":    "Bearer",
	}, http.StatusOK)
}

// issueTokenPair creates access + refresh tokens and stores the refresh token.
// When app is non-nil the access token is stamped with the app's audience and
// the refresh token is bound to that app (v2 audience-scoped tokens).
func (h *Handler) issueTokenPair(user *store.User, roles []string, perms []string, groups []string, app *store.App) (string, string, int, error) {
	claims := auth.Claims{
		GUID:              user.GUID,
		Name:              user.DisplayName,
		Email:             user.Email,
		Department:        user.Department,
		Company:           user.Company,
		JobTitle:          user.JobTitle,
		SAMAccountName:    user.SAMAccountName,
		Roles:             roles,
		Permissions:       perms,
		Groups:            groups,
		PreferredUsername: h.resolvePreferredUsername(user),
	}
	claims.Subject = user.GUID
	aud := ""
	if app != nil {
		aud = appAudience(app)
		claims.Audience = []string{aud}
		// Azp = the app's stable, unique id (distinct from the free-form, possibly
		// non-unique audience). The per-app-admin gate binds on this so a token can
		// only act as a management token when minted for the exact management app.
		claims.Azp = app.AppID
	}

	accessToken, err := h.jwt.IssueAccessToken(claims, h.cfg.AccessTTL)
	if err != nil {
		return "", "", 0, err
	}

	refreshToken, tokenID, familyID, err := h.jwt.IssueRefreshToken(user.GUID, "", h.cfg.RefreshTTL)
	if err != nil {
		return "", "", 0, err
	}

	rt := &store.RefreshToken{
		TokenID:   tokenID,
		FamilyID:  familyID,
		UserGUID:  user.GUID,
		ExpiresAt: time.Now().UTC().Add(h.cfg.RefreshTTL),
		CreatedAt: time.Now().UTC(),
	}
	if app != nil {
		rt.AppID = app.AppID
		rt.Audience = aud
	}
	// Persist before returning the pair: if the refresh row is not stored, the
	// client would receive a refresh token that can never be redeemed.
	if err := h.store.SaveRefreshToken(rt); err != nil {
		return "", "", 0, fmt.Errorf("persist refresh token: %w", err)
	}

	return accessToken, refreshToken, int(h.cfg.AccessTTL.Seconds()), nil
}

// isDirectoryBacked reports whether the user's AUTHORITATIVE credential lives in
// the directory (AD, via LDAP or Kerberos) rather than in SimpleAuth.
//
// This is the server-side truth behind the `auth_source` hint /api/auth/userinfo
// returns. It exists because a local password hash on a directory identity is a
// permanent SHADOW credential: authenticateUser resolves the "local" mapping
// FIRST ("local users always take priority") and nothing in SimpleAuth mirrors AD
// account state — there is no userAccountControl read anywhere — so such a hash
// keeps working after the AD account is disabled or the employee is terminated,
// while the victim's AD password still works (a failed local check falls through
// to the LDAP step) so nothing looks wrong (SA-7).
//
// No single signal is complete, so three are combined:
//
//   - OwnerAppID != "" → an app-LOCAL user (M5). Their password genuinely lives
//     here and they must keep self-service. Checked first because it is exact.
//   - SAMAccountName != "" → written ONLY by syncUserFromLDAP and the LDAP/Kerberos
//     JIT paths; no admin or app API exposes the field, so it is a reliable
//     positive. Not sufficient alone: POST /api/admin/ldap/import-users creates the
//     "ldap" mapping but leaves SAMAccountName empty until the first login.
//   - any identity mapping whose provider is neither "local" nor "applocal:<app_id>"
//     — "ldap", "kerberos", or any federated provider an admin attached. Note this
//     is deliberately NOT userinfo's plain `!= "local"` test, which would wrongly
//     call an app-local customer a directory user.
//
// A user who is BOTH (an admin-created local account later linked to AD) counts as
// directory-backed here. That only bites on the CREATE path — callers consult this
// when the local hash is EMPTY; an existing local hash stays rotatable with proof
// of possession.
//
// NOTE: internal/migrate/bundle.go:classifyUser answers a DIFFERENT question — it
// must produce a portable KEY for a user, not a yes/no verdict — and classifies on
// hash-presence and SAMAccountName rather than this predicate. Do not unify the
// two: internal/migrate importing from internal/handler would invert the
// dependency direction.
func (h *Handler) isDirectoryBacked(user *store.User) bool {
	if user.OwnerAppID != "" {
		return false
	}
	if user.SAMAccountName != "" {
		return true
	}
	mappings, err := h.store.GetMappingsForUser(user.GUID)
	if err != nil {
		// Fail CLOSED. A store error means we cannot PROVE the account is local. The
		// cost of a false positive is one refused password change (an admin can still
		// set it); the cost of a false negative is a permanent shadow credential on
		// an AD identity.
		log.Printf("[password] mappings lookup failed guid=%s err=%v — treating as directory-backed", user.GUID, err)
		return true
	}
	for _, m := range mappings {
		if m.Provider != "local" && !strings.HasPrefix(m.Provider, "applocal:") {
			return true
		}
	}
	return false
}

// resolvePreferredUsername finds the username for a user from identity mappings.
// Priority: local mapping > ldap mapping > email > display name.
func (h *Handler) resolvePreferredUsername(user *store.User) string {
	mappings, _ := h.store.GetMappingsForUser(user.GUID)
	var ldapUsername string
	for _, m := range mappings {
		if m.Provider == "local" {
			return m.ExternalID
		}
		if m.Provider == "ldap" && ldapUsername == "" {
			ldapUsername = m.ExternalID
		}
	}
	if ldapUsername != "" {
		return ldapUsername
	}
	// Fallback: email or display name
	if user.Email != "" {
		return user.Email
	}
	return user.DisplayName
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if !h.loginLimiter.allow(ip) {
		jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	claims, err := h.jwt.ValidateToken(req.RefreshToken)
	if err != nil {
		log.Printf("[refresh] Invalid token ip=%s err=%q", ip, err.Error())
		jsonError(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Atomically consume the refresh token (single-use). This closes the
	// rotation TOCTOU: two concurrent requests with the same token cannot both
	// succeed — exactly one consumes it, any other sees reuse.
	storedRT, err := h.store.ConsumeRefreshToken(claims.ID)
	if errors.Is(err, store.ErrRefreshTokenReused) {
		// Token reuse detected — revoke entire family
		h.store.RevokeTokenFamily(storedRT.FamilyID)
		log.Printf("[refresh] REPLAY DETECTED user=%s family=%s ip=%s — all sessions revoked", claims.Subject, storedRT.FamilyID, ip)
		h.audit("token_refresh", claims.Subject, getClientIP(r), map[string]interface{}{
			"event": "replay_detected", "family_id": storedRT.FamilyID,
		})
		jsonError(w, "token reuse detected, all sessions revoked", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("[refresh] Token not found id=%s user=%s ip=%s", claims.ID, claims.Subject, ip)
		jsonError(w, "refresh token not found", http.StatusUnauthorized)
		return
	}

	if time.Now().After(storedRT.ExpiresAt) {
		jsonError(w, "refresh token expired", http.StatusUnauthorized)
		return
	}

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
	// Honor the admin "revoke all sessions" kill switch on refresh too (M3):
	// a refreshed access token must not be mintable after access revocation.
	if revoked, _ := h.store.IsUserAccessRevoked(user.GUID); revoked {
		jsonError(w, "access revoked", http.StatusUnauthorized)
		return
	}

	// Refresh stays bound to the app the token was issued for (v2). Re-resolve the
	// app so a disabled/deleted app stops minting tokens (M10), and recompute the
	// per-app roles + the require_assignment gate instead of carrying the user's
	// GLOBAL roles — using global roles here let a scoped token escalate on refresh
	// (H5).
	app, err := h.resolveApp(storedRT.AppID)
	if err != nil {
		jsonError(w, "app unavailable", http.StatusUnauthorized)
		return
	}
	roles, perms, denied := h.resolveTokenRoles(app, user)
	if denied {
		jsonError(w, "access denied: not assigned to this app", http.StatusForbidden)
		return
	}

	newClaims := auth.Claims{
		GUID:              user.GUID,
		Name:              user.DisplayName,
		Email:             user.Email,
		Department:        user.Department,
		Company:           user.Company,
		JobTitle:          user.JobTitle,
		SAMAccountName:    user.SAMAccountName,
		Roles:             roles,
		Permissions:       perms,
		PreferredUsername: h.resolvePreferredUsername(user),
	}
	newClaims.Subject = user.GUID
	// Refresh stays bound to the same app (v2): re-stamp the original audience.
	if storedRT.Audience != "" {
		newClaims.Audience = []string{storedRT.Audience}
	}

	accessToken, err := h.jwt.IssueAccessToken(newClaims, h.cfg.AccessTTL)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	newRefreshToken, newTokenID, newFamilyID, err := h.jwt.IssueRefreshToken(user.GUID, storedRT.FamilyID, h.cfg.RefreshTTL)
	if err != nil {
		jsonError(w, "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	newRT := &store.RefreshToken{
		TokenID:   newTokenID,
		FamilyID:  newFamilyID,
		UserGUID:  user.GUID,
		ExpiresAt: time.Now().UTC().Add(h.cfg.RefreshTTL),
		CreatedAt: time.Now().UTC(),
		AppID:     storedRT.AppID,
		Audience:  storedRT.Audience,
	}
	if err := h.store.SaveRefreshToken(newRT); err != nil {
		jsonError(w, "refresh token generation failed", http.StatusInternalServerError)
		return
	}

	log.Printf("[refresh] Success user=%q guid=%s ip=%s", h.resolvePreferredUsername(user), user.GUID, ip)
	h.audit("token_refresh", user.GUID, getClientIP(r), nil)

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

	claims, err := h.validateAccessToken(tokenStr)
	if err != nil {
		jsonError(w, "invalid or revoked token", http.StatusUnauthorized)
		return
	}

	user, err := h.store.ResolveUser(claims.Subject)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	// Determine auth source (local vs ldap) for the account page
	authSource := "local"
	mappings, _ := h.store.GetMappingsForUser(user.GUID)
	for _, m := range mappings {
		if m.Provider != "local" {
			authSource = "ldap"
			break
		}
	}

	jsonResp(w, map[string]interface{}{
		"guid":               user.GUID,
		"preferred_username": h.resolvePreferredUsername(user),
		"samaccountname":     user.SAMAccountName,
		"display_name":       user.DisplayName,
		"email":              user.Email,
		"department":         user.Department,
		"company":            user.Company,
		"job_title":          user.JobTitle,
		"roles":              claims.Roles,
		"permissions":        claims.Permissions,
		"groups":             claims.Groups,
		"auth_source":        authSource,
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
	// Don't mint an impersonation token for a target who could not log in
	// themselves — match the login/refresh gates (F44).
	if target.Disabled {
		jsonError(w, "target user is disabled", http.StatusForbidden)
		return
	}
	if revoked, _ := h.store.IsUserAccessRevoked(target.GUID); revoked {
		jsonError(w, "target user access is revoked", http.StatusForbidden)
		return
	}

	// Scope the impersonation token to an app so it carries an audience and the
	// target's per-app roles, instead of an aud-less token with global roles that
	// validates anywhere aud is not checked (L2). app_id is optional — absent means
	// the default app (whose authz falls back to the global roles, as before).
	app, err := h.resolveApp(req.AppID)
	if err != nil {
		jsonError(w, "unknown app", http.StatusBadRequest)
		return
	}
	roles, perms, _ := h.resolveTokenRoles(app, target)

	// Get admin GUID from the Authorization header (it's the master key, so we use "admin")
	adminActor := "admin"

	claims := auth.Claims{
		GUID:              target.GUID,
		Name:              target.DisplayName,
		Email:             target.Email,
		PreferredUsername: h.resolvePreferredUsername(target),
		Department:        target.Department,
		Company:           target.Company,
		JobTitle:          target.JobTitle,
		SAMAccountName:    target.SAMAccountName,
		Roles:             roles,
		Permissions:       perms,
		Impersonated:      true,
		ImpersonatedBy:    adminActor,
	}
	claims.Subject = target.GUID
	claims.Audience = []string{appAudience(app)}

	accessToken, err := h.jwt.IssueAccessToken(claims, h.cfg.ImpersonateTTL)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	ip := getClientIP(r)
	log.Printf("[impersonate] Admin impersonating user=%q guid=%s ip=%s", h.resolvePreferredUsername(target), target.GUID, ip)
	h.audit("impersonation", adminActor, ip, map[string]interface{}{
		"target_guid": target.GUID,
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

// validateAccessToken validates a JWT and checks the revocation blacklist.
func (h *Handler) validateAccessToken(tokenStr string) (*auth.Claims, error) {
	claims, err := h.jwt.ValidateToken(tokenStr)
	if err != nil {
		return nil, err
	}
	// App-management tokens (minted by /api/app/token, typ="app-mgmt") are NOT user
	// access tokens. They are accepted only by authenticateApp for the /api/app/*
	// surface; reject them at every user-resource boundary so a management
	// credential cannot read user profiles via userinfo/introspection or act as a
	// user — including the case where an app_id collides with a user GUID (H7).
	if claims.Typ == "app-mgmt" {
		return nil, fmt.Errorf("not a user access token")
	}
	// Reject non-access token classes presented at a user-resource boundary.
	// Every token here is signed by the same RSA key, so the signature alone does
	// not prove the token is an access token; we must check its class explicitly.
	//   - refresh tokens carry a family_id and must only be redeemed at /refresh
	//   - OIDC id_tokens carry typ="ID" and are end-client identity assertions,
	//     never bearer credentials for resource access (RFC 8725 / OAuth BCP)
	// Direct-login access tokens have neither marker; service tokens carry
	// typ="Bearer". Both are accepted. (Closes the refresh/id-as-access confusion.)
	if claims.FamilyID != "" {
		return nil, fmt.Errorf("refresh token is not an access token")
	}
	if claims.Typ == "ID" {
		return nil, fmt.Errorf("id_token is not an access token")
	}
	// Check user-level revocation (admin revoked all sessions)
	if revoked, _ := h.store.IsUserAccessRevoked(claims.Subject); revoked {
		return nil, fmt.Errorf("access revoked")
	}
	// Check individual token revocation
	if claims.ID != "" {
		if revoked, _ := h.store.IsAccessTokenRevoked(claims.ID); revoked {
			return nil, fmt.Errorf("token revoked")
		}
	}
	return claims, nil
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

	claims, err := h.validateAccessToken(tokenStr)
	if err != nil {
		jsonError(w, "invalid or revoked token", http.StatusUnauthorized)
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

	// Validate password against policy
	if err := auth.ValidatePassword(req.NewPassword, h.passwordPolicy()); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.store.ResolveUser(claims.Subject)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	// This endpoint ROTATES an existing SimpleAuth-local password. It must never
	// CREATE one. The old guard (`PasswordHash != "" && !ForcePasswordChange`)
	// skipped the entire proof-of-possession block whenever the hash was empty —
	// which is exactly the state of every directory user, whose credential lives
	// in AD — so a bearer token minted for ANY audience could POST
	// {"new_password":...} with no current_password and plant a permanent local
	// bcrypt hash on an AD-backed record (SA-7). See isDirectoryBacked for why
	// that hash then outlives the AD account.
	//
	// Both refusals are 403, never "supply current_password": a directory user has
	// no local password to prove, so demanding one would be an unsatisfiable 400
	// loop rather than an honest "wrong place — change it in AD".
	if user.PasswordHash == "" {
		ip := getClientIP(r)
		if h.isDirectoryBacked(user) {
			// Log the GUID, not the resolved username: the GUID is server-generated
			// and unspoofable, whereas a directory-supplied username in a security
			// log is both injectable and less useful for correlation.
			log.Printf("[password] REFUSED directory-backed guid=%s ip=%s (attempt to plant a local password)",
				user.GUID, ip)
			h.audit("password_change_denied", user.GUID, ip, map[string]interface{}{
				"reason": "directory_backed",
			})
			jsonError(w, "password is managed by the directory — change it in Active Directory", http.StatusForbidden)
			return
		}
		// Not directory-backed, but no local credential exists either: an
		// admin-created account with no password. There is no first-time-set flow
		// to protect here — authenticateUser requires a non-empty hash in every
		// local branch, so this user can never log in and can never hold a token of
		// their own. Setting the initial password is an administrative act
		// (PUT /api/admin/users/{guid}/password).
		log.Printf("[password] REFUSED no local password guid=%s ip=%s", user.GUID, ip)
		h.audit("password_change_denied", user.GUID, ip, map[string]interface{}{
			"reason": "no_local_password",
		})
		jsonError(w, "no local password is set for this account — ask an administrator to set one", http.StatusForbidden)
		return
	}

	// Proof of possession. ForcePasswordChange is the admin temp-password flow: the
	// admin already wrote a REAL hash via PUT /api/admin/users/{guid}/password
	// (admin.go writes user.PasswordHash immediately before setting the flag), the
	// login response carried force_password_change:true, and the user now changes
	// it without re-typing the temp password. That flow always runs with a
	// NON-EMPTY hash, which is precisely why the empty-hash gate above can sit
	// ahead of it.
	if !user.ForcePasswordChange {
		if req.CurrentPassword == "" {
			jsonError(w, "current_password required", http.StatusBadRequest)
			return
		}
		if !auth.CheckPassword(user.PasswordHash, req.CurrentPassword) {
			jsonError(w, "current password is incorrect", http.StatusForbidden)
			return
		}
	}

	// Check password history
	if h.getPasswordHistoryCount() > 0 && auth.CheckPasswordHistory(req.NewPassword, user.PasswordHistory) {
		jsonError(w, fmt.Sprintf("password was recently used — choose a different password (last %d passwords are remembered)", h.getPasswordHistoryCount()), http.StatusBadRequest)
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		jsonError(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	// Update password history
	if h.getPasswordHistoryCount() > 0 && user.PasswordHash != "" {
		user.PasswordHistory = auth.AddToPasswordHistory(user.PasswordHistory, user.PasswordHash, h.getPasswordHistoryCount())
	}

	user.PasswordHash = hash
	user.ForcePasswordChange = false // clear the flag on successful password change
	if err := h.store.UpdateUser(user); err != nil {
		jsonError(w, "failed to update password", http.StatusInternalServerError)
		return
	}

	ip := getClientIP(r)
	log.Printf("[password] Changed user=%q guid=%s ip=%s", h.resolvePreferredUsername(user), user.GUID, ip)
	h.audit("password_changed", user.GUID, ip, nil)
	jsonResp(w, map[string]string{"status": "password updated"}, http.StatusOK)
}

// handleNegotiate handles Kerberos/SPNEGO authentication.
// GET /api/auth/negotiate
// Browser sends Authorization: Negotiate <base64-token>
func (h *Handler) handleNegotiate(w http.ResponseWriter, r *http.Request) {
	if !h.loginLimiter.allow(getClientIP(r)) {
		jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	keytabPath := h.getKeytabPath()
	if keytabPath == "" {
		jsonError(w, "Kerberos not configured", http.StatusNotImplemented)
		return
	}

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
	kt, err := keytab.Load(keytabPath)
	if err != nil {
		jsonError(w, "failed to load keytab", http.StatusInternalServerError)
		return
	}

	// Parse and FULLY VERIFY the AP-REQ — authenticator, clock skew, and replay
	// cache — not just decrypt the ticket (C1).
	apReq, err := parseAPReqToken(tokenBytes)
	if err != nil {
		jsonError(w, "invalid SPNEGO token", http.StatusUnauthorized)
		return
	}
	username, cname, err := h.verifyAPReq(apReq, kt)
	if err != nil {
		log.Printf("[negotiate] AP-REQ verification failed ip=%s err=%v", getClientIP(r), err)
		jsonError(w, "Kerberos authentication failed", http.StatusUnauthorized)
		return
	}

	ip := getClientIP(r)

	// Look up user by kerberos identity mapping
	userGUID, err := h.store.ResolveMapping("kerberos", cname)
	if err != nil {
		// Try without realm
		userGUID, err = h.store.ResolveMapping("kerberos", username)
	}
	if err != nil {
		// Auto-provision: look for a directory user with matching display name/email.
		users, _ := h.store.ListUsers()
		if guid := matchAutoProvisionUser(users, username); guid != "" {
			userGUID = guid
			// Create identity mapping for next time
			h.store.SetIdentityMapping("kerberos", cname, userGUID)
		}
		if userGUID == "" {
			h.audit("negotiate_failed", "", ip, map[string]interface{}{
				"principal": cname, "reason": "no matching user",
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

	// Resolve the app (v2) — optional client_id query, else default app.
	app, err := h.resolveApp(r.URL.Query().Get("client_id"))
	if err != nil {
		jsonError(w, "unknown app", http.StatusBadRequest)
		return
	}

	// Issue tokens (per-app roles + require_assignment, v2 M3)
	roles, perms, denied := h.resolveTokenRoles(app, user)
	if denied {
		jsonError(w, "access denied: not assigned to this app", http.StatusForbidden)
		return
	}
	accessToken, refreshToken, expiresIn, err := h.issueTokenPair(user, roles, perms, nil, app)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}

	h.auditLogin(user, ip, map[string]interface{}{
		"flow": "kerberos", "principal": cname,
	})

	jsonResp(w, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    expiresIn,
		"token_type":    "Bearer",
	}, http.StatusOK)
}

// handleNegotiateTest serves a Kerberos/SPNEGO test page.
// GET /test-negotiate — browser triggers SPNEGO, falls back to login form.
func (h *Handler) handleNegotiateTest(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")

	// No auth header — send Negotiate challenge + page with fallback form
	if authHeader == "" || !strings.HasPrefix(authHeader, "Negotiate ") {
		keytabPath := h.getKeytabPath()
		if keytabPath != "" {
			w.Header().Set("WWW-Authenticate", "Negotiate")
		}
		h.renderNegotiateTest(w, negotiateTestWaitTmpl, http.StatusUnauthorized, negotiateTestData{})
		return
	}

	// Decode SPNEGO token
	tokenB64 := authHeader[10:]
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		http.Error(w, "invalid Negotiate token encoding", http.StatusBadRequest)
		return
	}

	// Check if this is NTLM instead of Kerberos
	if isNTLMToken(tokenBytes) {
		// NTLM fallback: show form with explanation
		h.renderNegotiateTest(w, negotiateTestNTLMFallbackTmpl, http.StatusOK, negotiateTestData{})
		return
	}

	keytabPath := h.getKeytabPath()
	if keytabPath == "" {
		http.Error(w, "Kerberos not configured", http.StatusNotImplemented)
		return
	}

	kt, err := keytab.Load(keytabPath)
	if err != nil {
		http.Error(w, "failed to load keytab", http.StatusInternalServerError)
		return
	}

	// Log raw token info for debugging
	log.Printf("[spnego] Token length: %d bytes, first bytes: %x", len(tokenBytes), tokenBytes[:min(16, len(tokenBytes))])

	var spnegoToken spnego.SPNEGOToken
	if err := spnegoToken.Unmarshal(tokenBytes); err != nil {
		log.Printf("[spnego] SPNEGO unmarshal failed: %v", err)
		// Maybe it's a raw Kerberos AP-REQ (not wrapped in SPNEGO)
		var apReq krbmsg.APReq
		if err2 := apReq.Unmarshal(tokenBytes); err2 == nil {
			log.Printf("[spnego] Token is raw AP-REQ (not SPNEGO-wrapped)")
			// completeKerberosAuth performs full verification (C1).
			h.completeKerberosAuth(w, r, &apReq, kt)
			return
		}
		// Can't parse as SPNEGO or raw AP-REQ — fall back to login form
		h.renderNegotiateTest(w, negotiateTestKrbFailedTmpl, http.StatusOK, negotiateTestData{Error: "Invalid SPNEGO token: " + err.Error()})
		return
	}

	// Log SPNEGO OIDs for debugging
	for i, oid := range spnegoToken.NegTokenInit.MechTypes {
		log.Printf("[spnego] MechType[%d]: %s", i, oid.String())
	}

	if len(spnegoToken.NegTokenInit.MechTokenBytes) == 0 {
		h.renderNegotiateTest(w, negotiateTestKrbFailedTmpl, http.StatusOK, negotiateTestData{Error: "No mechanism token in SPNEGO negotiation."})
		return
	}

	mechBytes := spnegoToken.NegTokenInit.MechTokenBytes
	log.Printf("[spnego] MechToken length: %d, first bytes: %x", len(mechBytes), mechBytes[:min(16, len(mechBytes))])

	if isNTLMToken(mechBytes) {
		log.Printf("[spnego] NTLM token detected inside SPNEGO")
		h.renderNegotiateTest(w, negotiateTestNTLMFallbackTmpl, http.StatusOK, negotiateTestData{})
		return
	}

	// Strip GSS-API OID wrapper if present (Windows wraps AP-REQ in GSS-API header)
	mechBytes = stripGSSAPIWrapper(mechBytes)

	var apReq krbmsg.APReq
	if err := apReq.Unmarshal(mechBytes); err != nil {
		log.Printf("[spnego] AP-REQ unmarshal failed: %v, mechToken first bytes: %x", err, mechBytes[:min(32, len(mechBytes))])
		// AP-REQ parse failed — fall back to login form
		h.renderNegotiateTest(w, negotiateTestKrbFailedTmpl, http.StatusOK, negotiateTestData{Error: "Kerberos ticket could not be parsed: " + err.Error()})
		return
	}

	// Full AP-REQ verification (authenticator + clock skew + replay cache; C1).
	h.completeKerberosAuth(w, r, &apReq, kt)
}

// completeKerberosAuth handles the success path after the AP-REQ is fully
// verified (authenticator + clock skew + replay cache; C1).
func (h *Handler) completeKerberosAuth(w http.ResponseWriter, r *http.Request, apReq *krbmsg.APReq, kt *keytab.Keytab) {
	username, cname, err := h.verifyAPReq(apReq, kt)
	if err != nil {
		h.renderNegotiateTest(w, negotiateTestKrbFailedTmpl, http.StatusOK, negotiateTestData{Error: "Kerberos verification failed: " + err.Error()})
		return
	}

	userInfo := map[string]string{
		"auth_method": "Kerberos/SPNEGO",
		"principal":   cname,
		"realm":       h.getKRB5Realm(),
		"username":    username,
	}

	h.enrichUserInfoFromLDAP(userInfo, username)
	h.renderNegotiateSuccess(w, userInfo)
}

// handleSSOLogin handles redirect-based SPNEGO authentication.
// GET /login/sso?redirect_uri=... — browser triggers SPNEGO, on success redirects with tokens.
func (h *Handler) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	if !h.loginLimiter.allow(getClientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	redirectURI := r.URL.Query().Get("redirect_uri")

	// Resolve the app (v2) and validate redirect_uri against ITS allowlist — per-app
	// redirect_uris are authoritative (falling back to the global list). Validating
	// only against the global list let an app-scoped token be delivered to a URI the
	// app itself never authorized (L1).
	app, err := h.resolveApp(r.URL.Query().Get("client_id"))
	if err != nil {
		http.Error(w, "unknown app", http.StatusBadRequest)
		return
	}
	if redirectURI != "" && !h.appAllowsRedirect(app, redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	// Mark SSO as attempted so auto-SSO doesn't loop on failure
	http.SetCookie(w, &http.Cookie{
		Name:     "__sso_attempted",
		Value:    "1",
		Path:     "/",
		MaxAge:   300, // 5 minutes — prevents loop, but allows retry later
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	authHeader := r.Header.Get("Authorization")

	ip := getClientIP(r)
	log.Printf("[sso] SSO login attempt ip=%s redirect_uri=%q", ip, redirectURI)

	// No auth header — send Negotiate challenge or fail
	if authHeader == "" || !strings.HasPrefix(authHeader, "Negotiate ") {
		keytabPath := h.getKeytabPath()
		if keytabPath == "" {
			log.Printf("[sso] Kerberos not configured ip=%s", ip)
			h.redirectToLoginError(w, r, redirectURI, "Kerberos not configured")
			return
		}

		// If we already sent the challenge (sso_attempt=1) and the browser
		// still didn't respond with a Negotiate token, SSO has failed.
		if r.URL.Query().Get("sso_attempt") == "1" {
			log.Printf("[sso] Browser did not provide Kerberos credentials ip=%s", ip)
			h.redirectToLoginError(w, r, redirectURI, "SSO authentication failed — your browser did not provide Kerberos credentials")
			return
		}

		log.Printf("[sso] Sending Negotiate challenge ip=%s", ip)
		// First visit — send the 401 challenge
		retryURL := h.url("/login/sso") + "?sso_attempt=1"
		if redirectURI != "" {
			retryURL += "&redirect_uri=" + url.QueryEscape(redirectURI)
		}
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		// Redirect to self with sso_attempt=1 so we can detect failure
		// retryURL is built server-side from h.url() + url.QueryEscape'd values —
		// it is never echoed from the request. Escaped here for defence in depth.
		// NOTE: html/template treats <meta content> as contentTypeUnsafe (it
		// attribute-escapes but does NOT URL-filter), so a template rewrite would
		// not add a guarantee here; the safety rests on the server-side
		// construction above. Left as an explicit EscapeString rather than moved
		// into a template, deliberately.
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=%s"></head><body><p>Authenticating...</p></body></html>`, html.EscapeString(retryURL))
		return
	}

	// Decode SPNEGO token
	tokenB64 := authHeader[10:]
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		h.redirectToLoginError(w, r, redirectURI, "Invalid Negotiate token")
		return
	}

	if isNTLMToken(tokenBytes) {
		log.Printf("[sso] NTLM token rejected (Kerberos required) ip=%s", ip)
		h.redirectToLoginError(w, r, redirectURI, "NTLM is not supported, Kerberos required")
		return
	}

	keytabPath := h.getKeytabPath()
	if keytabPath == "" {
		h.redirectToLoginError(w, r, redirectURI, "Kerberos not configured")
		return
	}

	kt, err := keytab.Load(keytabPath)
	if err != nil {
		h.redirectToLoginError(w, r, redirectURI, "Kerberos configuration error")
		return
	}

	// Extract username from SPNEGO/Kerberos token
	username, err := h.extractKerberosUsername(tokenBytes, kt)
	if err != nil {
		log.Printf("[sso] Kerberos auth failed: %v", err)
		h.redirectToLoginError(w, r, redirectURI, "Kerberos authentication failed")
		return
	}

	// Resolve or create user via LDAP lookup + JIT provisioning
	userGUID, ldapGroups, err := h.resolveKerberosUser(username)
	if err != nil {
		log.Printf("[sso] User resolution failed for %q: %v", username, err)
		h.redirectToLoginError(w, r, redirectURI, "User not found in directory")
		return
	}

	user, err := h.store.ResolveUser(userGUID)
	if err != nil {
		h.redirectToLoginError(w, r, redirectURI, "User not found")
		return
	}
	if user.Disabled {
		h.redirectToLoginError(w, r, redirectURI, "Account disabled")
		return
	}

	// app was resolved + redirect validated at the top of the handler (L1).
	roles, perms, denied := h.resolveTokenRoles(app, user)
	if denied {
		h.redirectToLoginError(w, r, redirectURI, "Access denied: not assigned to this app")
		return
	}
	accessToken, refreshToken, expiresIn, err := h.issueTokenPair(user, roles, perms, ldapGroups, app)
	if err != nil {
		h.redirectToLoginError(w, r, redirectURI, "Token generation failed")
		return
	}

	log.Printf("[sso] Login success user=%q guid=%s name=%q ip=%s", username, user.GUID, user.DisplayName, ip)
	h.auditLogin(user, ip, map[string]interface{}{"flow": "sso", "method": "kerberos"})

	// Clear SSO-attempted cookie on success so future auto-SSO works
	http.SetCookie(w, &http.Cookie{Name: "__sso_attempted", Value: "", Path: "/", MaxAge: -1})

	// Seed shared SSO session cookie (no-op if feature disabled)
	h.issueSessionCookie(w, r, user.GUID)

	// OIDC flow: issue auth code and redirect with ?code=X&state=Z
	if r.URL.Query().Get("oidc") == "1" {
		state := r.URL.Query().Get("state")
		nonce := r.URL.Query().Get("nonce")
		codeChallenge := r.URL.Query().Get("code_challenge")
		codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

		codeBytes := make([]byte, 32)
		if _, err := rand.Read(codeBytes); err != nil {
			h.redirectToLoginError(w, r, redirectURI, "Internal error")
			return
		}
		code := hex.EncodeToString(codeBytes)

		ac := &store.OIDCAuthCode{
			Code:                code,
			UserGUID:            user.GUID,
			AppID:               app.AppID,
			RedirectURI:         redirectURI,
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			ExpiresAt:           time.Now().Add(10 * time.Minute),
			CreatedAt:           time.Now(),
		}
		if err := h.store.SaveOIDCAuthCode(ac); err != nil {
			h.redirectToLoginError(w, r, redirectURI, "Internal error")
			return
		}

		target := redirectURI
		if target == "" {
			target = h.getDefaultRedirectURI()
		}
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target += sep + "code=" + url.QueryEscape(code)
		if state != "" {
			target += "&state=" + url.QueryEscape(state)
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	// Direct flow: redirect with tokens in fragment
	fragment := fmt.Sprintf("access_token=%s&refresh_token=%s&expires_in=%d&token_type=Bearer",
		url.QueryEscape(accessToken),
		url.QueryEscape(refreshToken),
		expiresIn,
	)

	if redirectURI != "" {
		http.Redirect(w, r, redirectURI+"#"+fragment, http.StatusFound)
		return
	}
	http.Redirect(w, r, h.url("/account")+"#"+fragment, http.StatusFound)
}

// extractKerberosUsername validates a SPNEGO/Kerberos token (full AP-REQ
// verification — authenticator, clock skew, replay cache; C1) and returns the
// realm-stripped username.
func (h *Handler) extractKerberosUsername(tokenBytes []byte, kt *keytab.Keytab) (string, error) {
	apReq, err := parseAPReqToken(tokenBytes)
	if err != nil {
		return "", err
	}
	username, _, err := h.verifyAPReq(apReq, kt)
	if err != nil {
		return "", err
	}
	return username, nil
}

// resolveKerberosUser looks up a Kerberos-authenticated user by the Kerberos
// cname (stripped of realm), creates via JIT provisioning if needed, and
// returns the user GUID and LDAP groups.
//
// The Kerberos cname is NOT guaranteed to equal sAMAccountName — in many AD
// deployments it is the userPrincipalName (UPN) which can look like an email
// (e.g. `itdirector@shit.org`). We use the cname only for LDAP lookup and
// store the authoritative sAMAccountName (from the LDAP result) on the user
// record and as the primary identity mapping.
func (h *Handler) resolveKerberosUser(username string) (string, []string, error) {
	ldapCfg, ldapErr := h.getLDAPConfigDecrypted()
	if ldapErr != nil {
		return "", nil, fmt.Errorf("ldap not configured")
	}
	cfg := ldapConfigFromStore(ldapCfg)

	// Check existing identity mappings (ldap first, then local)
	for _, provider := range []string{"ldap", "local"} {
		if guid, err := h.store.ResolveMapping(provider, username); err == nil {
			user, err := h.store.ResolveUser(guid)
			if err == nil {
				var groups []string
				result, err := auth.LDAPSearchUser(cfg, "sAMAccountName", username)
				if err == nil {
					groups = result.Groups
					h.syncUserFromLDAP(user, result) // self-heals SAMAccountName + mappings
				}
				return user.GUID, groups, nil
			}
		}
	}

	// JIT provisioning: search LDAP by sAMAccountName (unique per domain)
	result, err := auth.LDAPSearchUser(cfg, "sAMAccountName", username)
	if err != nil {
		return "", nil, fmt.Errorf("user %q not found in LDAP: %v", username, err)
	}

	// Double-check: ensure no existing user with the authoritative sAMAccountName
	// before creating. If the cname differs from sAMAccountName (common with UPN-
	// based principals), this prevents duplicate accounts from being provisioned.
	samName := result.Username
	if samName == "" {
		samName = username
	}
	if existingGUID, err := h.store.ResolveMapping("ldap", samName); err == nil {
		log.Printf("[sso] JIT: user %q already mapped to %s via ldap/sAMAccountName, reusing", samName, existingGUID)
		if samName != username {
			h.store.SetIdentityMapping("ldap", username, existingGUID) // remember the cname form too
		}
		return existingGUID, result.Groups, nil
	}
	if existingGUID, err := h.store.ResolveMapping("ldap", username); err == nil {
		log.Printf("[sso] JIT: user %q already mapped to %s via ldap/cname, reusing", username, existingGUID)
		return existingGUID, result.Groups, nil
	}

	newUser := &store.User{
		DisplayName:    result.DisplayName,
		Email:          result.Email,
		Department:     result.Department,
		Company:        result.Company,
		JobTitle:       result.JobTitle,
		SAMAccountName: result.Username,
	}
	h.store.CreateUser(newUser)
	// Map by the authoritative sAMAccountName (primary lookup key).
	h.store.SetIdentityMapping("ldap", samName, newUser.GUID)
	h.store.SetIdentityMapping("local", samName, newUser.GUID)
	// Also map by the cname if it differs, so Kerberos re-logins find the user.
	if username != samName {
		h.store.SetIdentityMapping("ldap", username, newUser.GUID)
		h.store.SetIdentityMapping("local", username, newUser.GUID)
	}
	log.Printf("[sso] JIT provisioned user guid=%s cname=%q sam=%q from LDAP", newUser.GUID, username, samName)
	return newUser.GUID, result.Groups, nil
}

// handleNegotiateTestForm handles the fallback login form (POST).
func (h *Handler) handleNegotiateTestForm(w http.ResponseWriter, r *http.Request) {
	if !h.loginLimiter.allow(getClientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		h.renderNegotiateTest(w, negotiateTestFormErrorTmpl, http.StatusOK, negotiateTestData{})
		return
	}

	// Try LDAP authentication
	ldapCfg, ldapErr := h.getLDAPConfigDecrypted()
	if ldapErr != nil {
		log.Printf("[test-negotiate] No LDAP configured")
		h.renderNegotiateTest(w, negotiateTestLoginFailedTmpl, http.StatusOK, negotiateTestData{Error: "LDAP not configured"})
		return
	}

	cfg := ldapConfigFromStore(ldapCfg)
	log.Printf("[test-negotiate] Form login attempt for user=%q (URL=%s, BaseDN=%s)", username, ldapCfg.URL, ldapCfg.BaseDN)
	authResult, authErr := auth.LDAPAuthenticate(cfg, username, password)

	if authResult == nil {
		errMsg := "LDAP authentication failed"
		if authErr != nil {
			errMsg = authErr.Error()
		}
		log.Printf("[test-negotiate] Auth failed for user=%q: %s", username, errMsg)
		h.renderNegotiateTest(w, negotiateTestLoginFailedTmpl, http.StatusOK, negotiateTestData{Error: errMsg})
		return
	}

	userInfo := map[string]string{
		"auth_method": "LDAP Bind",
		"principal":   username,
		"username":    authResult.Username,
	}
	if ldapCfg.Domain != "" {
		userInfo["domain"] = ldapCfg.Domain
	}
	if authResult.DisplayName != "" {
		userInfo["display_name"] = authResult.DisplayName
	}
	if authResult.Email != "" {
		userInfo["email"] = authResult.Email
	}
	if authResult.Department != "" {
		userInfo["department"] = authResult.Department
	}
	if authResult.Company != "" {
		userInfo["company"] = authResult.Company
	}
	if authResult.JobTitle != "" {
		userInfo["job_title"] = authResult.JobTitle
	}
	if len(authResult.Groups) > 0 {
		userInfo["groups"] = strings.Join(authResult.Groups, ", ")
	}

	h.renderNegotiateSuccess(w, userInfo)
}

// parseAPReqToken extracts a Kerberos AP-REQ from a raw token that may be a
// SPNEGO NegTokenInit, a GSS-API-wrapped AP-REQ, or a bare AP-REQ.
func parseAPReqToken(tokenBytes []byte) (*krbmsg.APReq, error) {
	var spnegoToken spnego.SPNEGOToken
	if err := spnegoToken.Unmarshal(tokenBytes); err == nil && len(spnegoToken.NegTokenInit.MechTokenBytes) > 0 {
		mechBytes := spnegoToken.NegTokenInit.MechTokenBytes
		if isNTLMToken(mechBytes) {
			return nil, fmt.Errorf("NTLM is not supported, Kerberos required")
		}
		mechBytes = stripGSSAPIWrapper(mechBytes)
		var apReq krbmsg.APReq
		if err := apReq.Unmarshal(mechBytes); err != nil {
			return nil, fmt.Errorf("AP-REQ parse failed: %w", err)
		}
		return &apReq, nil
	}
	// Not SPNEGO-wrapped — try a bare or GSS-wrapped AP-REQ.
	var apReq krbmsg.APReq
	if err := apReq.Unmarshal(stripGSSAPIWrapper(tokenBytes)); err != nil {
		return nil, fmt.Errorf("invalid token: not SPNEGO or AP-REQ")
	}
	return &apReq, nil
}

// kerberosSettings builds gokrb5 service settings used to verify AP-REQs:
// enforces clock skew, sizes the replay cache, and disables PAC decoding (group
// membership is sourced from LDAP, not the PAC).
func kerberosSettings(kt *keytab.Keytab) *service.Settings {
	return service.NewSettings(kt,
		service.MaxClockSkew(kerberosMaxClockSkew),
		service.DecodePAC(false),
	)
}

// verifyAPReq fully validates a Kerberos AP-REQ: it decrypts the ticket AND
// verifies the authenticator (proving the presenter holds the session key),
// enforces clock skew, and rejects replays via the replay cache. Returns the
// realm-stripped username and the full client cname.
//
// This replaces the previous decrypt-only path (DecryptEncPart with no
// authenticator/replay check), which accepted any captured AP-REQ for
// unlimited replay (C1).
func (h *Handler) verifyAPReq(apReq *krbmsg.APReq, kt *keytab.Keytab) (username, cname string, err error) {
	// AD increments the keytab KVNO on service-account password changes; the
	// in-memory keytab generated from the bind password may carry a placeholder
	// KVNO. Align it so the correct key is selectable. This does not weaken
	// verification — the authenticator check below is what proves freshness and
	// possession of the session key; the service key only decrypts the ticket.
	patchKeytabKVNO(kt, apReq.Ticket.EncPart.KVNO)

	ok, creds, err := service.VerifyAPREQ(apReq, kerberosSettings(kt))
	if err != nil {
		return "", "", fmt.Errorf("AP-REQ verification failed: %w", err)
	}
	if !ok {
		return "", "", fmt.Errorf("AP-REQ verification failed")
	}
	cname = creds.CName().PrincipalNameString()
	// Bind the verified principal to the configured realm. Without this, in an AD
	// forest / realm-trust topology a foreign-realm "jsmith@OTHER.REALM" verifies
	// and then maps to the home-realm short name "jsmith", minting a token as that
	// local user (cross-realm identity hijack, F-kerberos-realm).
	if realm := h.getKRB5Realm(); realm != "" && !strings.EqualFold(creds.Realm(), realm) {
		return "", "", fmt.Errorf("client realm %q is not the configured realm %q", creds.Realm(), realm)
	}
	username = cname
	if idx := strings.Index(cname, "@"); idx > 0 {
		username = cname[:idx]
	}
	return username, cname, nil
}

// isNTLMToken checks if bytes are an NTLM message (raw or SPNEGO-wrapped).
func isNTLMToken(b []byte) bool {
	return len(b) > 7 && string(b[:7]) == "NTLMSSP"
}

// stripGSSAPIWrapper removes the GSS-API OID header wrapping a Kerberos AP-REQ.
// Windows sends mechTokens as: 60 <len> 06 09 <krb5-oid> 00 <ap-req...>
// The AP-REQ itself starts with tag 0x6e (ASN.1 Application 14).
func stripGSSAPIWrapper(b []byte) []byte {
	// Look for AP-REQ tag (0x6e) in the first 20 bytes
	for i := 0; i < len(b) && i < 20; i++ {
		if b[i] == 0x6e {
			return b[i:]
		}
	}
	return b
}

// patchKeytabKVNO sets all keytab entries to match the ticket's kvno,
// so decryption works regardless of kvno mismatch between keytab and AD.
func patchKeytabKVNO(kt *keytab.Keytab, ticketKVNO int) {
	for i := range kt.Entries {
		kt.Entries[i].KVNO = uint32(ticketKVNO)
		kt.Entries[i].KVNO8 = uint8(ticketKVNO)
	}
}

// enrichUserInfoFromLDAP looks up a username in the LDAP config.
func (h *Handler) enrichUserInfoFromLDAP(userInfo map[string]string, username string) {
	ldapCfg, err := h.getLDAPConfigDecrypted()
	if err != nil {
		return
	}
	cfg := ldapConfigFromStore(ldapCfg)
	result, err := auth.LDAPSearchUser(cfg, "sAMAccountName", username)
	if err != nil {
		return
	}
	if result.DisplayName != "" {
		userInfo["display_name"] = result.DisplayName
	}
	if result.Email != "" {
		userInfo["email"] = result.Email
	}
	if result.Department != "" {
		userInfo["department"] = result.Department
	}
	if result.Company != "" {
		userInfo["company"] = result.Company
	}
	if result.JobTitle != "" {
		userInfo["job_title"] = result.JobTitle
	}
	if len(result.Groups) > 0 {
		userInfo["groups"] = strings.Join(result.Groups, ", ")
	}
}

// renderNegotiateSuccess renders the success page with user info.
func (h *Handler) renderNegotiateSuccess(w http.ResponseWriter, userInfo map[string]string) {
	h.renderNegotiateTest(w, negotiateTestSuccessTmpl, http.StatusOK, negotiateTestData{
		Method:       userInfo["auth_method"],
		Principal:    mapGet(userInfo, "principal", "-"),
		Realm:        mapGet(userInfo, "realm", "-"),
		Username:     mapGet(userInfo, "username", "-"),
		ProviderName: mapGet(userInfo, "provider_name", "none"),
		ProviderID:   mapGet(userInfo, "provider_id", "-"),
		DisplayName:  mapGet(userInfo, "display_name", "-"),
		Email:        mapGet(userInfo, "email", "-"),
		Department:   mapGet(userInfo, "department", "-"),
		Company:      mapGet(userInfo, "company", "-"),
		JobTitle:     mapGet(userInfo, "job_title", "-"),
		Groups:       mapGet(userInfo, "groups", "-"),
	})
}

func mapGet(m map[string]string, key, fallback string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return fallback
}

const negotiateTestCSS = `:root{--bg:#FAFAF8;--card:#FFF;--text:#333F48;--muted:#A59F8A;--border:#D6D1CA;--burgundy:#8B153D;--burgundy-hover:#6E1030;--error-bg:#F8E4E4;--error-text:#8B153D;--green:#2D7A3A;--green-bg:#E8F5E9;--gold-light:#F8E08E;--gold-dark:#8F6A2A}
@media(prefers-color-scheme:dark){:root{--bg:#1A1E22;--card:#242A30;--text:#E8E4DE;--muted:#6B6760;--border:#3A424A;--burgundy:#A02050;--burgundy-hover:#B82D60;--error-bg:rgba(139,21,61,0.2);--error-text:#D4A0A0;--green:#4CAF50;--green-bg:rgba(45,122,58,0.15)}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{width:480px;padding:40px;background:var(--card);border:1px solid var(--border);border-radius:12px}
.card h1{font-size:1.5rem;margin-bottom:8px;text-align:center}
.card p{color:var(--muted);margin-bottom:16px;text-align:center;font-size:0.9rem}
.gold-bar{height:3px;background:linear-gradient(90deg,var(--gold-light),var(--gold-dark));border-radius:999px;margin-bottom:24px}
.error{background:var(--error-bg);color:var(--error-text);padding:12px 16px;border-radius:8px;font-size:0.85rem;margin-bottom:16px}
.success{background:var(--green-bg);color:var(--green);padding:16px;border-radius:8px;text-align:center;margin-bottom:24px;font-weight:600;font-size:1.1rem}
.spinner{display:inline-block;width:24px;height:24px;border:3px solid var(--border);border-top-color:var(--burgundy);border-radius:50%;animation:spin 0.8s linear infinite;margin-bottom:16px}
@keyframes spin{to{transform:rotate(360deg)}}
label{display:block;font-size:0.875rem;font-weight:600;margin-bottom:6px}
input[type=text],input[type=password]{width:100%;padding:10px 14px;background:var(--card);border:1px solid var(--border);border-radius:8px;font-size:0.875rem;font-family:inherit;color:var(--text);margin-bottom:14px}
input:focus{outline:none;border-color:var(--burgundy);box-shadow:0 0 0 3px rgba(139,21,61,0.15)}
button{width:100%;padding:10px;background:var(--burgundy);color:#fff;border:none;border-radius:8px;font-size:0.875rem;font-weight:600;cursor:pointer;font-family:inherit}
button:hover{background:var(--burgundy-hover)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border)}
th{font-size:0.8rem;text-transform:uppercase;color:var(--muted);width:130px}
td{font-size:0.9rem}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600}
.badge-krb{background:var(--green-bg);color:var(--green)}
.badge-ldap{background:rgba(139,21,61,0.1);color:var(--burgundy)}
#fallback{display:none}
`

// negotiateTestData drives the Kerberos/LDAP diagnostic pages.
//
// These pages are rendered with html/template rather than fmt.Fprintf because
// every value below originates outside SimpleAuth: Error derives from parsing the
// attacker-supplied `Authorization: Negotiate` header, and the success-page fields
// are AD attributes (displayName, mail, department, memberOf) that a directory
// principal may control. Three of the old call sites passed err.Error() with NO
// escaping at all, and the success page reflected every AD attribute raw (M39).
//
// html/template also escapes per CONTEXT, which matters here: BasePath lands in a
// form action (URL context) while the rest land in HTML text.
type negotiateTestData struct {
	BasePath string
	Error    string

	// Success page.
	Method       string
	Principal    string
	Realm        string
	Username     string
	ProviderName string
	ProviderID   string
	DisplayName  string
	Email        string
	Department   string
	Company      string
	JobTitle     string
	Groups       string
}

var (
	negotiateTestWaitTmpl         = template.Must(template.New("negoWait").Parse(negotiateTestWaitHTML))
	negotiateTestNTLMFallbackTmpl = template.Must(template.New("negoNTLM").Parse(negotiateTestNTLMFallbackHTML))
	negotiateTestFormErrorTmpl    = template.Must(template.New("negoFormErr").Parse(negotiateTestFormErrorHTML))
	negotiateTestKrbFailedTmpl    = template.Must(template.New("negoKrbFail").Parse(negotiateTestKrbFailedHTML))
	negotiateTestLoginFailedTmpl  = template.Must(template.New("negoLoginFail").Parse(negotiateTestLoginFailedHTML))
	negotiateTestSuccessTmpl      = template.Must(template.New("negoSuccess").Parse(negotiateTestSuccessHTML))
)

// renderNegotiateTest executes a diagnostic template, always supplying BasePath.
func (h *Handler) renderNegotiateTest(w http.ResponseWriter, t *template.Template, status int, d negotiateTestData) {
	d.BasePath = h.cfg.BasePath
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.Execute(w, d); err != nil {
		log.Printf("[negotiate-test] render: %v", err)
	}
}

const negotiateTestWaitHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Authentication Test — SimpleAuth</title>
<style>` + negotiateTestCSS + `</style></head><body>
<div class="card">
<div id="spnego" style="text-align:center">
<div class="spinner"></div>
<h1>Kerberos/SPNEGO</h1>
<p>Attempting automatic sign-in...</p>
</div>
<div id="fallback">
<h1>Sign In</h1>
<p>Kerberos not available — enter your AD credentials</p>
<div class="gold-bar"></div>
<form method="POST" action="{{.BasePath}}/test-negotiate">
<label>Username</label>
<input type="text" name="username" placeholder="Enter your AD username" autofocus required>
<label>Password</label>
<input type="password" name="password" placeholder="Enter your password" required>
<button type="submit">Sign In</button>
</form>
</div>
</div>
<script>setTimeout(function(){document.getElementById('spnego').style.display='none';document.getElementById('fallback').style.display='block';},2000);</script>
</body></html>`

const negotiateTestNTLMFallbackHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Authentication Test — SimpleAuth</title>
<style>` + negotiateTestCSS + `</style></head><body>
<div class="card">
<h1>Sign In</h1>
<p>Kerberos unavailable (browser sent NTLM) — use credentials instead</p>
<div class="gold-bar"></div>
<div class="error">Your browser could not obtain a Kerberos ticket and fell back to NTLM. Check that the SPN matches the URL hostname and you are on the domain.</div>
<form method="POST" action="{{.BasePath}}/test-negotiate">
<label>Username</label>
<input type="text" name="username" placeholder="Enter your AD username" autofocus required>
<label>Password</label>
<input type="password" name="password" placeholder="Enter your password" required>
<button type="submit">Sign In</button>
</form>
</div></body></html>`

const negotiateTestFormErrorHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Authentication Test — SimpleAuth</title>
<style>` + negotiateTestCSS + `</style></head><body>
<div class="card">
<h1>Sign In</h1>
<div class="gold-bar"></div>
<div class="error">Username and password are required.</div>
<form method="POST" action="{{.BasePath}}/test-negotiate">
<label>Username</label>
<input type="text" name="username" placeholder="Enter your AD username" autofocus required>
<label>Password</label>
<input type="password" name="password" placeholder="Enter your password" required>
<button type="submit">Sign In</button>
</form>
</div></body></html>`

const negotiateTestKrbFailedHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Authentication Test — SimpleAuth</title>
<style>` + negotiateTestCSS + `</style></head><body>
<div class="card">
<h1>Sign In</h1>
<p>Kerberos authentication failed — use credentials instead</p>
<div class="gold-bar"></div>
<div class="error">{{.Error}}</div>
<form method="POST" action="{{.BasePath}}/test-negotiate">
<label>Username</label>
<input type="text" name="username" placeholder="Enter your AD username" autofocus required>
<label>Password</label>
<input type="password" name="password" placeholder="Enter your password" required>
<button type="submit">Sign In</button>
</form>
</div></body></html>`

const negotiateTestLoginFailedHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Authentication Test — SimpleAuth</title>
<style>` + negotiateTestCSS + `</style></head><body>
<div class="card">
<h1>Sign In</h1>
<div class="gold-bar"></div>
<div class="error">Authentication failed: {{.Error}}</div>
<form method="POST" action="{{.BasePath}}/test-negotiate">
<label>Username</label>
<input type="text" name="username" placeholder="Enter your AD username" autofocus required>
<label>Password</label>
<input type="password" name="password" placeholder="Enter your password" required>
<button type="submit">Sign In</button>
</form>
</div></body></html>`

const negotiateTestSuccessHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Authentication Test — Success</title>
<style>` + negotiateTestCSS + `</style></head><body>
<div class="card">
<div class="success">Authentication Successful</div>
<h1>Authenticated User</h1>
<table>
<tr><th>Method</th><td>{{.Method}}</td></tr>
<tr><th>Principal</th><td>{{.Principal}}</td></tr>
<tr><th>Realm</th><td>{{.Realm}}</td></tr>
<tr><th>Username</th><td>{{.Username}}</td></tr>
<tr><th>LDAP Provider</th><td>{{.ProviderName}} <span style="color:var(--muted);font-size:0.8rem">({{.ProviderID}})</span></td></tr>
<tr><th>Display Name</th><td>{{.DisplayName}}</td></tr>
<tr><th>Email</th><td>{{.Email}}</td></tr>
<tr><th>Department</th><td>{{.Department}}</td></tr>
<tr><th>Company</th><td>{{.Company}}</td></tr>
<tr><th>Job Title</th><td>{{.JobTitle}}</td></tr>
<tr><th>Groups</th><td>{{.Groups}}</td></tr>
</table>
</div></body></html>`
