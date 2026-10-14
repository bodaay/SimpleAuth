package handler

import (
	"errors"
	"log"
	"net/http"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// ctxAppID carries the authenticated app's id for /api/app/* handlers.
const ctxAppID contextKey = "app_id"

// dummyAppSecretHash is a valid bcrypt hash compared against when an app_id is
// unknown or secret-less, so the credential check runs in the same time as for a
// real app with a wrong secret — closing the app_id enumeration timing oracle (L5).
var dummyAppSecretHash, _ = auth.HashPassword("simpleauth-app-credential-placeholder")

// requireApp authenticates the calling app (HTTP Basic app_id:app_secret, or a
// Bearer app-management token) and scopes the request to that app — the app_id
// is derived from the credential and put in context, never read from the path,
// so an app can only ever act on its own scope (v2 M4).
func (h *Handler) requireApp(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Throttle app_secret (HTTP Basic) attempts to brake brute-force. A Bearer
		// management token is signed and not a guessing vector, so token-based API
		// calls are not rate-limited (M16).
		if _, _, basic := r.BasicAuth(); basic {
			if !h.loginLimiter.allow(getClientIP(r)) {
				jsonError(w, "too many requests", http.StatusTooManyRequests)
				return
			}
		}
		appID, ok := h.authenticateApp(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="simpleauth-app"`)
			jsonError(w, "invalid app credentials", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(setContext(r.Context(), ctxAppID, appID)))
	}
}

// authenticateApp resolves the app from HTTP Basic (app_id:app_secret) or a
// Bearer app-management token. Returns (app_id, ok).
func (h *Handler) authenticateApp(r *http.Request) (string, bool) {
	if appID, secret, ok := r.BasicAuth(); ok && appID != "" {
		app, err := h.store.GetApp(appID)
		// Always run exactly one bcrypt comparison (against a dummy hash when the app
		// is unknown/secret-less) so timing doesn't reveal whether the app_id exists (L5).
		hash := dummyAppSecretHash
		if err == nil && app.SecretHash != "" {
			hash = app.SecretHash
		}
		secretOK := auth.CheckPassword(hash, secret)
		if err == nil && !app.Disabled && app.SecretHash != "" && secretOK {
			return appID, true
		}
		return "", false
	}
	if tok := extractBearerToken(r); tok != "" {
		if claims, err := h.jwt.ValidateToken(tok); err == nil && claims.Typ == "app-mgmt" && claims.Azp != "" {
			if app, err := h.store.GetApp(claims.Azp); err == nil && !app.Disabled {
				// Reject management tokens minted before the last secret rotation, so
				// rotating a leaked secret actually revokes outstanding tokens (L4).
				if !app.SecretRotatedAt.IsZero() && (claims.IssuedAt == nil || claims.IssuedAt.Time.Before(app.SecretRotatedAt)) {
					return "", false
				}
				return claims.Azp, true
			}
		}
	}
	return "", false
}

func appIDFromContext(r *http.Request) string {
	return getContext(r.Context(), ctxAppID)
}

// handleAppToken exchanges app_id + app_secret for a short-lived app-management
// token (usable as a Bearer on /api/app/*). Accepts HTTP Basic or form fields.
// POST /api/app/token
func (h *Handler) handleAppToken(w http.ResponseWriter, r *http.Request) {
	if !h.loginLimiter.allow(getClientIP(r)) {
		jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	_ = r.ParseForm()
	appID := r.FormValue("app_id")
	secret := r.FormValue("app_secret")
	if appID == "" {
		if id, sec, ok := r.BasicAuth(); ok {
			appID, secret = id, sec
		}
	}
	app, err := h.store.GetApp(appID)
	// Always run exactly one bcrypt comparison (dummy hash when unknown/secret-less)
	// so an unknown app_id is indistinguishable from a wrong secret by timing (L5).
	hash := dummyAppSecretHash
	if err == nil && app.SecretHash != "" {
		hash = app.SecretHash
	}
	secretOK := auth.CheckPassword(hash, secret)
	if err != nil || app.Disabled || app.SecretHash == "" || !secretOK {
		w.Header().Set("WWW-Authenticate", `Basic realm="simpleauth-app"`)
		jsonError(w, "invalid app credentials", http.StatusUnauthorized)
		return
	}
	claims := auth.Claims{Typ: "app-mgmt", Azp: appID}
	claims.Subject = appID
	tok, err := h.jwt.IssueAccessToken(claims, h.cfg.AccessTTL)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]interface{}{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(h.cfg.AccessTTL.Seconds()),
	}, http.StatusOK)
}

// defaultAppAuthzForbidden writes a 403 and returns true when appID is the
// default ("home") app. The home app's authorization is the v1 global world —
// managed via the Roles & Permissions catalog + per-user roles, NOT the per-app
// authz surface (resolveTokenRoles ignores the home app's AppAuthz). Refusing
// these writes/reads keeps a holder of the legacy client secret (or a home-app
// admin) from clobbering or reading the directory's home-app role data through a
// surface that has no effect anyway.
func (h *Handler) defaultAppAuthzForbidden(w http.ResponseWriter, appID string) bool {
	if appID == h.defaultAppID() {
		jsonError(w, "the default app is managed via Roles & Permissions and per-user roles, not the per-app authz surface", http.StatusForbidden)
		return true
	}
	return false
}

// handleGetOwnAuthz returns the calling app's authorization. GET /api/app/authz
func (h *Handler) handleGetOwnAuthz(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	if h.defaultAppAuthzForbidden(w, appID) {
		return
	}
	authz, err := h.store.GetAppAuthz(appID)
	if err != nil {
		jsonError(w, "failed to read authz", http.StatusInternalServerError)
		return
	}
	jsonResp(w, authz, http.StatusOK)
}

// handleSetOwnAuthz replaces the calling app's authorization. PUT /api/app/authz
func (h *Handler) handleSetOwnAuthz(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	if h.defaultAppAuthzForbidden(w, appID) {
		return
	}
	var authz store.AppAuthz
	if err := readJSON(r, &authz); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	authz.AppID = appID // the credential is authoritative; ignore any body app_id
	if err := h.store.SaveAppAuthz(&authz); err != nil {
		jsonError(w, "failed to save authz", http.StatusInternalServerError)
		return
	}
	h.audit("app_authz_updated", h.appActor(r), getClientIP(r), map[string]interface{}{"app_id": appID, "actor_kind": h.appActorKind(r)})
	jsonResp(w, &authz, http.StatusOK)
}

// handleAppBootstrap is idempotent authz-as-code for the calling app: it
// declares the app's roles, role→permission map, and assignments. Safe to call
// on every deploy. POST /api/app/bootstrap
func (h *Handler) handleAppBootstrap(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	if h.defaultAppAuthzForbidden(w, appID) {
		return
	}
	var req struct {
		Roles           []string            `json:"roles"`
		Permissions     []string            `json:"permissions"`
		RolePermissions map[string][]string `json:"role_permissions"`
		Assignments     []struct {
			User  string   `json:"user"`
			Group string   `json:"group"`
			Roles []string `json:"roles"`
		} `json:"assignments"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	authz := &store.AppAuthz{
		AppID:            appID,
		Roles:            req.Roles,
		Permissions:      req.Permissions,
		RolePermissions:  req.RolePermissions,
		UserAssignments:  map[string][]string{},
		GroupAssignments: map[string][]string{},
	}
	for _, a := range req.Assignments {
		if a.User != "" {
			authz.UserAssignments[a.User] = a.Roles
		}
		if a.Group != "" {
			authz.GroupAssignments[a.Group] = a.Roles
		}
	}
	if err := h.store.SaveAppAuthz(authz); err != nil {
		jsonError(w, "bootstrap failed", http.StatusInternalServerError)
		return
	}
	h.audit("app_bootstrap", h.appActor(r), getClientIP(r), map[string]interface{}{"app_id": appID, "actor_kind": h.appActorKind(r)})
	jsonResp(w, map[string]interface{}{
		"status":            "ok",
		"app_id":            appID,
		"roles_count":       len(authz.Roles),
		"assignments_count": len(authz.UserAssignments) + len(authz.GroupAssignments),
	}, http.StatusOK)
}

// handleAppSettings returns the calling app's own settings (no secret).
// GET /api/app/settings
func (h *Handler) handleAppSettings(w http.ResponseWriter, r *http.Request) {
	app, err := h.store.GetApp(appIDFromContext(r))
	if err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}
	jsonResp(w, appView(app), http.StatusOK)
}

// --- App-local users (v2 M5) ---

// handleCreateLocalUser provisions an app-local user owned by the calling app
// (e.g. a customer not in the directory). POST /api/app/users — requires the
// app's allow_local_users flag. Roles, if given, are recorded as the app's own
// assignment for that username.
func (h *Handler) handleCreateLocalUser(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	app, err := h.store.GetApp(appID)
	if err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}
	if !app.AllowLocalUsers {
		jsonError(w, "this app does not allow local users (set allow_local_users)", http.StatusForbidden)
		return
	}
	var req struct {
		Username    string   `json:"username"`
		Password    string   `json:"password"`
		DisplayName string   `json:"display_name"`
		Email       string   `json:"email"`
		Roles       []string `json:"roles"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		jsonError(w, "username and password required", http.StatusBadRequest)
		return
	}
	// App-local passwords authenticate through the normal login flow, so they must
	// meet the same password policy as every other write path (M15).
	if err := auth.ValidatePassword(req.Password, h.passwordPolicy()); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	mapKey := "applocal:" + appID
	// Serialize the existence check and the create+mapping so two concurrent
	// creates of the same username can't both pass the check and have the second
	// overwrite the first's mapping, orphaning a fully-provisioned user (L3).
	h.localUserMu.Lock()
	defer h.localUserMu.Unlock()
	if existing, err := h.store.ResolveMapping(mapKey, req.Username); err == nil && existing != "" {
		jsonError(w, "username already exists for this app", http.StatusConflict)
		return
	}
	// Load the authz record before creating anything so a store failure can't
	// leave a half-provisioned user behind.
	var authz *store.AppAuthz
	if len(req.Roles) > 0 {
		authz, err = h.store.GetAppAuthz(appID)
		if err != nil || authz == nil {
			jsonError(w, "failed to load app authorization", http.StatusInternalServerError)
			return
		}
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "failed to hash password", http.StatusInternalServerError)
		return
	}
	u := &store.User{
		OwnerAppID:   appID,
		DisplayName:  req.DisplayName,
		Email:        req.Email,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	}
	if err := h.store.CreateUser(u); err != nil {
		jsonError(w, "failed to create user", http.StatusInternalServerError)
		return
	}
	if err := h.store.SetIdentityMapping(mapKey, req.Username, u.GUID); err != nil {
		h.store.DeleteUser(u.GUID)
		jsonError(w, "failed to create user", http.StatusInternalServerError)
		return
	}
	if authz != nil {
		if authz.UserAssignments == nil {
			authz.UserAssignments = map[string][]string{}
		}
		authz.UserAssignments[req.Username] = req.Roles
		if err := h.store.SaveAppAuthz(authz); err != nil {
			h.store.DeleteIdentityMapping(mapKey, req.Username)
			h.store.DeleteUser(u.GUID)
			jsonError(w, "failed to assign roles", http.StatusInternalServerError)
			return
		}
	}
	h.audit("app_local_user_created", h.appActor(r), getClientIP(r), map[string]interface{}{"app_id": appID, "username": req.Username, "actor_kind": h.appActorKind(r)})
	jsonResp(w, map[string]interface{}{"guid": u.GUID, "username": req.Username, "owner_app_id": appID}, http.StatusCreated)
}

// handleListLocalUsers lists the calling app's local users. GET /api/app/users
func (h *Handler) handleListLocalUsers(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	all, err := h.store.ListUsers()
	if err != nil {
		jsonError(w, "failed to list users", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0)
	for _, u := range all {
		if u.OwnerAppID != appID {
			continue
		}
		out = append(out, map[string]interface{}{
			"guid": u.GUID, "display_name": u.DisplayName, "email": u.Email,
			"disabled": u.Disabled, "created_at": u.CreatedAt,
		})
	}
	jsonResp(w, map[string]interface{}{"users": out}, http.StatusOK)
}

// handleDeleteLocalUser removes an app-local user owned by the calling app.
// DELETE /api/app/users/{guid}
func (h *Handler) handleDeleteLocalUser(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	guid := pathParam(r, "guid")
	// Same lock as create, so a create of this username cannot run between the
	// delete and the assignment cleanup.
	h.localUserMu.Lock()
	defer h.localUserMu.Unlock()
	u, err := h.store.GetUser(guid)
	if err != nil || u.OwnerAppID != appID {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	err = h.deleteLocalUser(appID, guid)
	if err != nil && !errors.Is(err, errLocalAssignmentCleanup) {
		jsonError(w, "failed to delete user", http.StatusInternalServerError)
		return
	}
	h.purgeDeletedUserState(guid)
	h.audit("app_local_user_deleted", h.appActor(r), getClientIP(r), map[string]interface{}{"app_id": appID, "guid": guid, "actor_kind": h.appActorKind(r)})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

// errLocalAssignmentCleanup means the user was deleted but the app's role
// assignment for its username could not be cleared.
var errLocalAssignmentCleanup = errors.New("user deleted, but clearing its role assignment in the app failed")

// deleteLocalUser deletes an app-local user of appID and the app's role
// assignment kept under its username. DeleteUser removes the user's identity
// mappings, which frees the username (M14, M41). The assignment is keyed by
// username, not GUID, so it must go too, or a user created again under that
// name would inherit the old roles. Everything is read before anything is
// deleted, so a read failure leaves the user in place. Callers hold localUserMu
// and call purgeDeletedUserState afterwards, also on errLocalAssignmentCleanup.
func (h *Handler) deleteLocalUser(appID, guid string) error {
	mappings, err := h.store.GetMappingsForUser(guid)
	if err != nil {
		return err
	}
	authz, err := h.store.GetAppAuthz(appID)
	if err != nil {
		return err
	}
	if err := h.store.DeleteUser(guid); err != nil {
		return err
	}
	if authz == nil || authz.UserAssignments == nil {
		return nil
	}
	mapKey := "applocal:" + appID
	changed := false
	for _, m := range mappings {
		if _, ok := authz.UserAssignments[m.ExternalID]; ok && m.Provider == mapKey {
			delete(authz.UserAssignments, m.ExternalID)
			changed = true
		}
	}
	if changed {
		if err := h.store.SaveAppAuthz(authz); err != nil {
			log.Printf("[app] delete local user: clear role assignment failed app=%s guid=%s err=%v", appID, guid, err)
			return errLocalAssignmentCleanup
		}
	}
	return nil
}

// handleSetLocalUserPassword resets an app-local user's password.
// PUT /api/app/users/{guid}/password
func (h *Handler) handleSetLocalUserPassword(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	guid := pathParam(r, "guid")
	u, err := h.store.GetUser(guid)
	if err != nil || u.OwnerAppID != appID {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil || req.Password == "" {
		jsonError(w, "password required", http.StatusBadRequest)
		return
	}
	if err := auth.ValidatePassword(req.Password, h.passwordPolicy()); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "failed to hash password", http.StatusInternalServerError)
		return
	}
	u.PasswordHash = hash
	if err := h.store.UpdateUser(u); err != nil {
		jsonError(w, "failed to update password", http.StatusInternalServerError)
		return
	}
	h.audit("app_local_user_password_reset", h.appActor(r), getClientIP(r), map[string]interface{}{"app_id": appID, "guid": guid, "actor_kind": h.appActorKind(r)})
	jsonResp(w, map[string]string{"status": "password updated"}, http.StatusOK)
}
