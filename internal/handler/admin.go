package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// --- App Management ---

func (h *Handler) handleListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.store.ListApps()
	if err != nil {
		jsonError(w, "failed to list apps", http.StatusInternalServerError)
		return
	}
	if apps == nil {
		apps = []*store.App{}
	}
	jsonResp(w, apps, http.StatusOK)
}

func (h *Handler) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name             string                          `json:"name"`
		Description      string                          `json:"description"`
		RedirectURIs     []string                        `json:"redirect_uris"`
		ProviderMappings map[string]store.ProviderMapping `json:"provider_mappings"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name required", http.StatusBadRequest)
		return
	}

	app := &store.App{
		Name:             req.Name,
		Description:      req.Description,
		RedirectURIs:     req.RedirectURIs,
		ProviderMappings: req.ProviderMappings,
	}
	if err := h.store.CreateApp(app); err != nil {
		jsonError(w, "failed to create app", http.StatusInternalServerError)
		return
	}

	h.audit("app_registered", "admin", getClientIP(r), map[string]interface{}{"app_id": app.AppID})

	jsonResp(w, map[string]interface{}{
		"app_id":  app.AppID,
		"name":    app.Name,
		"api_key": app.APIKey,
	}, http.StatusCreated)
}

func (h *Handler) handleGetApp(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	app, err := h.store.GetApp(appID)
	if err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}
	jsonResp(w, app, http.StatusOK)
}

func (h *Handler) handleUpdateApp(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	app, err := h.store.GetApp(appID)
	if err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}

	var req struct {
		Name             *string                          `json:"name"`
		Description      *string                          `json:"description"`
		RedirectURIs     []string                         `json:"redirect_uris"`
		ProviderMappings map[string]store.ProviderMapping `json:"provider_mappings"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name != nil {
		app.Name = *req.Name
	}
	if req.Description != nil {
		app.Description = *req.Description
	}
	if req.RedirectURIs != nil {
		app.RedirectURIs = req.RedirectURIs
	}
	if req.ProviderMappings != nil {
		app.ProviderMappings = req.ProviderMappings
	}

	if err := h.store.UpdateApp(app); err != nil {
		jsonError(w, "failed to update app", http.StatusInternalServerError)
		return
	}
	jsonResp(w, app, http.StatusOK)
}

func (h *Handler) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	if err := h.store.DeleteApp(appID); err != nil {
		jsonError(w, "failed to delete app", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

func (h *Handler) handleRotateAppKey(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	newKey, err := h.store.RotateAppKey(appID)
	if err != nil {
		jsonError(w, "failed to rotate key", http.StatusInternalServerError)
		return
	}

	h.audit("app_key_rotated", "admin", getClientIP(r), map[string]interface{}{"app_id": appID})

	jsonResp(w, map[string]string{
		"app_id":      appID,
		"new_api_key": newKey,
	}, http.StatusOK)
}

// --- User Management ---

func (h *Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers()
	if err != nil {
		jsonError(w, "failed to list users", http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []*store.User{}
	}
	// Strip password hashes
	for _, u := range users {
		u.PasswordHash = ""
	}
	jsonResp(w, users, http.StatusOK)
}

func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Department  string `json:"department"`
		Company     string `json:"company"`
		JobTitle    string `json:"job_title"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user := &store.User{
		DisplayName: req.DisplayName,
		Email:       req.Email,
		Department:  req.Department,
		Company:     req.Company,
		JobTitle:    req.JobTitle,
	}

	if req.Password != "" {
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			jsonError(w, "failed to hash password", http.StatusInternalServerError)
			return
		}
		user.PasswordHash = hash
	}

	if err := h.store.CreateUser(user); err != nil {
		jsonError(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	// Create identity mapping for username if provided
	if req.Username != "" {
		h.store.SetIdentityMapping("local", req.Username, user.GUID)
	}

	h.audit("user_created", user.GUID, getClientIP(r), map[string]interface{}{"username": req.Username})

	jsonResp(w, map[string]interface{}{
		"guid":         user.GUID,
		"display_name": user.DisplayName,
		"email":        user.Email,
	}, http.StatusCreated)
}

func (h *Handler) handleGetUser(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	user, err := h.store.GetUser(guid)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	user.PasswordHash = ""
	jsonResp(w, user, http.StatusOK)
}

func (h *Handler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	user, err := h.store.GetUser(guid)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	var req struct {
		DisplayName *string `json:"display_name"`
		Email       *string `json:"email"`
		Department  *string `json:"department"`
		Company     *string `json:"company"`
		JobTitle    *string `json:"job_title"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.DisplayName != nil {
		user.DisplayName = *req.DisplayName
	}
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.Department != nil {
		user.Department = *req.Department
	}
	if req.Company != nil {
		user.Company = *req.Company
	}
	if req.JobTitle != nil {
		user.JobTitle = *req.JobTitle
	}

	if err := h.store.UpdateUser(user); err != nil {
		jsonError(w, "failed to update user", http.StatusInternalServerError)
		return
	}
	user.PasswordHash = ""
	jsonResp(w, user, http.StatusOK)
}

func (h *Handler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	if err := h.store.DeleteUser(guid); err != nil {
		jsonError(w, "failed to delete user", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

func (h *Handler) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	user, err := h.store.GetUser(guid)
	if err != nil {
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

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "failed to hash password", http.StatusInternalServerError)
		return
	}
	user.PasswordHash = hash
	if err := h.store.UpdateUser(user); err != nil {
		jsonError(w, "failed to update password", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]string{"status": "password updated"}, http.StatusOK)
}

func (h *Handler) handleSetDisabled(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	user, err := h.store.GetUser(guid)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	var req struct {
		Disabled bool `json:"disabled"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	user.Disabled = req.Disabled
	if err := h.store.UpdateUser(user); err != nil {
		jsonError(w, "failed to update user", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]interface{}{"guid": guid, "disabled": user.Disabled}, http.StatusOK)
}

// --- Sessions ---

func (h *Handler) handleListSessions(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	sessions, err := h.store.ListUserSessions(guid)
	if err != nil {
		jsonError(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}
	if sessions == nil {
		sessions = []*store.RefreshToken{}
	}
	// Return safe subset (no raw token IDs)
	type sessionInfo struct {
		FamilyID  string    `json:"family_id"`
		AppID     string    `json:"app_id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	result := make([]sessionInfo, len(sessions))
	for i, s := range sessions {
		result[i] = sessionInfo{
			FamilyID:  s.FamilyID,
			AppID:     s.AppID,
			CreatedAt: s.CreatedAt,
			ExpiresAt: s.ExpiresAt,
		}
	}
	jsonResp(w, result, http.StatusOK)
}

func (h *Handler) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	if err := h.store.RevokeUserTokens(guid); err != nil {
		jsonError(w, "failed to revoke sessions", http.StatusInternalServerError)
		return
	}
	h.audit("sessions_revoked", "admin", getClientIP(r), map[string]interface{}{"target_guid": guid})
	jsonResp(w, map[string]string{"status": "all sessions revoked"}, http.StatusOK)
}

// --- Identity Mappings ---

func (h *Handler) handleListAllMappings(w http.ResponseWriter, r *http.Request) {
	mappings, err := h.store.ListAllMappings()
	if err != nil {
		jsonError(w, "failed to list mappings", http.StatusInternalServerError)
		return
	}
	if mappings == nil {
		mappings = []store.IdentityMappingEntry{}
	}
	jsonResp(w, mappings, http.StatusOK)
}

func (h *Handler) handleGetMappings(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	mappings, err := h.store.GetMappingsForUser(guid)
	if err != nil {
		jsonError(w, "failed to get mappings", http.StatusInternalServerError)
		return
	}
	if mappings == nil {
		mappings = []store.IdentityMapping{}
	}
	jsonResp(w, mappings, http.StatusOK)
}

func (h *Handler) handleSetMapping(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")

	var req struct {
		Provider   string `json:"provider"`
		ExternalID string `json:"external_id"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Provider == "" || req.ExternalID == "" {
		jsonError(w, "provider and external_id required", http.StatusBadRequest)
		return
	}

	// App API keys can only set mappings for their own provider
	if !h.checkAppScope(r, "") {
		callerAppID := getContext(r.Context(), ctxAppID)
		if req.Provider != "app:"+callerAppID {
			jsonError(w, "can only manage mappings for your own app", http.StatusForbidden)
			return
		}
	}

	if err := h.store.SetIdentityMapping(req.Provider, req.ExternalID, guid); err != nil {
		jsonError(w, "failed to set mapping", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]string{"status": "ok"}, http.StatusOK)
}

func (h *Handler) handleDeleteMapping(w http.ResponseWriter, r *http.Request) {
	provider, externalID := splitMappingPath(r)
	if err := h.store.DeleteIdentityMapping(provider, externalID); err != nil {
		jsonError(w, "failed to delete mapping", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

func (h *Handler) handleResolveMapping(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	externalID := r.URL.Query().Get("external_id")
	if provider == "" || externalID == "" {
		jsonError(w, "provider and external_id query params required", http.StatusBadRequest)
		return
	}

	guid, err := h.store.ResolveMapping(provider, externalID)
	if err != nil {
		jsonError(w, "mapping not found", http.StatusNotFound)
		return
	}

	// Follow merges
	user, err := h.store.ResolveUser(guid)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	jsonResp(w, map[string]string{"guid": user.GUID}, http.StatusOK)
}

// --- Roles & Permissions ---

func (h *Handler) handleListAppUsers(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	if !h.checkAppScope(r, appID) {
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	guids, err := h.store.GetUsersWithRolesInApp(appID)
	if err != nil {
		jsonError(w, "failed to list users", http.StatusInternalServerError)
		return
	}

	type userWithRoles struct {
		GUID        string   `json:"guid"`
		DisplayName string   `json:"display_name"`
		Email       string   `json:"email"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}

	var result []userWithRoles
	for _, guid := range guids {
		user, err := h.store.GetUser(guid)
		if err != nil {
			continue
		}
		roles, _ := h.store.GetUserRoles(guid, appID)
		perms, _ := h.store.GetUserPermissions(guid, appID)
		result = append(result, userWithRoles{
			GUID:        user.GUID,
			DisplayName: user.DisplayName,
			Email:       user.Email,
			Roles:       roles,
			Permissions: perms,
		})
	}

	if result == nil {
		result = []userWithRoles{}
	}
	jsonResp(w, result, http.StatusOK)
}

func (h *Handler) handleGetRoles(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	guid := pathParam(r, "guid")
	if !h.checkAppScope(r, appID) {
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}
	roles, err := h.store.GetUserRoles(guid, appID)
	if err != nil {
		jsonError(w, "failed to get roles", http.StatusInternalServerError)
		return
	}
	if roles == nil {
		roles = []string{}
	}
	jsonResp(w, roles, http.StatusOK)
}

func (h *Handler) handleSetRoles(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	guid := pathParam(r, "guid")
	if !h.checkAppScope(r, appID) {
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	var roles []string
	if err := readJSON(r, &roles); err != nil {
		jsonError(w, "invalid request body, expected array of strings", http.StatusBadRequest)
		return
	}

	oldRoles, _ := h.store.GetUserRoles(guid, appID)
	if err := h.store.SetUserRoles(guid, appID, roles); err != nil {
		jsonError(w, "failed to set roles", http.StatusInternalServerError)
		return
	}

	h.audit("role_changed", "admin", getClientIP(r), map[string]interface{}{
		"user_guid": guid, "app_id": appID,
		"old_roles": oldRoles, "new_roles": roles,
	})

	jsonResp(w, roles, http.StatusOK)
}

func (h *Handler) handleGetPermissions(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	guid := pathParam(r, "guid")
	if !h.checkAppScope(r, appID) {
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}
	perms, err := h.store.GetUserPermissions(guid, appID)
	if err != nil {
		jsonError(w, "failed to get permissions", http.StatusInternalServerError)
		return
	}
	if perms == nil {
		perms = []string{}
	}
	jsonResp(w, perms, http.StatusOK)
}

func (h *Handler) handleSetPermissions(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	guid := pathParam(r, "guid")
	if !h.checkAppScope(r, appID) {
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	var perms []string
	if err := readJSON(r, &perms); err != nil {
		jsonError(w, "invalid request body, expected array of strings", http.StatusBadRequest)
		return
	}

	oldPerms, _ := h.store.GetUserPermissions(guid, appID)
	if err := h.store.SetUserPermissions(guid, appID, perms); err != nil {
		jsonError(w, "failed to set permissions", http.StatusInternalServerError)
		return
	}

	h.audit("permission_changed", "admin", getClientIP(r), map[string]interface{}{
		"user_guid": guid, "app_id": appID,
		"old_permissions": oldPerms, "new_permissions": perms,
	})

	jsonResp(w, perms, http.StatusOK)
}

func (h *Handler) handleGetDefaultRoles(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	if !h.checkAppScope(r, appID) {
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}
	roles, _ := h.store.GetDefaultRoles(appID)
	if roles == nil {
		roles = []string{}
	}
	jsonResp(w, roles, http.StatusOK)
}

func (h *Handler) handleSetDefaultRoles(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	if !h.checkAppScope(r, appID) {
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	var roles []string
	if err := readJSON(r, &roles); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.store.SetDefaultRoles(appID, roles); err != nil {
		jsonError(w, "failed to set default roles", http.StatusInternalServerError)
		return
	}
	jsonResp(w, roles, http.StatusOK)
}

// --- Global Default Roles ---

func (h *Handler) handleGetGlobalDefaultRoles(w http.ResponseWriter, r *http.Request) {
	roles, _ := h.store.GetGlobalDefaultRoles()
	if roles == nil {
		roles = []string{}
	}
	jsonResp(w, roles, http.StatusOK)
}

func (h *Handler) handleSetGlobalDefaultRoles(w http.ResponseWriter, r *http.Request) {
	var roles []string
	if err := readJSON(r, &roles); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.store.SetGlobalDefaultRoles(roles); err != nil {
		jsonError(w, "failed to set global default roles", http.StatusInternalServerError)
		return
	}

	h.audit("global_default_roles_changed", "admin", getClientIP(r), map[string]interface{}{
		"roles": roles,
	})

	jsonResp(w, roles, http.StatusOK)
}

// --- Role → Permissions Mapping ---

func (h *Handler) handleGetRolePermissions(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	if !h.checkAppScope(r, appID) {
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}
	mapping, _ := h.store.GetRolePermissions(appID)
	if mapping == nil {
		mapping = map[string][]string{}
	}
	jsonResp(w, mapping, http.StatusOK)
}

func (h *Handler) handleSetRolePermissions(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	if !h.checkAppScope(r, appID) {
		jsonError(w, "access denied", http.StatusForbidden)
		return
	}

	var mapping map[string][]string
	if err := readJSON(r, &mapping); err != nil {
		jsonError(w, "invalid request body — expected {\"role\": [\"perm1\", \"perm2\"]}", http.StatusBadRequest)
		return
	}
	if err := h.store.SetRolePermissions(appID, mapping); err != nil {
		jsonError(w, "failed to set role permissions", http.StatusInternalServerError)
		return
	}

	h.audit("role_permissions_changed", "admin", getClientIP(r), map[string]interface{}{
		"app_id": appID, "mapping": mapping,
	})

	jsonResp(w, mapping, http.StatusOK)
}

// --- User Merge ---

func (h *Handler) handleMergeUsers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SourceGUIDs []string `json:"source_guids"`
		DisplayName string   `json:"display_name"`
		Email       string   `json:"email"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.SourceGUIDs) < 2 {
		jsonError(w, "at least 2 source_guids required", http.StatusBadRequest)
		return
	}

	newUser, err := h.store.MergeUsers(req.SourceGUIDs, req.DisplayName, req.Email)
	if err != nil {
		jsonError(w, fmt.Sprintf("merge failed: %v", err), http.StatusInternalServerError)
		return
	}

	h.audit("user_merged", "admin", getClientIP(r), map[string]interface{}{
		"source_guids": req.SourceGUIDs, "merged_guid": newUser.GUID,
	})

	jsonResp(w, map[string]interface{}{
		"merged_guid": newUser.GUID,
		"sources":     req.SourceGUIDs,
	}, http.StatusOK)
}

func (h *Handler) handleUnmergeUser(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	if err := h.store.UnmergeUser(guid); err != nil {
		jsonError(w, fmt.Sprintf("unmerge failed: %v", err), http.StatusBadRequest)
		return
	}

	h.audit("user_unmerged", "admin", getClientIP(r), map[string]interface{}{"guid": guid})

	jsonResp(w, map[string]string{"status": "unmerged", "guid": guid}, http.StatusOK)
}

// --- Backup & Restore ---

func (h *Handler) handleBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="auth-backup-%s.db"`, time.Now().Format("2006-01-02")))

	if err := h.store.BackupWriter(w); err != nil {
		jsonError(w, "backup failed", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) handleRestore(w http.ResponseWriter, r *http.Request) {
	// Limit upload to 500MB
	r.Body = http.MaxBytesReader(w, r.Body, 500<<20)

	file, _, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "file upload required (multipart field 'file')", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if err := h.store.Restore(file); err != nil {
		jsonError(w, "restore failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResp(w, map[string]string{"status": "restored"}, http.StatusOK)
}

// --- Audit Log ---

func (h *Handler) handleQueryAudit(w http.ResponseWriter, r *http.Request) {
	q := store.AuditQuery{
		Event:  r.URL.Query().Get("event"),
		UserID: r.URL.Query().Get("user"),
	}

	if from := r.URL.Query().Get("from"); from != "" {
		if t, err := time.Parse("2006-01-02", from); err == nil {
			q.From = t
		}
	}
	if to := r.URL.Query().Get("to"); to != "" {
		if t, err := time.Parse("2006-01-02", to); err == nil {
			q.To = t.Add(24 * time.Hour) // Include the entire day
		}
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil {
			q.Limit = n
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		if n, err := strconv.Atoi(offset); err == nil {
			q.Offset = n
		}
	}

	entries, err := h.store.QueryAuditLog(q)
	if err != nil {
		jsonError(w, "failed to query audit log", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []*store.AuditEntry{}
	}
	jsonResp(w, entries, http.StatusOK)
}

// --- One-Time Tokens ---

func (h *Handler) handleListTokens(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	tokens, err := h.store.ListOneTimeTokens(scope)
	if err != nil {
		jsonError(w, "failed to list tokens", http.StatusInternalServerError)
		return
	}
	if tokens == nil {
		tokens = []*store.OneTimeToken{}
	}
	jsonResp(w, tokens, http.StatusOK)
}

func (h *Handler) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Scope string `json:"scope"`
		Label string `json:"label"`
		TTL   string `json:"ttl"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Scope == "" {
		jsonError(w, "scope required", http.StatusBadRequest)
		return
	}

	ttl := 24 * time.Hour // default 24h
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err != nil {
			jsonError(w, "invalid ttl duration", http.StatusBadRequest)
			return
		}
		ttl = parsed
	}

	tok, err := h.store.CreateOneTimeToken(req.Scope, req.Label, ttl)
	if err != nil {
		jsonError(w, "failed to create token", http.StatusInternalServerError)
		return
	}

	h.audit("token_created", "admin", getClientIP(r), map[string]interface{}{
		"token": tok.Token, "scope": req.Scope, "label": req.Label,
	})

	jsonResp(w, tok, http.StatusCreated)
}

func (h *Handler) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	token := pathParam(r, "token")
	if err := h.store.DeleteOneTimeToken(token); err != nil {
		jsonError(w, "failed to delete token", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

// handleSelfRegister allows an app to register itself using a one-time token scoped to "app-registration".
// This is a public endpoint — no admin key required.
func (h *Handler) handleSelfRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token            string                          `json:"token"`
		Name             string                          `json:"name"`
		Description      string                          `json:"description"`
		RedirectURIs     []string                        `json:"redirect_uris"`
		ProviderMappings map[string]store.ProviderMapping `json:"provider_mappings"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	token := strings.TrimSpace(req.Token)
	if token == "" || req.Name == "" {
		jsonError(w, "token and name required", http.StatusBadRequest)
		return
	}

	// Create the app
	app := &store.App{
		Name:             req.Name,
		Description:      req.Description,
		RedirectURIs:     req.RedirectURIs,
		ProviderMappings: req.ProviderMappings,
	}
	if err := h.store.CreateApp(app); err != nil {
		jsonError(w, "failed to create app", http.StatusInternalServerError)
		return
	}

	// Consume the token (validates scope, expiry, and single-use)
	if err := h.store.UseOneTimeToken(token, "app-registration", app.AppID); err != nil {
		// Rollback the app creation
		h.store.DeleteApp(app.AppID)
		jsonError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	h.audit("app_self_registered", app.AppID, getClientIP(r), map[string]interface{}{
		"token": token, "app_name": req.Name,
	})

	jsonResp(w, map[string]interface{}{
		"app_id":  app.AppID,
		"name":    app.Name,
		"api_key": app.APIKey,
	}, http.StatusCreated)
}
