package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

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
	// Strip password hashes and history
	for _, u := range users {
		u.PasswordHash = ""
		u.PasswordHistory = nil
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
		if err := auth.ValidatePassword(req.Password, h.passwordPolicy()); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
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
	user.PasswordHistory = nil
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
	user.PasswordHistory = nil
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
		Password    string `json:"password"`
		ForceChange *bool  `json:"force_change"`
	}
	if err := readJSON(r, &req); err != nil || req.Password == "" {
		jsonError(w, "password required", http.StatusBadRequest)
		return
	}

	// Validate password against policy
	if err := auth.ValidatePassword(req.Password, h.passwordPolicy()); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check password history
	if h.cfg.PasswordHistoryCount > 0 && auth.CheckPasswordHistory(req.Password, user.PasswordHistory) {
		jsonError(w, fmt.Sprintf("password was recently used (last %d passwords are remembered)", h.cfg.PasswordHistoryCount), http.StatusBadRequest)
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		jsonError(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	// Update password history
	if h.cfg.PasswordHistoryCount > 0 && user.PasswordHash != "" {
		user.PasswordHistory = auth.AddToPasswordHistory(user.PasswordHistory, user.PasswordHash, h.cfg.PasswordHistoryCount)
	}

	user.PasswordHash = hash

	// Set force_change flag (defaults to false if not provided)
	if req.ForceChange != nil {
		user.ForcePasswordChange = *req.ForceChange
	}

	if err := h.store.UpdateUser(user); err != nil {
		jsonError(w, "failed to update password", http.StatusInternalServerError)
		return
	}

	h.audit("password_set", "admin", getClientIP(r), map[string]interface{}{
		"target_guid":  guid,
		"force_change": user.ForcePasswordChange,
	})

	jsonResp(w, map[string]interface{}{
		"status":       "password updated",
		"force_change": user.ForcePasswordChange,
	}, http.StatusOK)
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

// --- Password Policy ---

func (h *Handler) handleGetPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, map[string]interface{}{
		"min_length":         h.cfg.PasswordMinLength,
		"require_uppercase":  h.cfg.PasswordRequireUppercase,
		"require_lowercase":  h.cfg.PasswordRequireLowercase,
		"require_digit":      h.cfg.PasswordRequireDigit,
		"require_special":    h.cfg.PasswordRequireSpecial,
		"history_count":      h.cfg.PasswordHistoryCount,
		"lockout_threshold":  h.cfg.AccountLockoutThreshold,
		"lockout_duration":   h.cfg.AccountLockoutDuration.String(),
	}, http.StatusOK)
}

func (h *Handler) handleUnlockAccount(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	user, err := h.store.GetUser(guid)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	if err := h.store.UpdateUser(user); err != nil {
		jsonError(w, "failed to unlock account", http.StatusInternalServerError)
		return
	}
	h.audit("account_unlocked", "admin", getClientIP(r), map[string]interface{}{"target_guid": guid})
	jsonResp(w, map[string]string{"status": "account unlocked"}, http.StatusOK)
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
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	result := make([]sessionInfo, len(sessions))
	for i, s := range sessions {
		result[i] = sessionInfo{
			FamilyID:  s.FamilyID,
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

func (h *Handler) handleGetRoles(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	roles, err := h.store.GetUserRoles(guid)
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
	guid := pathParam(r, "guid")

	var roles []string
	if err := readJSON(r, &roles); err != nil {
		jsonError(w, "invalid request body, expected array of strings", http.StatusBadRequest)
		return
	}

	oldRoles, _ := h.store.GetUserRoles(guid)
	if err := h.store.SetUserRoles(guid, roles); err != nil {
		jsonError(w, "failed to set roles", http.StatusInternalServerError)
		return
	}

	h.audit("role_changed", "admin", getClientIP(r), map[string]interface{}{
		"user_guid": guid,
		"old_roles": oldRoles, "new_roles": roles,
	})

	jsonResp(w, roles, http.StatusOK)
}

func (h *Handler) handleGetPermissions(w http.ResponseWriter, r *http.Request) {
	guid := pathParam(r, "guid")
	perms, err := h.store.GetUserPermissions(guid)
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
	guid := pathParam(r, "guid")

	var perms []string
	if err := readJSON(r, &perms); err != nil {
		jsonError(w, "invalid request body, expected array of strings", http.StatusBadRequest)
		return
	}

	oldPerms, _ := h.store.GetUserPermissions(guid)
	if err := h.store.SetUserPermissions(guid, perms); err != nil {
		jsonError(w, "failed to set permissions", http.StatusInternalServerError)
		return
	}

	h.audit("permission_changed", "admin", getClientIP(r), map[string]interface{}{
		"user_guid":       guid,
		"old_permissions": oldPerms, "new_permissions": perms,
	})

	jsonResp(w, perms, http.StatusOK)
}

func (h *Handler) handleGetDefaultRoles(w http.ResponseWriter, r *http.Request) {
	roles, _ := h.store.GetDefaultRoles()
	if roles == nil {
		roles = []string{}
	}
	jsonResp(w, roles, http.StatusOK)
}

func (h *Handler) handleSetDefaultRoles(w http.ResponseWriter, r *http.Request) {
	var roles []string
	if err := readJSON(r, &roles); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.store.SetDefaultRoles(roles); err != nil {
		jsonError(w, "failed to set default roles", http.StatusInternalServerError)
		return
	}

	h.audit("default_roles_changed", "admin", getClientIP(r), map[string]interface{}{
		"roles": roles,
	})

	jsonResp(w, roles, http.StatusOK)
}

// --- Role -> Permissions Mapping ---

func (h *Handler) handleGetRolePermissions(w http.ResponseWriter, r *http.Request) {
	mapping, _ := h.store.GetRolePermissions()
	if mapping == nil {
		mapping = map[string][]string{}
	}
	jsonResp(w, mapping, http.StatusOK)
}

func (h *Handler) handleSetRolePermissions(w http.ResponseWriter, r *http.Request) {
	var mapping map[string][]string
	if err := readJSON(r, &mapping); err != nil {
		jsonError(w, "invalid request body — expected {\"role\": [\"perm1\", \"perm2\"]}", http.StatusBadRequest)
		return
	}
	if err := h.store.SetRolePermissions(mapping); err != nil {
		jsonError(w, "failed to set role permissions", http.StatusInternalServerError)
		return
	}

	h.audit("role_permissions_changed", "admin", getClientIP(r), map[string]interface{}{
		"mapping": mapping,
	})

	jsonResp(w, mapping, http.StatusOK)
}

// --- List All Roles / Permissions ---

func (h *Handler) handleListAllRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.store.ListAllRoles()
	if err != nil {
		jsonError(w, "failed to list roles", http.StatusInternalServerError)
		return
	}
	if roles == nil {
		roles = []string{}
	}
	jsonResp(w, roles, http.StatusOK)
}

func (h *Handler) handleListAllPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.store.ListAllPermissions()
	if err != nil {
		jsonError(w, "failed to list permissions", http.StatusInternalServerError)
		return
	}
	if perms == nil {
		perms = []string{}
	}
	jsonResp(w, perms, http.StatusOK)
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

// --- AD/LDAP Sync ---

// handleSyncUser syncs a single user's profile from LDAP.
// POST /api/admin/ldap/sync-user
// Body: {"username": "alice"}
func (h *Handler) handleSyncUser(w http.ResponseWriter, r *http.Request) {
	p, err := h.store.GetLDAPConfig()
	if err != nil {
		jsonError(w, "ldap not configured", http.StatusNotFound)
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := readJSON(r, &req); err != nil || req.Username == "" {
		jsonError(w, "username required", http.StatusBadRequest)
		return
	}

	cfg := ldapConfigFromStore(p)
	usernameAttr := cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}
	result, err := auth.LDAPSearchUser(cfg, usernameAttr, req.Username)
	if err != nil {
		jsonError(w, fmt.Sprintf("LDAP search failed: %v", err), http.StatusBadGateway)
		return
	}

	// Find user by LDAP mapping
	userGUID, err := h.store.ResolveMapping("ldap", req.Username)
	if err != nil {
		jsonError(w, "no local user mapped to ldap:"+req.Username, http.StatusNotFound)
		return
	}

	user, err := h.store.ResolveUser(userGUID)
	if err != nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	h.syncUserFromLDAP(user, result)

	h.audit("ldap_sync_user", "admin", getClientIP(r), map[string]interface{}{
		"username": req.Username, "user_guid": user.GUID,
	})

	user.PasswordHash = ""
	user.PasswordHistory = nil
	jsonResp(w, map[string]interface{}{
		"status": "synced",
		"user":   user,
	}, http.StatusOK)
}

// handleSyncAll syncs all users that have LDAP mappings.
// POST /api/admin/ldap/sync-all
func (h *Handler) handleSyncAll(w http.ResponseWriter, r *http.Request) {
	p, err := h.store.GetLDAPConfig()
	if err != nil {
		jsonError(w, "ldap not configured", http.StatusNotFound)
		return
	}

	cfg := ldapConfigFromStore(p)

	users, err := h.store.ListUsers()
	if err != nil {
		jsonError(w, "failed to list users", http.StatusInternalServerError)
		return
	}

	synced := 0
	failed := 0
	var syncErrors []string

	for _, u := range users {
		if u.MergedInto != "" {
			continue
		}
		mappings, _ := h.store.GetMappingsForUser(u.GUID)
		for _, m := range mappings {
			if m.Provider != "ldap" {
				continue
			}
			result, err := auth.LDAPSearchUser(cfg, "sAMAccountName", m.ExternalID)
			if err != nil {
				failed++
				syncErrors = append(syncErrors, fmt.Sprintf("%s: %v", m.ExternalID, err))
				continue
			}
			h.syncUserFromLDAP(u, result)
			synced++
			break
		}
	}

	h.audit("ldap_sync_all", "admin", getClientIP(r), map[string]interface{}{
		"synced": synced, "failed": failed,
	})

	resp := map[string]interface{}{
		"status": "completed",
		"synced": synced,
		"failed": failed,
	}
	if len(syncErrors) > 0 {
		resp["errors"] = syncErrors
	}
	jsonResp(w, resp, http.StatusOK)
}
