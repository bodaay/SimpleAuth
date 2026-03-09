package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/config"
	"simpleauth/internal/store"
)

type Handler struct {
	cfg         *config.Config
	store       *store.Store
	jwt         *auth.JWTManager
	loginLimiter *rateLimiter
	mux         *http.ServeMux
}

func New(cfg *config.Config, s *store.Store, jwtMgr *auth.JWTManager, uiFS fs.FS) *Handler {
	h := &Handler{
		cfg:          cfg,
		store:        s,
		jwt:          jwtMgr,
		loginLimiter: newRateLimiter(cfg.RateLimitMax, cfg.RateLimitWindow),
		mux:          http.NewServeMux(),
	}
	h.registerRoutes(uiFS)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.cfg.CORSOrigins != "" {
		origin := r.Header.Get("Origin")
		if origin != "" && h.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) isAllowedOrigin(origin string) bool {
	if h.cfg.CORSOrigins == "*" {
		return true
	}
	for _, allowed := range strings.Split(h.cfg.CORSOrigins, ",") {
		if strings.TrimSpace(allowed) == origin {
			return true
		}
	}
	return false
}

func (h *Handler) registerRoutes(uiFS fs.FS) {
	// Auth endpoints
	h.mux.HandleFunc("POST /api/auth/login", h.handleLogin)
	h.mux.HandleFunc("POST /api/auth/refresh", h.handleRefresh)
	h.mux.HandleFunc("GET /api/auth/userinfo", h.handleUserInfo)
	h.mux.HandleFunc("POST /api/auth/impersonate", h.requireMasterAdmin(h.handleImpersonate))
	h.mux.HandleFunc("GET /api/auth/negotiate", h.handleNegotiate)
	h.mux.HandleFunc("GET /auth/test-negotiate", h.handleNegotiateTest)
	h.mux.HandleFunc("POST /auth/test-negotiate", h.handleNegotiateTestForm)

	// Hosted login page
	h.mux.HandleFunc("GET /login", h.handleHostedLoginPage)
	h.mux.HandleFunc("POST /login", h.handleHostedLoginSubmit)

	// JWKS
	h.mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)

	// Health & Server Info
	h.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]string{"status": "ok"}, http.StatusOK)
	})
	h.mux.HandleFunc("GET /api/admin/server-info", h.requireMasterAdmin(func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{
			"hostname":     h.cfg.Hostname,
			"project_name": h.cfg.ProjectName,
			"jwt_issuer":   h.cfg.JWTIssuer,
			"version":      "dev",
		}, http.StatusOK)
	}))

	// Admin: Apps
	h.mux.HandleFunc("GET /api/admin/apps", h.adminAuth(h.handleListApps))
	h.mux.HandleFunc("POST /api/admin/apps", h.requireMasterAdmin(h.handleCreateApp))
	h.mux.HandleFunc("GET /api/admin/apps/{app_id}", h.adminAuth(h.handleGetApp))
	h.mux.HandleFunc("PUT /api/admin/apps/{app_id}", h.requireMasterAdmin(h.handleUpdateApp))
	h.mux.HandleFunc("DELETE /api/admin/apps/{app_id}", h.requireMasterAdmin(h.handleDeleteApp))
	h.mux.HandleFunc("POST /api/admin/apps/{app_id}/rotate-key", h.requireMasterAdmin(h.handleRotateAppKey))

	// Admin: LDAP Providers
	h.mux.HandleFunc("GET /api/admin/ldap", h.requireMasterAdmin(h.handleListLDAP))
	h.mux.HandleFunc("POST /api/admin/ldap", h.requireMasterAdmin(h.handleCreateLDAP))
	h.mux.HandleFunc("GET /api/admin/ldap/export", h.requireMasterAdmin(h.handleExportLDAP))
	h.mux.HandleFunc("POST /api/admin/ldap/import", h.requireMasterAdmin(h.handleImportLDAP))
	h.mux.HandleFunc("POST /api/admin/ldap/auto-discover", h.requireMasterAdmin(h.handleAutoDiscoverLDAP))
	h.mux.HandleFunc("GET /api/admin/ldap/{provider_id}", h.requireMasterAdmin(h.handleGetLDAP))
	h.mux.HandleFunc("PUT /api/admin/ldap/{provider_id}", h.requireMasterAdmin(h.handleUpdateLDAP))
	h.mux.HandleFunc("DELETE /api/admin/ldap/{provider_id}", h.requireMasterAdmin(h.handleDeleteLDAP))
	h.mux.HandleFunc("POST /api/admin/ldap/{provider_id}/test", h.requireMasterAdmin(h.handleTestLDAP))
	h.mux.HandleFunc("POST /api/admin/ldap/{provider_id}/setup-kerberos", h.requireMasterAdmin(h.handleSetupKerberos))
	h.mux.HandleFunc("POST /api/admin/ldap/{provider_id}/cleanup-kerberos", h.requireMasterAdmin(h.handleCleanupKerberos))
	h.mux.HandleFunc("GET /api/admin/kerberos/status", h.requireMasterAdmin(h.handleKerberosStatus))

	// Admin: Users
	h.mux.HandleFunc("GET /api/admin/users", h.requireMasterAdmin(h.handleListUsers))
	h.mux.HandleFunc("POST /api/admin/users", h.requireMasterAdmin(h.handleCreateUser))
	h.mux.HandleFunc("POST /api/admin/users/merge", h.requireMasterAdmin(h.handleMergeUsers))
	h.mux.HandleFunc("GET /api/admin/users/{guid}", h.requireMasterAdmin(h.handleGetUser))
	h.mux.HandleFunc("PUT /api/admin/users/{guid}", h.requireMasterAdmin(h.handleUpdateUser))
	h.mux.HandleFunc("DELETE /api/admin/users/{guid}", h.requireMasterAdmin(h.handleDeleteUser))
	h.mux.HandleFunc("PUT /api/admin/users/{guid}/password", h.requireMasterAdmin(h.handleSetPassword))
	h.mux.HandleFunc("PUT /api/admin/users/{guid}/disabled", h.requireMasterAdmin(h.handleSetDisabled))
	h.mux.HandleFunc("POST /api/admin/users/{guid}/unmerge", h.requireMasterAdmin(h.handleUnmergeUser))
	h.mux.HandleFunc("GET /api/admin/users/{guid}/sessions", h.requireMasterAdmin(h.handleListSessions))
	h.mux.HandleFunc("DELETE /api/admin/users/{guid}/sessions", h.requireMasterAdmin(h.handleRevokeSessions))
	h.mux.HandleFunc("POST /api/auth/reset-password", h.handleResetPassword)

	// Admin: Identity Mappings
	h.mux.HandleFunc("GET /api/admin/mappings", h.adminAuth(h.handleListAllMappings))
	h.mux.HandleFunc("GET /api/admin/users/{guid}/mappings", h.requireMasterAdmin(h.handleGetMappings))
	h.mux.HandleFunc("PUT /api/admin/users/{guid}/mappings", h.adminAuth(h.handleSetMapping))
	h.mux.HandleFunc("DELETE /api/admin/users/{guid}/mappings/{provider}/{external_id}", h.adminAuth(h.handleDeleteMapping))
	h.mux.HandleFunc("GET /api/admin/mappings/resolve", h.adminAuth(h.handleResolveMapping))

	// Admin: Roles & Permissions
	h.mux.HandleFunc("GET /api/admin/apps/{app_id}/users", h.adminAuth(h.handleListAppUsers))
	h.mux.HandleFunc("GET /api/admin/apps/{app_id}/users/{guid}/roles", h.adminAuth(h.handleGetRoles))
	h.mux.HandleFunc("PUT /api/admin/apps/{app_id}/users/{guid}/roles", h.adminAuth(h.handleSetRoles))
	h.mux.HandleFunc("GET /api/admin/apps/{app_id}/users/{guid}/permissions", h.adminAuth(h.handleGetPermissions))
	h.mux.HandleFunc("PUT /api/admin/apps/{app_id}/users/{guid}/permissions", h.adminAuth(h.handleSetPermissions))
	h.mux.HandleFunc("GET /api/admin/apps/{app_id}/defaults/roles", h.adminAuth(h.handleGetDefaultRoles))
	h.mux.HandleFunc("PUT /api/admin/apps/{app_id}/defaults/roles", h.adminAuth(h.handleSetDefaultRoles))

	// Admin: One-Time Tokens
	h.mux.HandleFunc("GET /api/admin/tokens", h.requireMasterAdmin(h.handleListTokens))
	h.mux.HandleFunc("POST /api/admin/tokens", h.requireMasterAdmin(h.handleCreateToken))
	h.mux.HandleFunc("DELETE /api/admin/tokens/{token}", h.requireMasterAdmin(h.handleDeleteToken))

	// Public: Self-Register with token
	h.mux.HandleFunc("POST /api/register", h.handleSelfRegister)

	// Admin: Backup/Restore
	h.mux.HandleFunc("GET /api/admin/backup", h.requireMasterAdmin(h.handleBackup))
	h.mux.HandleFunc("POST /api/admin/restore", h.requireMasterAdmin(h.handleRestore))

	// Admin: Audit Log
	h.mux.HandleFunc("GET /api/admin/audit", h.requireMasterAdmin(h.handleQueryAudit))

	// OIDC / Keycloak-compatible endpoints
	h.registerOIDCRoutes()

	// Hosted login page + UI
	if uiFS != nil {
		h.mux.Handle("GET /", http.FileServerFS(uiFS))
	}
}

// StartAuditPruner runs a background goroutine to clean old audit entries.
func (h *Handler) StartAuditPruner() {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		for range ticker.C {
			if err := h.store.PruneAuditLog(h.cfg.AuditRetention); err != nil {
				log.Printf("audit prune error: %v", err)
			}
		}
	}()
}

// --- Helpers ---

func jsonResp(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	jsonResp(w, map[string]string{"error": msg}, status)
}

func readJSON(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("empty request body")
	}
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func setContext(ctx context.Context, key contextKey, val string) context.Context {
	return context.WithValue(ctx, key, val)
}

func getContext(ctx context.Context, key contextKey) string {
	v, _ := ctx.Value(key).(string)
	return v
}

// checkAppScope verifies that an app API key can only manage its own app.
func (h *Handler) checkAppScope(r *http.Request, targetAppID string) bool {
	if getContext(r.Context(), ctxIsAdmin) == "true" {
		return true
	}
	callerAppID := getContext(r.Context(), ctxAppID)
	return callerAppID == targetAppID
}

func (h *Handler) audit(event, actor, ip string, data map[string]interface{}) {
	entry := &store.AuditEntry{
		Event: event,
		Actor: actor,
		IP:    ip,
		Data:  data,
	}
	if err := h.store.WriteAuditLog(entry); err != nil {
		log.Printf("audit log write error: %v", err)
	}
}

func ldapConfigFromProvider(p *store.LDAPProvider) *auth.LDAPConfig {
	return &auth.LDAPConfig{
		URL:             p.URL,
		BaseDN:          p.BaseDN,
		BindDN:          p.BindDN,
		BindPassword:    p.BindPassword,
		UserFilter:      p.UserFilter,
		UseTLS:          p.UseTLS,
		SkipTLSVerify:   p.SkipTLSVerify,
		DisplayNameAttr: p.DisplayNameAttr,
		EmailAttr:       p.EmailAttr,
		DepartmentAttr:  p.DepartmentAttr,
		CompanyAttr:     p.CompanyAttr,
		JobTitleAttr:    p.JobTitleAttr,
		GroupsAttr:      p.GroupsAttr,
	}
}

// pathParam extracts a path parameter. Go 1.22+ ServeMux supports {name} patterns.
func pathParam(r *http.Request, name string) string {
	return r.PathValue(name)
}

// trimProviderPrefix returns the provider portion from a mapping path.
// For paths like /api/admin/users/{guid}/mappings/{provider}/{external_id}
// where provider might contain colons (e.g., "app:chat-app").
func splitMappingPath(r *http.Request) (provider, externalID string) {
	provider = pathParam(r, "provider")
	externalID = pathParam(r, "external_id")
	// Handle the case where provider contains path separators by reconstructing
	path := r.URL.Path
	parts := strings.Split(path, "/mappings/")
	if len(parts) == 2 {
		remainder := parts[1]
		// Find the last slash to separate provider from external_id
		if idx := strings.LastIndex(remainder, "/"); idx >= 0 {
			provider = remainder[:idx]
			externalID = remainder[idx+1:]
		}
	}
	return
}
