package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
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
	version     string
}

func New(cfg *config.Config, s *store.Store, jwtMgr *auth.JWTManager, uiFS fs.FS, version string) *Handler {
	h := &Handler{
		cfg:          cfg,
		store:        s,
		jwt:          jwtMgr,
		loginLimiter: newRateLimiter(cfg.RateLimitMax, cfg.RateLimitWindow),
		mux:          http.NewServeMux(),
		version:      version,
	}
	// Set trusted proxy CIDRs for getClientIP
	trustedCIDRs = cfg.TrustedProxyCIDRs

	h.registerRoutes(uiFS)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-SimpleAuth-Version", h.version)
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

	// Strip base path prefix from incoming requests
	if bp := h.cfg.BasePath; bp != "" {
		p := r.URL.Path
		if p == bp || strings.HasPrefix(p, bp+"/") {
			r2 := new(http.Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.URL.Path = p[len(bp):]
			if r2.URL.Path == "" {
				r2.URL.Path = "/"
			}
			r = r2
		} else {
			http.NotFound(w, r)
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

// url returns a path prefixed with the configured base path.
func (h *Handler) url(path string) string {
	return h.cfg.BasePath + path
}

// bp replaces {{BASE_PATH}} markers in HTML templates with the configured base path.
func (h *Handler) bp(tmpl string) string {
	return strings.ReplaceAll(tmpl, "{{BASE_PATH}}", h.cfg.BasePath)
}

func (h *Handler) registerRoutes(uiFS fs.FS) {
	// Auth endpoints
	h.mux.HandleFunc("POST /api/auth/login", h.handleLogin)
	h.mux.HandleFunc("POST /api/auth/refresh", h.handleRefresh)
	h.mux.HandleFunc("GET /api/auth/userinfo", h.handleUserInfo)
	h.mux.HandleFunc("POST /api/auth/impersonate", h.requireMasterAdmin(h.handleImpersonate))
	h.mux.HandleFunc("GET /api/auth/negotiate", h.handleNegotiate)
	h.mux.HandleFunc("GET /test-negotiate", h.handleNegotiateTest)
	h.mux.HandleFunc("POST /test-negotiate", h.handleNegotiateTestForm)

	// Root redirect
	h.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, h.url("/login"), http.StatusFound)
	})

	// Hosted login page
	h.mux.HandleFunc("GET /login", h.handleHostedLoginPage)
	h.mux.HandleFunc("POST /login", h.handleHostedLoginSubmit)
	h.mux.HandleFunc("GET /login/sso", h.handleSSOLogin)

	// User self-service account page
	h.mux.HandleFunc("GET /account", h.handleAccountPage)

	// JWKS
	h.mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)

	// Health & Server Info
	h.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]string{"status": "ok"}, http.StatusOK)
	})
	h.mux.HandleFunc("GET /api/admin/server-info", h.requireMasterAdmin(func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{
			"hostname":        h.cfg.Hostname,
			"deployment_name": h.cfg.DeploymentName,
			"jwt_issuer":      h.cfg.JWTIssuer,
			"version":         h.version,
			"redirect_uri":    h.cfg.RedirectURI,
		}, http.StatusOK)
	}))

	// Admin: LDAP Config (single)
	h.mux.HandleFunc("GET /api/admin/ldap", h.requireMasterAdmin(h.handleGetLDAPConfig))
	h.mux.HandleFunc("PUT /api/admin/ldap", h.requireMasterAdmin(h.handleSaveLDAPConfig))
	h.mux.HandleFunc("DELETE /api/admin/ldap", h.requireMasterAdmin(h.handleDeleteLDAPConfig))
	h.mux.HandleFunc("POST /api/admin/ldap/test", h.requireMasterAdmin(h.handleTestLDAPConfig))
	h.mux.HandleFunc("POST /api/admin/ldap/test-user", h.requireMasterAdmin(h.handleTestLDAPUser))
	h.mux.HandleFunc("POST /api/admin/ldap/auto-discover", h.requireMasterAdmin(h.handleAutoDiscoverLDAP))
	h.mux.HandleFunc("POST /api/admin/ldap/import", h.requireMasterAdmin(h.handleImportLDAP))
	h.mux.HandleFunc("POST /api/admin/ldap/search-users", h.requireMasterAdmin(h.handleSearchLDAPUsers))
	h.mux.HandleFunc("POST /api/admin/ldap/import-users", h.requireMasterAdmin(h.handleImportLDAPUsers))
	h.mux.HandleFunc("POST /api/admin/ldap/setup-kerberos", h.requireMasterAdmin(h.handleSetupKerberos))
	h.mux.HandleFunc("POST /api/admin/ldap/cleanup-kerberos", h.requireMasterAdmin(h.handleCleanupKerberos))
	h.mux.HandleFunc("POST /api/admin/ldap/sync-user", h.requireMasterAdmin(h.handleSyncUser))
	h.mux.HandleFunc("POST /api/admin/ldap/sync-all", h.requireMasterAdmin(h.handleSyncAll))
	h.mux.HandleFunc("GET /api/admin/setup-script", h.requireMasterAdmin(h.handleSetupScript))
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
	h.mux.HandleFunc("GET /api/admin/mappings", h.requireMasterAdmin(h.handleListAllMappings))
	h.mux.HandleFunc("GET /api/admin/users/{guid}/mappings", h.requireMasterAdmin(h.handleGetMappings))
	h.mux.HandleFunc("PUT /api/admin/users/{guid}/mappings", h.requireMasterAdmin(h.handleSetMapping))
	h.mux.HandleFunc("DELETE /api/admin/users/{guid}/mappings/{provider}/{external_id}", h.requireMasterAdmin(h.handleDeleteMapping))
	h.mux.HandleFunc("GET /api/admin/mappings/resolve", h.requireMasterAdmin(h.handleResolveMapping))

	// Admin: Roles & Permissions
	h.mux.HandleFunc("GET /api/admin/users/{guid}/roles", h.requireMasterAdmin(h.handleGetRoles))
	h.mux.HandleFunc("PUT /api/admin/users/{guid}/roles", h.requireMasterAdmin(h.handleSetRoles))
	h.mux.HandleFunc("GET /api/admin/users/{guid}/permissions", h.requireMasterAdmin(h.handleGetPermissions))
	h.mux.HandleFunc("PUT /api/admin/users/{guid}/permissions", h.requireMasterAdmin(h.handleSetPermissions))
	h.mux.HandleFunc("GET /api/admin/defaults/roles", h.requireMasterAdmin(h.handleGetDefaultRoles))
	h.mux.HandleFunc("PUT /api/admin/defaults/roles", h.requireMasterAdmin(h.handleSetDefaultRoles))
	h.mux.HandleFunc("GET /api/admin/role-permissions", h.requireMasterAdmin(h.handleGetRolePermissions))
	h.mux.HandleFunc("PUT /api/admin/role-permissions", h.requireMasterAdmin(h.handleSetRolePermissions))
	h.mux.HandleFunc("GET /api/admin/roles", h.requireMasterAdmin(h.handleListAllRoles))
	h.mux.HandleFunc("GET /api/admin/permissions", h.requireMasterAdmin(h.handleListAllPermissions))

	// Admin: Password Policy & Account Unlock
	h.mux.HandleFunc("GET /api/admin/password-policy", h.requireMasterAdmin(h.handleGetPasswordPolicy))
	h.mux.HandleFunc("PUT /api/admin/users/{guid}/unlock", h.requireMasterAdmin(h.handleUnlockAccount))

	// Admin: Backup/Restore
	h.mux.HandleFunc("GET /api/admin/backup", h.requireMasterAdmin(h.handleBackup))
	h.mux.HandleFunc("POST /api/admin/restore", h.requireMasterAdmin(h.handleRestore))

	// Admin: Audit Log
	h.mux.HandleFunc("GET /api/admin/audit", h.requireMasterAdmin(h.handleQueryAudit))

	// OIDC / Keycloak-compatible endpoints
	h.registerOIDCRoutes()

	// Admin UI at /admin
	if uiFS != nil {
		// Pre-process index.html to inject __BASE_PATH__ and rewrite asset paths
		indexData, _ := fs.ReadFile(uiFS, "index.html")
		if indexData != nil {
			content := string(indexData)
			bp := h.cfg.BasePath
			injection := fmt.Sprintf("<script>window.__BASE_PATH__=%q;</script>", bp)
			content = strings.Replace(content, "<head>", "<head>\n  "+injection, 1)
			// Always rewrite asset paths to include /admin prefix
			adminPrefix := bp + "/admin"
			content = strings.ReplaceAll(content, `href="/`, `href="`+adminPrefix+`/`)
			content = strings.ReplaceAll(content, `src="/`, `src="`+adminPrefix+`/`)
			content = strings.ReplaceAll(content, `"/vendor/`, `"`+adminPrefix+`/vendor/`)
			indexData = []byte(content)
		}

		fileServer := http.FileServerFS(uiFS)
		h.mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
			if indexData != nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(indexData)
				return
			}
			http.Redirect(w, r, h.url("/admin/"), http.StatusMovedPermanently)
		})
		h.mux.HandleFunc("GET /admin/{path...}", func(w http.ResponseWriter, r *http.Request) {
			p := r.PathValue("path")
			if p == "" || p == "index.html" {
				if indexData != nil {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Write(indexData)
					return
				}
			}
			// Strip /admin/ prefix so the file server finds the file in the embedded FS
			r2 := new(http.Request)
			*r2 = *r
			r2.URL = new(url.URL)
			*r2.URL = *r.URL
			r2.URL.Path = "/" + p
			fileServer.ServeHTTP(w, r2)
		})
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

func ldapConfigFromStore(p *store.LDAPConfig) *auth.LDAPConfig {
	return &auth.LDAPConfig{
		URL:             p.URL,
		BaseDN:          p.BaseDN,
		BindDN:          p.BindDN,
		BindPassword:    p.BindPassword,
		UsernameAttr:    p.UsernameAttr,
		CustomFilter:    p.CustomFilter,
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
