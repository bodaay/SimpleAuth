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
	"sync"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/config"
	"simpleauth/internal/store"
)

type Handler struct {
	cfg             *config.Config
	store           store.Store
	jwt             *auth.JWTManager
	loginLimiter    *rateLimiter
	mux             *http.ServeMux
	version         string
	migration       *migrationState
	runtimeSettings runtimeSettingsCache
	restartCh       chan<- struct{}
	// secretKey is the AES-256 data key for encrypting secrets at rest (e.g.
	// the LDAP bind password). Loaded from <data_dir>/secret.key. May be nil if
	// the key could not be loaded; legacy plaintext still reads in that case.
	secretKey []byte
	// localUserMu serializes app-local user provisioning so the existence check
	// and the create+mapping are atomic (L3).
	localUserMu sync.Mutex
	// migrationMu serializes a migration commit's token-claim + Apply + consume so
	// the single-use token cannot be raced into a double import.
	migrationMu sync.Mutex
	// settingsMu serializes a settings PUT's version-check + save + cache-set +
	// limiter-apply so concurrent updates cannot leave the store, the cache, and
	// the live rate limiter with different states.
	settingsMu sync.Mutex
	// dirChecked caches each user's last successful AD account-status check
	// (guid -> time.Time); persisted as config value "dircheck:<guid>" so the
	// AD-outage grace window survives restarts.
	dirChecked sync.Map
}

func New(cfg *config.Config, s store.Store, jwtMgr *auth.JWTManager, uiFS fs.FS, version string) *Handler {
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

	// Load (or create) the at-rest encryption key for secrets like the LDAP
	// bind password (H4). Best-effort: on failure, log and continue — legacy
	// plaintext still reads, and new saves will surface the error.
	if key, err := loadOrCreateSecretKey(cfg.DataDir); err != nil {
		log.Printf("[secrets] could not load %s: %v — secrets at rest disabled", secretKeyFile, err)
	} else {
		h.secretKey = key
	}

	h.initMigrationState()
	h.initRuntimeSettings()
	h.registerRoutes(uiFS)
	return h
}

// SetRestartChannel sets the channel used to trigger graceful restarts.
func (h *Handler) SetRestartChannel(ch chan<- struct{}) {
	h.restartCh = ch
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-SimpleAuth-Version", h.version)
	// Baseline security headers on every response (M8). The admin UI sets a
	// stricter CSP of its own; these are the safe global defaults. Frame
	// protection is part of the baseline so login / OIDC / account pages — not
	// just the admin UI — cannot be framed for clickjacking (M8 was incomplete).
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	corsOrigins := h.getCORSOrigins()
	if corsOrigins != "" {
		origin := r.Header.Get("Origin")
		if corsOrigins == "*" {
			// Public wildcard: emit a literal "*" rather than reflecting the
			// caller's Origin. Reflecting an arbitrary origin invites a
			// credentialed cross-site read; the literal "*" cannot be combined
			// with credentials by the browser, so it fails safe (F64).
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "86400")
		} else if origin != "" && h.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
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
	cors := h.getCORSOrigins()
	if cors == "*" {
		return true
	}
	for _, allowed := range strings.Split(cors, ",") {
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
	// User self-service (authenticated by the user's own access token, any audience)
	h.mux.HandleFunc("GET /api/user/apps", h.handleUserApps)
	h.mux.HandleFunc("POST /api/user/logout-all", h.handleUserLogoutAll)
	h.mux.HandleFunc("GET /api/user/preferences", h.handleGetUserPreferences)
	h.mux.HandleFunc("PUT /api/user/preferences", h.handleSetUserPreferences)
	h.mux.HandleFunc("POST /api/auth/impersonate", h.requireMasterAdmin(h.handleImpersonate))
	h.mux.HandleFunc("GET /api/auth/negotiate", h.handleNegotiate)
	// Diagnostic Kerberos/LDAP test pages — unauthenticated and perform live
	// LDAP binds (a password oracle), so gated behind an explicit flag
	// (default off; H1). Enable with AUTH_ENABLE_TEST_ENDPOINTS=true.
	if h.cfg.EnableTestEndpoints {
		h.mux.HandleFunc("GET /test-negotiate", h.handleNegotiateTest)
		h.mux.HandleFunc("POST /test-negotiate", h.handleNegotiateTestForm)
	}

	// Root redirect
	h.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, h.url("/login"), http.StatusFound)
	})

	// Hosted login page
	h.mux.HandleFunc("GET /login", h.handleHostedLoginPage)
	h.mux.HandleFunc("GET /logout", h.handleLogout)
	h.mux.HandleFunc("POST /login", h.handleHostedLoginSubmit)
	h.mux.HandleFunc("GET /login/sso", h.handleSSOLogin)

	// User self-service account page
	h.mux.HandleFunc("GET /account", h.handleAccountPage)

	// JWKS
	h.mux.HandleFunc("GET /.well-known/jwks.json", h.handleJWKS)

	// Health & Server Info
	h.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]string{"status": "ok", "version": h.version}, http.StatusOK)
	})
	h.mux.HandleFunc("GET /api/admin/server-info", h.requireMasterAdmin(func(w http.ResponseWriter, r *http.Request) {
		jsonResp(w, map[string]interface{}{
			"hostname":        h.cfg.Hostname,
			"deployment_name": h.getDeploymentName(),
			"jwt_issuer":      h.cfg.JWTIssuer,
			"version":         h.version,
			"redirect_uri":    h.getDefaultRedirectURI(),
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
	h.mux.HandleFunc("GET /api/admin/linux-setup-script", h.requireMasterAdmin(h.handleLinuxSetupScript))
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
	h.mux.HandleFunc("PUT /api/admin/permissions", h.requireMasterAdmin(h.handleSetDefinedPermissions))

	// Admin: Apps (v2 per-app authorization — registry)
	h.mux.HandleFunc("POST /api/admin/apps", h.requireMasterAdmin(h.handleCreateApp))
	h.mux.HandleFunc("GET /api/admin/apps", h.requireMasterAdmin(h.handleListApps))
	h.mux.HandleFunc("GET /api/admin/apps/{app_id}", h.requireMasterAdmin(h.handleGetApp))
	h.mux.HandleFunc("PUT /api/admin/apps/{app_id}", h.requireMasterAdmin(h.handleUpdateApp))
	h.mux.HandleFunc("DELETE /api/admin/apps/{app_id}", h.requireMasterAdmin(h.handleDeleteApp))
	h.mux.HandleFunc("POST /api/admin/apps/{app_id}/rotate-secret", h.requireMasterAdmin(h.handleRotateAppSecret))
	h.mux.HandleFunc("GET /api/admin/apps/{app_id}/authz", h.requireMasterAdmin(h.handleGetAppAuthz))
	h.mux.HandleFunc("PUT /api/admin/apps/{app_id}/authz", h.requireMasterAdmin(h.handleSetAppAuthz))
	// Standalone->central migration: a master mints a single-use token on the
	// target app; the standalone uses it to authenticate the cross-install
	// preflight/commit (those are token-authed, not master-key/session authed).
	h.mux.HandleFunc("POST /api/admin/apps/{app_id}/migration-token", h.requireMasterAdmin(h.handleGenMigrationToken))
	h.mux.HandleFunc("POST /api/migration/preflight", h.handleMigrationPreflight)
	h.mux.HandleFunc("POST /api/migration/commit", h.handleMigrationCommit)
	// Standalone side: package this deployment and push it to a central app.
	h.mux.HandleFunc("POST /api/admin/migrate-to-central/preflight", h.requireMasterAdmin(h.handleMigrateToCentralPreflight))
	h.mux.HandleFunc("POST /api/admin/migrate-to-central/commit", h.requireMasterAdmin(h.handleMigrateToCentralCommit))
	// Per-app admins (human users who manage an app with their own login).
	h.mux.HandleFunc("GET /api/admin/apps/{app_id}/admins", h.requireMasterAdmin(h.handleListAppAdminsMaster))
	h.mux.HandleFunc("POST /api/admin/apps/{app_id}/admins", h.requireMasterAdmin(h.handleAddAppAdminMaster))
	h.mux.HandleFunc("DELETE /api/admin/apps/{app_id}/admins/{user}", h.requireMasterAdmin(h.handleRemoveAppAdminMaster))

	// App self-service (v2) — authed by app_id/app_secret (Basic) or an
	// app-management token from POST /api/app/token. Scoped to the calling app.
	h.mux.HandleFunc("POST /api/app/token", h.handleAppToken)
	h.mux.HandleFunc("POST /api/app/bootstrap", h.requireApp(h.handleAppBootstrap))
	h.mux.HandleFunc("GET /api/app/authz", h.requireApp(h.handleGetOwnAuthz))
	h.mux.HandleFunc("PUT /api/app/authz", h.requireApp(h.handleSetOwnAuthz))
	h.mux.HandleFunc("GET /api/app/settings", h.requireApp(h.handleAppSettings))
	// App-local users (v2 M5) — provisioning, gated by allow_local_users.
	h.mux.HandleFunc("POST /api/app/users", h.requireApp(h.handleCreateLocalUser))
	h.mux.HandleFunc("GET /api/app/users", h.requireApp(h.handleListLocalUsers))
	h.mux.HandleFunc("DELETE /api/app/users/{guid}", h.requireApp(h.handleDeleteLocalUser))
	h.mux.HandleFunc("PUT /api/app/users/{guid}/password", h.requireApp(h.handleSetLocalUserPassword))
	// App admins — only the app-secret holder (here) or the master admin may
	// add/remove them (a per-app admin themselves cannot, by decision).
	h.mux.HandleFunc("GET /api/app/admins", h.requireApp(h.handleListOwnAdmins))
	h.mux.HandleFunc("POST /api/app/admins", h.requireApp(h.handleAddOwnAdmin))
	h.mux.HandleFunc("DELETE /api/app/admins/{user}", h.requireApp(h.handleRemoveOwnAdmin))

	// Per-app admin surface (v2): a human app admin manages an app with their OWN
	// login. Per-app login model — the app is the one the caller logged into
	// (token Azp), not a path parameter, so a token can only manage its own app.
	// Reuses the self-service handlers — requireAppAdmin sets app_id in context
	// from the token. Separate /api/app-admin/ prefix keeps it off the
	// credential-scoped /api/app/ surface.
	h.mux.HandleFunc("GET /api/app-admin/authz", h.requireAppAdmin(h.handleGetOwnAuthz))
	h.mux.HandleFunc("PUT /api/app-admin/authz", h.requireAppAdmin(h.handleSetOwnAuthz))
	h.mux.HandleFunc("POST /api/app-admin/bootstrap", h.requireAppAdmin(h.handleAppBootstrap))
	h.mux.HandleFunc("GET /api/app-admin/settings", h.requireAppAdmin(h.handleAppSettings))
	h.mux.HandleFunc("POST /api/app-admin/users", h.requireAppAdmin(h.handleCreateLocalUser))
	h.mux.HandleFunc("GET /api/app-admin/users", h.requireAppAdmin(h.handleListLocalUsers))
	h.mux.HandleFunc("DELETE /api/app-admin/users/{guid}", h.requireAppAdmin(h.handleDeleteLocalUser))
	h.mux.HandleFunc("PUT /api/app-admin/users/{guid}/password", h.requireAppAdmin(h.handleSetLocalUserPassword))

	// Admin: Bootstrap
	h.mux.HandleFunc("POST /api/admin/bootstrap", h.requireMasterAdmin(h.handleBootstrap))

	// Admin: Password Policy & Account Unlock
	h.mux.HandleFunc("GET /api/admin/password-policy", h.requireMasterAdmin(h.handleGetPasswordPolicy))
	h.mux.HandleFunc("PUT /api/admin/users/{guid}/unlock", h.requireMasterAdmin(h.handleUnlockAccount))

	// Admin: Restart
	h.mux.HandleFunc("POST /api/admin/restart", h.requireMasterAdmin(h.handleRestart))

	// Admin: Settings (runtime config)
	h.mux.HandleFunc("GET /api/admin/settings", h.requireMasterAdmin(h.handleGetSettings))
	h.mux.HandleFunc("PUT /api/admin/settings", h.requireMasterAdmin(h.handleUpdateSettings))

	// Admin: Database / Migration
	h.mux.HandleFunc("GET /api/admin/database/info", h.requireMasterAdmin(h.handleDatabaseInfo))
	h.mux.HandleFunc("POST /api/admin/database/test", h.requireMasterAdmin(h.handleMigrateTest))
	h.mux.HandleFunc("POST /api/admin/database/migrate", h.requireMasterAdmin(h.handleMigrateStart))
	h.mux.HandleFunc("GET /api/admin/database/migrate/status", h.requireMasterAdmin(h.handleMigrateStatus))
	h.mux.HandleFunc("POST /api/admin/database/switch", h.requireMasterAdmin(h.handleSwitchBackend))

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
		setAdminHeaders := func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "no-referrer")
		}
		h.mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
			if indexData != nil {
				setAdminHeaders(w)
				w.Write(indexData)
				return
			}
			http.Redirect(w, r, h.url("/admin/"), http.StatusMovedPermanently)
		})
		h.mux.HandleFunc("GET /admin/{path...}", func(w http.ResponseWriter, r *http.Request) {
			p := r.PathValue("path")
			if p == "" || p == "index.html" {
				if indexData != nil {
					setAdminHeaders(w)
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

// StartAuditPruner runs a background goroutine that prunes audit entries and
// expired sessions/revocations/refresh-tokens hourly. It returns when stop is
// closed, so the caller can tear it down on graceful restart instead of leaking
// one pruner goroutine (still referencing the now-closed store) per restart.
func (h *Handler) StartAuditPruner(stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := h.store.PruneAuditLog(h.getAuditRetention()); err != nil {
					log.Printf("audit prune error: %v", err)
				}
				if err := h.store.CleanExpiredRevocations(); err != nil {
					log.Printf("revocation cleanup error: %v", err)
				}
				if err := h.store.CleanExpiredSessions(); err != nil {
					log.Printf("session cleanup error: %v", err)
				}
				if err := h.store.CleanExpiredRefreshTokens(); err != nil {
					log.Printf("refresh-token cleanup error: %v", err)
				}
				if err := h.store.CleanExpiredOIDCCodes(); err != nil {
					log.Printf("oidc-code cleanup error: %v", err)
				}
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

// auditLogin logs a login event enriched with user identity fields.
func (h *Handler) auditLogin(user *store.User, ip string, extra map[string]interface{}) {
	data := map[string]interface{}{
		"username":     h.resolvePreferredUsername(user),
		"display_name": user.DisplayName,
		"email":        user.Email,
	}
	for k, v := range extra {
		data[k] = v
	}
	h.audit("login_success", user.GUID, ip, data)
}

func ldapConfigFromStore(p *store.LDAPConfig) *auth.LDAPConfig {
	givenNameAttr, familyNameAttr := p.GivenNameAttr, p.FamilyNameAttr
	if givenNameAttr == "" {
		givenNameAttr = "givenName"
	}
	if familyNameAttr == "" {
		familyNameAttr = "sn"
	}
	return &auth.LDAPConfig{
		URL:             p.URL,
		BaseDN:          p.BaseDN,
		BindDN:          p.BindDN,
		BindPassword:    p.BindPassword,
		UsernameAttr:    p.UsernameAttr,
		CustomFilter:    p.CustomFilter,
		UseTLS:          p.UseTLS,
		SkipTLSVerify:   p.SkipTLSVerify,
		AllowInsecure:   p.AllowInsecure,
		DisplayNameAttr: p.DisplayNameAttr,
		EmailAttr:       p.EmailAttr,
		DepartmentAttr:  p.DepartmentAttr,
		CompanyAttr:     p.CompanyAttr,
		JobTitleAttr:    p.JobTitleAttr,
		GroupsAttr:      p.GroupsAttr,
		GivenNameAttr:   givenNameAttr,
		FamilyNameAttr:  familyNameAttr,
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
