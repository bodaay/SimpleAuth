package store

import "time"

// --- Data Types ---

type User struct {
	GUID         string `json:"guid"`
	PasswordHash string `json:"password_hash,omitempty"`
	DisplayName  string `json:"display_name"`
	GivenName    string `json:"given_name,omitempty"`
	FamilyName   string `json:"family_name,omitempty"`
	Email        string `json:"email"`
	Department   string `json:"department,omitempty"`
	Company      string `json:"company,omitempty"`
	JobTitle     string `json:"job_title,omitempty"`
	// SAMAccountName is the authoritative AD sAMAccountName, populated on every
	// successful LDAP or Kerberos authentication. Stable across UPN/email/
	// display-name changes in AD. Apps doing authn-only should key their
	// internal authz table on this field (via the JWT `samaccountname` claim)
	// rather than `email` or `preferred_username`.
	SAMAccountName string    `json:"sam_account_name,omitempty"`
	Disabled       bool      `json:"disabled"`
	MergedInto     string    `json:"merged_into,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	// OwnerAppID, when set, marks this as an app-LOCAL user owned by that app
	// (v2 M5): authenticated locally, only ever issued aud=owner-app tokens, and
	// never shared via cross-app SSO. Empty = a global directory user.
	OwnerAppID string `json:"owner_app_id,omitempty"`

	// Password security
	ForcePasswordChange bool       `json:"force_password_change,omitempty"`
	PasswordHistory     []string   `json:"password_history,omitempty"`
	FailedLoginAttempts int        `json:"failed_login_attempts,omitempty"`
	LockedUntil         *time.Time `json:"locked_until,omitempty"`

	// Groups holds the user's last-known directory group identifiers (refreshed
	// on each LDAP/Kerberos login). Used to resolve per-app group assignments at
	// token issuance (v2). Empty for local-only users.
	Groups []string `json:"groups,omitempty"`
}

// AppAuthz holds an app's per-app authorization data (v2): its role catalog,
// role→permission map, and user/group assignments. Keyed by app_id, managed by
// the app itself (or the master admin). All maps are role-lists keyed by the
// subject (user reference) or group identifier (sAMAccountName by default).
type AppAuthz struct {
	AppID            string              `json:"app_id"`
	Roles            []string            `json:"roles,omitempty"`
	Permissions      []string            `json:"permissions,omitempty"`
	RolePermissions  map[string][]string `json:"role_permissions,omitempty"`
	UserAssignments  map[string][]string `json:"user_assignments,omitempty"`
	GroupAssignments map[string][]string `json:"group_assignments,omitempty"`
}

// AppAdmin is a human user authorized to administer one app's self-service
// surface (its authz + app-local users) with their own login, instead of the
// app secret. Membership is stored as one row/entry per (AppID, UserGUID) — NOT
// inside the AppAuthz blob — so grants/revokes are atomic and the self-service
// authz writes can never clobber them. UserGUID is the strong, non-spoofable key
// (resolved at grant time); AddedBy records the granting principal for audit.
type AppAdmin struct {
	AppID    string    `json:"app_id"`
	UserGUID string    `json:"user_guid"`
	AddedBy  string    `json:"added_by"`
	AddedAt  time.Time `json:"added_at"`
}

type LDAPConfig struct {
	URL           string `json:"url"`
	BaseDN        string `json:"base_dn"`
	BindDN        string `json:"bind_dn"`
	BindPassword  string `json:"bind_password"`
	UsernameAttr  string `json:"username_attr"`
	CustomFilter  string `json:"custom_filter,omitempty"`
	UseTLS        bool   `json:"use_tls"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	// AllowInsecure permits binds over a cleartext ldap:// connection that could
	// not be upgraded with StartTLS. Default false: ldap:// is StartTLS-upgraded
	// and fails closed, so bind/user passwords are never sent in the clear.
	AllowInsecure   bool      `json:"allow_insecure,omitempty"`
	DisplayNameAttr string    `json:"display_name_attr"`
	EmailAttr       string    `json:"email_attr"`
	DepartmentAttr  string    `json:"department_attr"`
	CompanyAttr     string    `json:"company_attr"`
	JobTitleAttr    string    `json:"job_title_attr"`
	GroupsAttr      string    `json:"groups_attr"`
	Domain          string    `json:"domain,omitempty"`
	ConfiguredAt    time.Time `json:"configured_at"`

	// GivenNameAttr / FamilyNameAttr feed the OIDC given_name / family_name
	// claims. Empty means the AD defaults (givenName / sn), so deployments
	// configured before these existed pick them up without reconfiguration.
	GivenNameAttr  string `json:"given_name_attr,omitempty"`
	FamilyNameAttr string `json:"family_name_attr,omitempty"`
}

// App is a registered application (OAuth client) with its own per-app
// authorization scope (v2). The AppID partitions all per-app roles, permissions,
// and assignments; SecretHash authenticates the app for self-management and
// confidential token flows. SecretHash is never returned by the API.
type App struct {
	AppID             string    `json:"app_id"`
	Name              string    `json:"name"`
	Audience          string    `json:"audience"`
	SecretHash        string    `json:"secret_hash,omitempty"`
	RedirectURIs      []string  `json:"redirect_uris,omitempty"`
	CORSOrigins       []string  `json:"cors_origins,omitempty"`
	RequireAssignment bool      `json:"require_assignment"`
	AllowLocalUsers   bool      `json:"allow_local_users"`
	Disabled          bool      `json:"disabled,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	// SecretRotatedAt is set when the app secret is rotated; app-management tokens
	// issued before this instant are rejected so rotation revokes them (L4).
	SecretRotatedAt time.Time `json:"secret_rotated_at,omitempty"`

	// --- Presentation metadata (SA-1: the portal app-switcher / grid) ---
	// These are pure static data — never consulted by any token flow. SimpleAuth
	// stores and returns them but NEVER dereferences BaseURL (no manifest fetch,
	// no health check): it is a privileged host and must not be an SSRF vector.
	//
	// BaseURL is the module's canonical origin (absolute https, optional path
	// prefix, normalized without a trailing slash). Empty = a non-launchable app,
	// excluded from GET /api/user/apps.
	BaseURL string `json:"base_url,omitempty"`
	// DisplayName is a locale→name map (e.g. {"en":"Billing","ar":"..."}); "en"
	// is the expected default. Falls back to Name when a locale is absent.
	DisplayName map[string]string `json:"display_name,omitempty"`
	// Category is an opaque grouping string for the portal (taxonomy enforced by
	// the portal, not here).
	Category string `json:"category,omitempty"`
	// Icon is a RELATIVE path resolved under BaseURL (never inline bytes — the App
	// is deserialized on every login/refresh/authorize, and serving bytes from the
	// IdP origin is a stored-XSS surface). SA-2 returns the computed absolute URL.
	Icon string `json:"icon,omitempty"`
}

type IdentityMapping struct {
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
}

type IdentityMappingEntry struct {
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
	UserGUID   string `json:"user_guid"`
}

type RefreshToken struct {
	TokenID   string    `json:"token_id"`
	FamilyID  string    `json:"family_id"`
	UserGUID  string    `json:"user_guid"`
	Used      bool      `json:"used"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	// AppID/Audience bind the token family to one app (v2). A refresh token for
	// app A only ever mints app-A access tokens (aud = Audience).
	AppID    string `json:"app_id,omitempty"`
	Audience string `json:"audience,omitempty"`
}

type AuditEntry struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Event     string                 `json:"event"`
	Actor     string                 `json:"actor"`
	IP        string                 `json:"ip"`
	Data      map[string]interface{} `json:"data"`
}

type AuditQuery struct {
	Event  string
	UserID string
	From   time.Time
	To     time.Time
	Limit  int
	Offset int
}

type OIDCAuthCode struct {
	Code        string `json:"code"`
	UserGUID    string `json:"user_guid"`
	AppID       string `json:"app_id,omitempty"` // resolved from client_id at authorize (v2)
	RedirectURI string `json:"redirect_uri"`
	Scope       string `json:"scope"`
	Nonce       string `json:"nonce"`
	// PKCE (RFC 7636) — set when the client supplied a code_challenge on the
	// authorize request. When present, the token exchange must present a
	// matching code_verifier.
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
}

// DatabaseInfo holds stats about the active database backend.
type DatabaseInfo struct {
	Backend         string      `json:"backend"` // "boltdb" or "postgres"
	SizeMB          float64     `json:"size_mb"`
	Tables          int         `json:"tables"`
	TotalRows       int64       `json:"total_rows"`
	TableDetails    []TableInfo `json:"table_details"`
	Health          string      `json:"health"` // "healthy", "degraded", "error"
	Version         string      `json:"version,omitempty"`
	MaxConnections  int         `json:"max_connections,omitempty"`
	OpenConnections int         `json:"open_connections,omitempty"`
	InUse           int         `json:"in_use_connections,omitempty"`
	Idle            int         `json:"idle_connections,omitempty"`
}

// TableInfo holds per-table stats.
type TableInfo struct {
	Name   string  `json:"name"`
	Rows   int64   `json:"rows"`
	SizeMB float64 `json:"size_mb,omitempty"`
}

// Session represents an active SSO session cookie.
// When EnableSessionSSO is on, a valid session cookie lets the user
// auto-authenticate to any app redirecting to SimpleAuth.
type Session struct {
	ID         string    `json:"id"`
	UserGUID   string    `json:"user_guid"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"` // absolute max (hard limit)
	UserAgent  string    `json:"user_agent,omitempty"`
	IP         string    `json:"ip,omitempty"`
}

// RuntimeSettings holds configuration managed via the Admin UI.
// Stored in the DB config bucket under "runtime_settings".
type RuntimeSettings struct {
	DeploymentName           string   `json:"deployment_name"`
	RedirectURIs             []string `json:"redirect_uris"`
	CORSOrigins              string   `json:"cors_origins"`
	PasswordMinLength        int      `json:"password_min_length"`
	PasswordRequireUppercase bool     `json:"password_require_uppercase"`
	PasswordRequireLowercase bool     `json:"password_require_lowercase"`
	PasswordRequireDigit     bool     `json:"password_require_digit"`
	PasswordRequireSpecial   bool     `json:"password_require_special"`
	PasswordHistoryCount     int      `json:"password_history_count"`
	AccountLockoutThreshold  int      `json:"account_lockout_threshold"`
	AccountLockoutDurationS  int      `json:"account_lockout_duration_s"` // seconds
	DefaultRoles             []string `json:"default_roles"`
	RateLimitMax             int      `json:"rate_limit_max"`
	RateLimitWindowS         int      `json:"rate_limit_window_s"` // seconds
	RateLimitDisabled        bool     `json:"rate_limit_disabled"` // zero value keeps the limiter ON — only an explicit true turns it off (F25)
	AuditRetentionDays       int      `json:"audit_retention_days"`
	AutoSSO                  bool     `json:"auto_sso"`
	AutoSSODelay             int      `json:"auto_sso_delay"` // seconds, default 3
	EnableSessionSSO         bool     `json:"enable_session_sso"`
	SessionSSOIdleHours      int      `json:"session_sso_idle_hours"` // default 8
	SessionSSOMaxHours       int      `json:"session_sso_max_hours"`  // default 720 (30 days)
	// What to do with directory (AD) users when the AD account-status check
	// can't reach LDAP: "grace" (default; empty means grace), "block", or "allow".
	DirectoryOutagePolicy     string `json:"directory_outage_policy"`
	DirectoryOutageGraceHours int    `json:"directory_outage_grace_hours"` // grace window; default 10 (AD default ticket lifetime)
	Version                   int    `json:"version"`                      // optimistic-concurrency token: PUT echoes it, the server bumps it; 0 = client sent none (legacy last-writer-wins)
}
