package store

import "time"

// --- Data Types ---

type User struct {
	GUID         string    `json:"guid"`
	PasswordHash string    `json:"password_hash,omitempty"`
	DisplayName  string    `json:"display_name"`
	Email        string    `json:"email"`
	Department   string    `json:"department,omitempty"`
	Company      string    `json:"company,omitempty"`
	JobTitle     string    `json:"job_title,omitempty"`
	Disabled     bool      `json:"disabled"`
	MergedInto   string    `json:"merged_into,omitempty"`
	CreatedAt    time.Time `json:"created_at"`

	// Password security
	ForcePasswordChange bool       `json:"force_password_change,omitempty"`
	PasswordHistory     []string   `json:"password_history,omitempty"`
	FailedLoginAttempts int        `json:"failed_login_attempts,omitempty"`
	LockedUntil         *time.Time `json:"locked_until,omitempty"`
}

type LDAPConfig struct {
	URL             string    `json:"url"`
	BaseDN          string    `json:"base_dn"`
	BindDN          string    `json:"bind_dn"`
	BindPassword    string    `json:"bind_password"`
	UsernameAttr    string    `json:"username_attr"`
	CustomFilter    string    `json:"custom_filter,omitempty"`
	UseTLS          bool      `json:"use_tls"`
	SkipTLSVerify   bool      `json:"skip_tls_verify"`
	DisplayNameAttr string    `json:"display_name_attr"`
	EmailAttr       string    `json:"email_attr"`
	DepartmentAttr  string    `json:"department_attr"`
	CompanyAttr     string    `json:"company_attr"`
	JobTitleAttr    string    `json:"job_title_attr"`
	GroupsAttr      string    `json:"groups_attr"`
	Domain          string    `json:"domain,omitempty"`
	ConfiguredAt    time.Time `json:"configured_at"`
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
	Code        string    `json:"code"`
	UserGUID    string    `json:"user_guid"`
	RedirectURI string    `json:"redirect_uri"`
	Scope       string    `json:"scope"`
	Nonce       string    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// DatabaseInfo holds stats about the active database backend.
type DatabaseInfo struct {
	Backend         string      `json:"backend"`          // "boltdb" or "postgres"
	SizeMB          float64     `json:"size_mb"`
	Tables          int         `json:"tables"`
	TotalRows       int64       `json:"total_rows"`
	TableDetails    []TableInfo `json:"table_details"`
	Health          string      `json:"health"`           // "healthy", "degraded", "error"
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

// RuntimeSettings holds configuration managed via the Admin UI.
// Stored in the DB config bucket under "runtime_settings".
type RuntimeSettings struct {
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
	AuditRetentionDays       int      `json:"audit_retention_days"`
}
