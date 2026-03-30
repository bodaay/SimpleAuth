package store

import (
	"io"
	"time"
)

// Store defines the storage interface for SimpleAuth. Both BoltDB and
// PostgreSQL backends implement this interface.
type Store interface {
	Close() error

	// Users
	CreateUser(u *User) error
	GetUser(guid string) (*User, error)
	ResolveUser(guid string) (*User, error)
	UpdateUser(u *User) error
	DeleteUser(guid string) error
	ListUsers() ([]*User, error)
	MergeUsers(sourceGUIDs []string, displayName, email string) (*User, error)
	UnmergeUser(guid string) error

	// LDAP Config
	GetLDAPConfig() (*LDAPConfig, error)
	SaveLDAPConfig(cfg *LDAPConfig) error
	DeleteLDAPConfig() error

	// Identity Mappings
	SetIdentityMapping(provider, externalID, userGUID string) error
	ResolveMapping(provider, externalID string) (string, error)
	DeleteIdentityMapping(provider, externalID string) error
	GetMappingsForUser(userGUID string) ([]IdentityMapping, error)
	ListAllMappings() ([]IdentityMappingEntry, error)

	// Roles & Permissions
	SetUserRoles(guid string, roles []string) error
	GetUserRoles(guid string) ([]string, error)
	SetUserPermissions(guid string, perms []string) error
	GetUserPermissions(guid string) ([]string, error)
	ListAllRoles() ([]string, error)
	ListAllPermissions() ([]string, error)
	GetDefaultRoles() ([]string, error)
	SetDefaultRoles(roles []string) error
	GetRolePermissions() (map[string][]string, error)
	SetRolePermissions(mapping map[string][]string) error
	RoleExists(role string) (bool, error)
	GetDefinedPermissions() ([]string, error)
	SetDefinedPermissions(perms []string) error
	PermissionExists(perm string) (bool, error)
	ValidateRolesExist(roles []string) (string, error)
	ValidatePermissionsExist(perms []string) (string, error)
	ResolvePermissions(roles, directPerms []string) ([]string, error)

	// Config key-value
	SetConfigValue(key string, value []byte) error
	GetConfigValue(key string) ([]byte, error)
	DeleteConfigValue(key string) error

	// Refresh Tokens
	SaveRefreshToken(rt *RefreshToken) error
	GetRefreshToken(tokenID string) (*RefreshToken, error)
	MarkRefreshTokenUsed(tokenID string) error
	RevokeTokenFamily(familyID string) error
	ListUserSessions(userGUID string) ([]*RefreshToken, error)
	RevokeUserTokens(userGUID string) error

	// Audit Log
	WriteAuditLog(entry *AuditEntry) error
	QueryAuditLog(q AuditQuery) ([]*AuditEntry, error)
	PruneAuditLog(retention time.Duration) error

	// Backup / Restore
	Backup(path string) error
	BackupWriter(w io.Writer) error
	Restore(r io.Reader) error

	// OIDC
	SaveOIDCAuthCode(code *OIDCAuthCode) error
	ConsumeOIDCAuthCode(code string) (*OIDCAuthCode, error)

	// Runtime Settings
	GetRuntimeSettings() (*RuntimeSettings, error)
	SaveRuntimeSettings(s *RuntimeSettings) error

	// Token Revocation (access token blacklist)
	RevokeAccessToken(jti string, expiresAt time.Time) error
	IsAccessTokenRevoked(jti string) (bool, error)
	CleanExpiredRevocations() error
	RevokeAllUserAccessTokens(userGUID string, expiresAt time.Time) error
	IsUserAccessRevoked(userGUID string) (bool, error)
}
