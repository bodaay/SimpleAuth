package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/google/uuid"
)

// PostgresStore implements the Store interface using PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// OpenPostgres creates a new PostgresStore. dsn is a PostgreSQL connection string
// (e.g. "postgres://user:pass@host:5432/dbname?sslmode=disable").
func OpenPostgres(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	s := &PostgresStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate postgres schema: %w", err)
	}
	return s, nil
}

func (s *PostgresStore) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		guid TEXT PRIMARY KEY,
		data JSONB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS identity_mappings (
		provider TEXT NOT NULL,
		external_id TEXT NOT NULL,
		user_guid TEXT NOT NULL,
		PRIMARY KEY (provider, external_id)
	);
	CREATE INDEX IF NOT EXISTS idx_identity_mappings_guid ON identity_mappings(user_guid);
	CREATE TABLE IF NOT EXISTS user_roles (
		guid TEXT PRIMARY KEY,
		roles JSONB NOT NULL DEFAULT '[]'
	);
	CREATE TABLE IF NOT EXISTS user_permissions (
		guid TEXT PRIMARY KEY,
		permissions JSONB NOT NULL DEFAULT '[]'
	);
	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value BYTEA
	);
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		token_id TEXT PRIMARY KEY,
		data JSONB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS audit_log (
		id TEXT PRIMARY KEY,
		timestamp TIMESTAMPTZ NOT NULL,
		data JSONB NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(timestamp DESC);
	CREATE TABLE IF NOT EXISTS oidc_auth_codes (
		code TEXT PRIMARY KEY,
		data JSONB NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL
	);
	CREATE TABLE IF NOT EXISTS revoked_tokens (
		jti TEXT PRIMARY KEY,
		expires_at TIMESTAMPTZ NOT NULL
	);
	CREATE TABLE IF NOT EXISTS revoked_users (
		user_guid TEXT PRIMARY KEY,
		expires_at TIMESTAMPTZ NOT NULL
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// --- Users ---

func (s *PostgresStore) CreateUser(u *User) error {
	if u.GUID == "" {
		u.GUID = uuid.New().String()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	data, err := json.Marshal(u)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO users (guid, data) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET data = $2`,
		u.GUID, data,
	)
	return err
}

func (s *PostgresStore) GetUser(guid string) (*User, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT data FROM users WHERE guid = $1`, guid).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found: %s", guid)
	}
	if err != nil {
		return nil, err
	}
	var u User
	return &u, json.Unmarshal(data, &u)
}

func (s *PostgresStore) ResolveUser(guid string) (*User, error) {
	u, err := s.GetUser(guid)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{guid: true}
	for u.MergedInto != "" {
		if seen[u.MergedInto] {
			return nil, fmt.Errorf("merge cycle detected for %s", guid)
		}
		seen[u.MergedInto] = true
		u, err = s.GetUser(u.MergedInto)
		if err != nil {
			return nil, err
		}
	}
	return u, nil
}

func (s *PostgresStore) UpdateUser(u *User) error {
	data, err := json.Marshal(u)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE users SET data = $1 WHERE guid = $2`, data, u.GUID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found: %s", u.GUID)
	}
	return nil
}

func (s *PostgresStore) DeleteUser(guid string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE guid = $1`, guid)
	return err
}

func (s *PostgresStore) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT data FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var u User
		if err := json.Unmarshal(data, &u); err != nil {
			return nil, err
		}
		users = append(users, &u)
	}
	return users, rows.Err()
}

// --- LDAP Config ---

func (s *PostgresStore) GetLDAPConfig() (*LDAPConfig, error) {
	val, err := s.GetConfigValue("ldap:config")
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, fmt.Errorf("ldap not configured")
	}
	var cfg LDAPConfig
	return &cfg, json.Unmarshal(val, &cfg)
}

func (s *PostgresStore) SaveLDAPConfig(cfg *LDAPConfig) error {
	if cfg.ConfiguredAt.IsZero() {
		cfg.ConfiguredAt = time.Now().UTC()
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.SetConfigValue("ldap:config", data)
}

func (s *PostgresStore) DeleteLDAPConfig() error {
	return s.DeleteConfigValue("ldap:config")
}

// --- Identity Mappings ---

func (s *PostgresStore) SetIdentityMapping(provider, externalID, userGUID string) error {
	_, err := s.db.Exec(
		`INSERT INTO identity_mappings (provider, external_id, user_guid) VALUES ($1, $2, $3)
		 ON CONFLICT (provider, external_id) DO UPDATE SET user_guid = $3`,
		provider, externalID, userGUID,
	)
	return err
}

func (s *PostgresStore) ResolveMapping(provider, externalID string) (string, error) {
	var guid string
	err := s.db.QueryRow(
		`SELECT user_guid FROM identity_mappings WHERE provider = $1 AND external_id = $2`,
		provider, externalID,
	).Scan(&guid)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("mapping not found: %s:%s", provider, externalID)
	}
	return guid, err
}

func (s *PostgresStore) DeleteIdentityMapping(provider, externalID string) error {
	_, err := s.db.Exec(
		`DELETE FROM identity_mappings WHERE provider = $1 AND external_id = $2`,
		provider, externalID,
	)
	return err
}

func (s *PostgresStore) GetMappingsForUser(userGUID string) ([]IdentityMapping, error) {
	rows, err := s.db.Query(
		`SELECT provider, external_id FROM identity_mappings WHERE user_guid = $1`,
		userGUID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mappings []IdentityMapping
	for rows.Next() {
		var m IdentityMapping
		if err := rows.Scan(&m.Provider, &m.ExternalID); err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

func (s *PostgresStore) ListAllMappings() ([]IdentityMappingEntry, error) {
	rows, err := s.db.Query(`SELECT provider, external_id, user_guid FROM identity_mappings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []IdentityMappingEntry
	for rows.Next() {
		var e IdentityMappingEntry
		if err := rows.Scan(&e.Provider, &e.ExternalID, &e.UserGUID); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

// --- Roles & Permissions ---

func (s *PostgresStore) SetUserRoles(guid string, roles []string) error {
	data, _ := json.Marshal(roles)
	_, err := s.db.Exec(
		`INSERT INTO user_roles (guid, roles) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET roles = $2`,
		guid, data,
	)
	return err
}

func (s *PostgresStore) GetUserRoles(guid string) ([]string, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT roles FROM user_roles WHERE guid = $1`, guid).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var roles []string
	return roles, json.Unmarshal(data, &roles)
}

func (s *PostgresStore) SetUserPermissions(guid string, perms []string) error {
	data, _ := json.Marshal(perms)
	_, err := s.db.Exec(
		`INSERT INTO user_permissions (guid, permissions) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET permissions = $2`,
		guid, data,
	)
	return err
}

func (s *PostgresStore) GetUserPermissions(guid string) ([]string, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT permissions FROM user_permissions WHERE guid = $1`, guid).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var perms []string
	return perms, json.Unmarshal(data, &perms)
}

func (s *PostgresStore) ListAllRoles() ([]string, error) {
	mapping, err := s.GetRolePermissions()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(mapping))
	for r := range mapping {
		result = append(result, r)
	}
	sort.Strings(result)
	return result, nil
}

func (s *PostgresStore) ListAllPermissions() ([]string, error) {
	return s.GetDefinedPermissions()
}

// --- Config key-value ---

func (s *PostgresStore) SetConfigValue(key string, value []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`,
		key, value,
	)
	return err
}

func (s *PostgresStore) GetConfigValue(key string) ([]byte, error) {
	var val []byte
	err := s.db.QueryRow(`SELECT value FROM config WHERE key = $1`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return val, err
}

func (s *PostgresStore) DeleteConfigValue(key string) error {
	_, err := s.db.Exec(`DELETE FROM config WHERE key = $1`, key)
	return err
}

// --- Default Roles ---

func (s *PostgresStore) GetDefaultRoles() ([]string, error) {
	val, err := s.GetConfigValue("default_roles")
	if err != nil || val == nil {
		return nil, err
	}
	var roles []string
	return roles, json.Unmarshal(val, &roles)
}

func (s *PostgresStore) SetDefaultRoles(roles []string) error {
	data, _ := json.Marshal(roles)
	return s.SetConfigValue("default_roles", data)
}

// --- Role → Permissions Mapping ---

func (s *PostgresStore) GetRolePermissions() (map[string][]string, error) {
	val, err := s.GetConfigValue("role_permissions")
	if err != nil || val == nil {
		return nil, err
	}
	var mapping map[string][]string
	return mapping, json.Unmarshal(val, &mapping)
}

func (s *PostgresStore) SetRolePermissions(mapping map[string][]string) error {
	data, _ := json.Marshal(mapping)
	return s.SetConfigValue("role_permissions", data)
}

func (s *PostgresStore) RoleExists(role string) (bool, error) {
	mapping, err := s.GetRolePermissions()
	if err != nil || mapping == nil {
		return false, err
	}
	_, exists := mapping[role]
	return exists, nil
}

func (s *PostgresStore) GetDefinedPermissions() ([]string, error) {
	val, err := s.GetConfigValue("defined_permissions")
	if err != nil || val == nil {
		return nil, err
	}
	var perms []string
	return perms, json.Unmarshal(val, &perms)
}

func (s *PostgresStore) SetDefinedPermissions(perms []string) error {
	data, _ := json.Marshal(perms)
	return s.SetConfigValue("defined_permissions", data)
}

func (s *PostgresStore) PermissionExists(perm string) (bool, error) {
	perms, err := s.GetDefinedPermissions()
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == perm {
			return true, nil
		}
	}
	return false, nil
}

func (s *PostgresStore) ValidateRolesExist(roles []string) (string, error) {
	mapping, err := s.GetRolePermissions()
	if err != nil {
		return "", err
	}
	if mapping == nil {
		mapping = map[string][]string{}
	}
	for _, r := range roles {
		if _, exists := mapping[r]; !exists {
			return r, nil
		}
	}
	return "", nil
}

func (s *PostgresStore) ValidatePermissionsExist(perms []string) (string, error) {
	defined, err := s.GetDefinedPermissions()
	if err != nil {
		return "", err
	}
	set := make(map[string]struct{}, len(defined))
	for _, p := range defined {
		set[p] = struct{}{}
	}
	for _, p := range perms {
		if _, exists := set[p]; !exists {
			return p, nil
		}
	}
	return "", nil
}

func (s *PostgresStore) ResolvePermissions(roles, directPerms []string) ([]string, error) {
	mapping, err := s.GetRolePermissions()
	if err != nil {
		return directPerms, err
	}
	if mapping == nil {
		return directPerms, nil
	}
	seen := make(map[string]bool)
	var merged []string
	for _, role := range roles {
		if perms, ok := mapping[role]; ok {
			for _, p := range perms {
				if !seen[p] {
					seen[p] = true
					merged = append(merged, p)
				}
			}
		}
	}
	for _, p := range directPerms {
		if !seen[p] {
			seen[p] = true
			merged = append(merged, p)
		}
	}
	return merged, nil
}

// --- Refresh Tokens ---

func (s *PostgresStore) SaveRefreshToken(rt *RefreshToken) error {
	data, _ := json.Marshal(rt)
	_, err := s.db.Exec(
		`INSERT INTO refresh_tokens (token_id, data) VALUES ($1, $2) ON CONFLICT (token_id) DO UPDATE SET data = $2`,
		rt.TokenID, data,
	)
	return err
}

func (s *PostgresStore) GetRefreshToken(tokenID string) (*RefreshToken, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT data FROM refresh_tokens WHERE token_id = $1`, tokenID).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("refresh token not found")
	}
	if err != nil {
		return nil, err
	}
	var rt RefreshToken
	return &rt, json.Unmarshal(data, &rt)
}

func (s *PostgresStore) MarkRefreshTokenUsed(tokenID string) error {
	rt, err := s.GetRefreshToken(tokenID)
	if err != nil {
		return err
	}
	rt.Used = true
	return s.SaveRefreshToken(rt)
}

func (s *PostgresStore) RevokeTokenFamily(familyID string) error {
	rows, err := s.db.Query(`SELECT data FROM refresh_tokens`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var toDelete []string
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var rt RefreshToken
		if json.Unmarshal(data, &rt) == nil && rt.FamilyID == familyID {
			toDelete = append(toDelete, rt.TokenID)
		}
	}
	for _, id := range toDelete {
		s.db.Exec(`DELETE FROM refresh_tokens WHERE token_id = $1`, id)
	}
	return nil
}

func (s *PostgresStore) ListUserSessions(userGUID string) ([]*RefreshToken, error) {
	rows, err := s.db.Query(`SELECT data FROM refresh_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	var sessions []*RefreshToken
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var rt RefreshToken
		if json.Unmarshal(data, &rt) == nil && rt.UserGUID == userGUID && !rt.Used && rt.ExpiresAt.After(now) {
			sessions = append(sessions, &rt)
		}
	}
	return sessions, rows.Err()
}

func (s *PostgresStore) RevokeUserTokens(userGUID string) error {
	rows, err := s.db.Query(`SELECT data FROM refresh_tokens`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var toDelete []string
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var rt RefreshToken
		if json.Unmarshal(data, &rt) == nil && rt.UserGUID == userGUID {
			toDelete = append(toDelete, rt.TokenID)
		}
	}
	for _, id := range toDelete {
		s.db.Exec(`DELETE FROM refresh_tokens WHERE token_id = $1`, id)
	}
	return nil
}

// --- Audit Log ---

func (s *PostgresStore) WriteAuditLog(entry *AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	data, _ := json.Marshal(entry)
	_, err := s.db.Exec(
		`INSERT INTO audit_log (id, timestamp, data) VALUES ($1, $2, $3)`,
		entry.ID, entry.Timestamp, data,
	)
	return err
}

func (s *PostgresStore) QueryAuditLog(q AuditQuery) ([]*AuditEntry, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	var conditions []string
	var args []interface{}
	argN := 1

	if !q.From.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argN))
		args = append(args, q.From)
		argN++
	}
	if !q.To.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argN))
		args = append(args, q.To)
		argN++
	}

	query := `SELECT data FROM audit_log`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", q.Limit+q.Offset+100, 0) // fetch extra for filtering

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditEntry
	skipped := 0
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		if q.Event != "" && entry.Event != q.Event {
			continue
		}
		if q.UserID != "" && entry.Actor != q.UserID {
			continue
		}
		if skipped < q.Offset {
			skipped++
			continue
		}
		entries = append(entries, &entry)
		if len(entries) >= q.Limit {
			break
		}
	}
	return entries, rows.Err()
}

func (s *PostgresStore) PruneAuditLog(retention time.Duration) error {
	cutoff := time.Now().UTC().Add(-retention)
	_, err := s.db.Exec(`DELETE FROM audit_log WHERE timestamp < $1`, cutoff)
	return err
}

// --- User Merge ---

func (s *PostgresStore) MergeUsers(sourceGUIDs []string, displayName, email string) (*User, error) {
	newUser := &User{
		GUID:        uuid.New().String(),
		DisplayName: displayName,
		Email:       email,
		CreatedAt:   time.Now().UTC(),
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Create new user
	userData, _ := json.Marshal(newUser)
	if _, err := tx.Exec(`INSERT INTO users (guid, data) VALUES ($1, $2)`, newUser.GUID, userData); err != nil {
		return nil, err
	}

	allRoles := map[string]bool{}
	allPerms := map[string]bool{}

	for _, srcGUID := range sourceGUIDs {
		// Move identity mappings
		tx.Exec(`UPDATE identity_mappings SET user_guid = $1 WHERE user_guid = $2`, newUser.GUID, srcGUID)

		// Collect roles
		var rolesData []byte
		if err := tx.QueryRow(`SELECT roles FROM user_roles WHERE guid = $1`, srcGUID).Scan(&rolesData); err == nil {
			var roles []string
			json.Unmarshal(rolesData, &roles)
			for _, r := range roles {
				allRoles[r] = true
			}
		}
		tx.Exec(`DELETE FROM user_roles WHERE guid = $1`, srcGUID)

		// Collect permissions
		var permsData []byte
		if err := tx.QueryRow(`SELECT permissions FROM user_permissions WHERE guid = $1`, srcGUID).Scan(&permsData); err == nil {
			var perms []string
			json.Unmarshal(permsData, &perms)
			for _, p := range perms {
				allPerms[p] = true
			}
		}
		tx.Exec(`DELETE FROM user_permissions WHERE guid = $1`, srcGUID)

		// Mark source as merged
		var srcData []byte
		if err := tx.QueryRow(`SELECT data FROM users WHERE guid = $1`, srcGUID).Scan(&srcData); err == nil {
			var srcUser User
			json.Unmarshal(srcData, &srcUser)
			srcUser.MergedInto = newUser.GUID
			mergedData, _ := json.Marshal(&srcUser)
			tx.Exec(`UPDATE users SET data = $1 WHERE guid = $2`, mergedData, srcGUID)
		}
	}

	// Write merged roles
	if len(allRoles) > 0 {
		var roles []string
		for r := range allRoles {
			roles = append(roles, r)
		}
		data, _ := json.Marshal(roles)
		tx.Exec(`INSERT INTO user_roles (guid, roles) VALUES ($1, $2)`, newUser.GUID, data)
	}
	if len(allPerms) > 0 {
		var perms []string
		for p := range allPerms {
			perms = append(perms, p)
		}
		data, _ := json.Marshal(perms)
		tx.Exec(`INSERT INTO user_permissions (guid, permissions) VALUES ($1, $2)`, newUser.GUID, data)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return newUser, nil
}

func (s *PostgresStore) UnmergeUser(guid string) error {
	u, err := s.GetUser(guid)
	if err != nil {
		return err
	}
	if u.MergedInto == "" {
		return fmt.Errorf("user %s is not merged", guid)
	}
	u.MergedInto = ""
	return s.UpdateUser(u)
}

// --- Backup / Restore ---

func (s *PostgresStore) Backup(path string) error {
	return fmt.Errorf("backup to file not supported for PostgreSQL; use pg_dump instead")
}

func (s *PostgresStore) BackupWriter(w io.Writer) error {
	// Export all tables as JSON
	dump := map[string]interface{}{}

	// Users
	users, _ := s.ListUsers()
	dump["users"] = users

	// Identity mappings
	mappings, _ := s.ListAllMappings()
	dump["identity_mappings"] = mappings

	// Config
	rows, err := s.db.Query(`SELECT key, value FROM config`)
	if err == nil {
		defer rows.Close()
		configMap := map[string]json.RawMessage{}
		for rows.Next() {
			var k string
			var v []byte
			rows.Scan(&k, &v)
			configMap[k] = v
		}
		dump["config"] = configMap
	}

	// Roles, permissions, etc stored in config table already covered

	data, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func (s *PostgresStore) Restore(r io.Reader) error {
	return fmt.Errorf("restore not supported for PostgreSQL; use pg_restore or the migration endpoint")
}

// --- OIDC Authorization Codes ---

func (s *PostgresStore) SaveOIDCAuthCode(code *OIDCAuthCode) error {
	data, _ := json.Marshal(code)
	_, err := s.db.Exec(
		`INSERT INTO oidc_auth_codes (code, data, expires_at) VALUES ($1, $2, $3)`,
		code.Code, data, code.ExpiresAt,
	)
	return err
}

func (s *PostgresStore) ConsumeOIDCAuthCode(code string) (*OIDCAuthCode, error) {
	var data []byte
	err := s.db.QueryRow(`DELETE FROM oidc_auth_codes WHERE code = $1 RETURNING data`, code).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("auth code not found")
	}
	if err != nil {
		return nil, err
	}
	var ac OIDCAuthCode
	if err := json.Unmarshal(data, &ac); err != nil {
		return nil, err
	}
	if time.Now().After(ac.ExpiresAt) {
		return nil, fmt.Errorf("auth code expired")
	}
	return &ac, nil
}

// --- Runtime Settings ---

func (s *PostgresStore) GetRuntimeSettings() (*RuntimeSettings, error) {
	val, err := s.GetConfigValue("runtime_settings")
	if err != nil || val == nil {
		return nil, err
	}
	var rs RuntimeSettings
	return &rs, json.Unmarshal(val, &rs)
}

func (s *PostgresStore) SaveRuntimeSettings(rs *RuntimeSettings) error {
	data, err := json.Marshal(rs)
	if err != nil {
		return err
	}
	return s.SetConfigValue("runtime_settings", data)
}

// --- Token Revocation ---

func (s *PostgresStore) RevokeAccessToken(jti string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING`,
		jti, expiresAt,
	)
	return err
}

func (s *PostgresStore) IsAccessTokenRevoked(jti string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)`, jti).Scan(&exists)
	return exists, err
}

func (s *PostgresStore) CleanExpiredRevocations() error {
	_, err := s.db.Exec(`DELETE FROM revoked_tokens WHERE expires_at < NOW()`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM revoked_users WHERE expires_at < NOW()`)
	return err
}

func (s *PostgresStore) RevokeAllUserAccessTokens(userGUID string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO revoked_users (user_guid, expires_at) VALUES ($1, $2) ON CONFLICT (user_guid) DO UPDATE SET expires_at = $2`,
		userGUID, expiresAt,
	)
	return err
}

func (s *PostgresStore) IsUserAccessRevoked(userGUID string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM revoked_users WHERE user_guid = $1 AND expires_at > NOW())`,
		userGUID,
	).Scan(&exists)
	return exists, err
}
