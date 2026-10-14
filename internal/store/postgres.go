package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStore implements the Store interface using PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// OpenPostgres creates a new PostgresStore. dsn is a PostgreSQL connection string
// (e.g. "postgres://user:pass@host:5432/dbname?sslmode=disable").
func OpenPostgres(dsn string) (*PostgresStore, error) {
	return openPostgres(dsn, true)
}

// openPostgres opens the store. checkMappings runs the dangling-mapping check;
// TestPostgresConnection turns it off because it only probes the DSN.
func openPostgres(dsn string, checkMappings bool) (*PostgresStore, error) {
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
	if checkMappings {
		// Report identity mappings that still point at a deleted user; remove
		// them only on opt-in (M41).
		s.repairDanglingMappings()
	}
	return s, nil
}

// repairDanglingMappings reports identity mappings whose user no longer exists,
// which DeleteUser left behind before M41. It removes them only when the
// operator opts in (see danglingRepairEnabled), and then deletes exactly the
// mappings it logged.
func (s *PostgresStore) repairDanglingMappings() {
	type dangling struct{ provider, externalID, guid string }
	rows, err := s.db.Query(`SELECT m.provider, m.external_id, m.user_guid FROM sa_identity_mappings m
		WHERE NOT EXISTS (SELECT 1 FROM sa_users u WHERE u.guid = m.user_guid)`)
	if err != nil {
		log.Printf("[store] dangling-mapping check: query failed: %v", err)
		return
	}
	var found []dangling
	for rows.Next() {
		var d dangling
		if err := rows.Scan(&d.provider, &d.externalID, &d.guid); err != nil {
			rows.Close()
			log.Printf("[store] dangling-mapping check: scan failed: %v", err)
			return
		}
		found = append(found, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		log.Printf("[store] dangling-mapping check: query failed: %v", err)
		return
	}
	if len(found) == 0 {
		return
	}
	for _, d := range found {
		log.Printf("[store] dangling-mapping check: provider=%q external_id=%q points at deleted user %s (M41)", d.provider, d.externalID, d.guid)
	}
	if !danglingRepairEnabled() {
		logDanglingReportOnly(len(found))
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("[store] dangling-mapping repair FAILED: %v", err)
		return
	}
	defer tx.Rollback()
	var removed int64
	for _, d := range found {
		// Delete only the logged tuple, and only while its user is still missing.
		res, err := tx.Exec(`DELETE FROM sa_identity_mappings m
			WHERE m.provider = $1 AND m.external_id = $2 AND m.user_guid = $3
			AND NOT EXISTS (SELECT 1 FROM sa_users u WHERE u.guid = m.user_guid)`, d.provider, d.externalID, d.guid)
		if err != nil {
			log.Printf("[store] dangling-mapping repair FAILED: %v", err)
			return
		}
		n, _ := res.RowsAffected()
		removed += n
		if n > 0 && strings.HasPrefix(d.provider, "applocal:") {
			if err := clearStaleLocalAssignmentPG(tx, strings.TrimPrefix(d.provider, "applocal:"), d.externalID); err != nil {
				log.Printf("[store] dangling-mapping repair FAILED: %v", err)
				return
			}
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[store] dangling-mapping repair FAILED: %v", err)
		return
	}
	log.Printf("[store] dangling-mapping repair: SA_REPAIR_DANGLING_MAPPINGS=1, removed %d of %d mapping(s) (M41)", removed, len(found))
}

// clearStaleLocalAssignmentPG removes the role assignment appID keeps under a
// deleted app-local user's username, unless a live user can still match that
// key (see BoltStore clearStaleLocalAssignment).
func clearStaleLocalAssignmentPG(tx *sql.Tx, appID, username string) error {
	var liveMatch bool
	if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM sa_identity_mappings m JOIN sa_users u ON u.guid = m.user_guid WHERE m.external_id = $1)
		OR EXISTS (SELECT 1 FROM sa_users WHERE guid = $1 OR data->>'sam_account_name' = $1)`, username).Scan(&liveMatch); err != nil {
		return err
	}
	if liveMatch {
		log.Printf("[store] dangling-mapping repair: app %q keeps the role assignment for %q, a live user still matches that name (M41)", appID, username)
		return nil
	}
	var data []byte
	err := tx.QueryRow(`SELECT data FROM sa_app_authz WHERE app_id = $1 FOR UPDATE`, appID).Scan(&data)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	var authz AppAuthz
	if err := json.Unmarshal(data, &authz); err != nil {
		log.Printf("[store] dangling-mapping repair: app %q authz unreadable, role assignment for %q not checked: %v (M41)", appID, username, err)
		return nil
	}
	if _, ok := authz.UserAssignments[username]; !ok {
		return nil
	}
	delete(authz.UserAssignments, username)
	out, err := json.Marshal(&authz)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE sa_app_authz SET data = $2 WHERE app_id = $1`, appID, out); err != nil {
		return err
	}
	log.Printf("[store] dangling-mapping repair: cleared app %q role assignment for deleted app-local user %q (M41)", appID, username)
	return nil
}

func (s *PostgresStore) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS sa_users (
		guid TEXT PRIMARY KEY,
		data JSONB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sa_identity_mappings (
		provider TEXT NOT NULL,
		external_id TEXT NOT NULL,
		user_guid TEXT NOT NULL,
		PRIMARY KEY (provider, external_id)
	);
	CREATE INDEX IF NOT EXISTS idx_sa_identity_mappings_guid ON sa_identity_mappings(user_guid);
	CREATE TABLE IF NOT EXISTS sa_user_roles (
		guid TEXT PRIMARY KEY,
		roles JSONB NOT NULL DEFAULT '[]'
	);
	CREATE TABLE IF NOT EXISTS sa_user_permissions (
		guid TEXT PRIMARY KEY,
		permissions JSONB NOT NULL DEFAULT '[]'
	);
	CREATE TABLE IF NOT EXISTS sa_config (
		key TEXT PRIMARY KEY,
		value BYTEA
	);
	CREATE TABLE IF NOT EXISTS sa_refresh_tokens (
		token_id TEXT PRIMARY KEY,
		data JSONB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sa_audit_log (
		id TEXT PRIMARY KEY,
		timestamp TIMESTAMPTZ NOT NULL,
		data JSONB NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_sa_audit_log_ts ON sa_audit_log(timestamp DESC);
	CREATE TABLE IF NOT EXISTS sa_oidc_auth_codes (
		code TEXT PRIMARY KEY,
		data JSONB NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sa_revoked_tokens (
		jti TEXT PRIMARY KEY,
		expires_at TIMESTAMPTZ NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sa_revoked_users (
		user_guid TEXT PRIMARY KEY,
		expires_at TIMESTAMPTZ NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sa_sessions (
		id TEXT PRIMARY KEY,
		user_guid TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		last_used_at TIMESTAMPTZ NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		user_agent TEXT,
		ip TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_sa_sessions_user ON sa_sessions(user_guid);
	CREATE INDEX IF NOT EXISTS idx_sa_sessions_exp ON sa_sessions(expires_at);
	CREATE TABLE IF NOT EXISTS sa_apps (
		app_id TEXT PRIMARY KEY,
		data JSONB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sa_app_authz (
		app_id TEXT PRIMARY KEY,
		data JSONB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS sa_app_admins (
		app_id TEXT NOT NULL,
		user_guid TEXT NOT NULL,
		added_by TEXT,
		added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		PRIMARY KEY (app_id, user_guid)
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

// --- Apps (v2) ---

func (s *PostgresStore) CreateApp(a *App) error {
	data, _ := json.Marshal(a)
	res, err := s.db.Exec(`INSERT INTO sa_apps (app_id, data) VALUES ($1, $2) ON CONFLICT (app_id) DO NOTHING`, a.AppID, data)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAppExists
	}
	return nil
}

func (s *PostgresStore) GetApp(appID string) (*App, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT data FROM sa_apps WHERE app_id = $1`, appID).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, ErrAppNotFound
	}
	if err != nil {
		return nil, err
	}
	var a App
	return &a, json.Unmarshal(data, &a)
}

func (s *PostgresStore) ListApps() ([]*App, error) {
	rows, err := s.db.Query(`SELECT data FROM sa_apps ORDER BY app_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []*App
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var a App
		if err := json.Unmarshal(data, &a); err != nil {
			return nil, err
		}
		apps = append(apps, &a)
	}
	return apps, rows.Err()
}

func (s *PostgresStore) UpdateApp(a *App) error {
	data, _ := json.Marshal(a)
	res, err := s.db.Exec(`UPDATE sa_apps SET data = $2 WHERE app_id = $1`, a.AppID, data)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("app not found")
	}
	return nil
}

func (s *PostgresStore) DeleteApp(appID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Cascade: delete the app's app-local users and their identity mappings so a
	// reused app_id cannot resurrect ghost accounts under a new owner (H8).
	if _, err := tx.Exec(
		`DELETE FROM sa_identity_mappings WHERE user_guid IN (SELECT guid FROM sa_users WHERE data->>'owner_app_id' = $1)`, appID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sa_users WHERE data->>'owner_app_id' = $1`, appID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sa_apps WHERE app_id = $1`, appID); err != nil {
		return err
	}
	// Cascade: drop the app's authorization data too.
	if _, err := tx.Exec(`DELETE FROM sa_app_authz WHERE app_id = $1`, appID); err != nil {
		return err
	}
	// Cascade: drop the app's admins so a reused app_id cannot resurrect them.
	if _, err := tx.Exec(`DELETE FROM sa_app_admins WHERE app_id = $1`, appID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) GetAppAuthz(appID string) (*AppAuthz, error) {
	authz := &AppAuthz{AppID: appID}
	var data []byte
	err := s.db.QueryRow(`SELECT data FROM sa_app_authz WHERE app_id = $1`, appID).Scan(&data)
	if err == sql.ErrNoRows {
		return authz, nil
	}
	if err != nil {
		return nil, err
	}
	return authz, json.Unmarshal(data, authz)
}

func (s *PostgresStore) AddAppAdmin(appID, userGUID, addedBy string) error {
	_, err := s.db.Exec(
		`INSERT INTO sa_app_admins (app_id, user_guid, added_by, added_at) VALUES ($1, $2, $3, $4) ON CONFLICT (app_id, user_guid) DO NOTHING`,
		appID, userGUID, addedBy, time.Now().UTC())
	return err
}

func (s *PostgresStore) RemoveAppAdmin(appID, userGUID string) error {
	_, err := s.db.Exec(`DELETE FROM sa_app_admins WHERE app_id = $1 AND user_guid = $2`, appID, userGUID)
	return err
}

func (s *PostgresStore) IsAppAdmin(appID, userGUID string) (bool, error) {
	var ok bool
	err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM sa_app_admins WHERE app_id = $1 AND user_guid = $2)`,
		appID, userGUID).Scan(&ok)
	return ok, err
}

func (s *PostgresStore) ListAppAdmins(appID string) ([]*AppAdmin, error) {
	rows, err := s.db.Query(`SELECT app_id, user_guid, added_by, added_at FROM sa_app_admins WHERE app_id = $1 ORDER BY added_at`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AppAdmin
	for rows.Next() {
		a := &AppAdmin{}
		if err := rows.Scan(&a.AppID, &a.UserGUID, &a.AddedBy, &a.AddedAt); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SaveAppAuthz(authz *AppAuthz) error {
	data, _ := json.Marshal(authz)
	_, err := s.db.Exec(`INSERT INTO sa_app_authz (app_id, data) VALUES ($1, $2) ON CONFLICT (app_id) DO UPDATE SET data = $2`, authz.AppID, data)
	return err
}

// ResetSchema drops and recreates all tables. Used before migration to ensure
// a clean target. Do NOT call this on a running Postgres store with live data.
func (s *PostgresStore) ResetSchema() error {
	drops := `
	DROP TABLE IF EXISTS sa_app_authz CASCADE;
	DROP TABLE IF EXISTS sa_apps CASCADE;
	DROP TABLE IF EXISTS sa_sessions CASCADE;
	DROP TABLE IF EXISTS sa_revoked_users CASCADE;
	DROP TABLE IF EXISTS sa_revoked_tokens CASCADE;
	DROP TABLE IF EXISTS sa_oidc_auth_codes CASCADE;
	DROP TABLE IF EXISTS sa_audit_log CASCADE;
	DROP TABLE IF EXISTS sa_refresh_tokens CASCADE;
	DROP TABLE IF EXISTS sa_config CASCADE;
	DROP TABLE IF EXISTS sa_user_permissions CASCADE;
	DROP TABLE IF EXISTS sa_user_roles CASCADE;
	DROP TABLE IF EXISTS sa_identity_mappings CASCADE;
	DROP TABLE IF EXISTS sa_users CASCADE;
	`
	if _, err := s.db.Exec(drops); err != nil {
		return err
	}
	return s.migrate()
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
		`INSERT INTO sa_users (guid, data) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET data = $2`,
		u.GUID, data,
	)
	return err
}

func (s *PostgresStore) GetUser(guid string) (*User, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT data FROM sa_users WHERE guid = $1`, guid).Scan(&data)
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
	res, err := s.db.Exec(`UPDATE sa_users SET data = $1 WHERE guid = $2`, data, u.GUID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found: %s", u.GUID)
	}
	return nil
}

// DeleteUser removes the user row, its identity mappings, its global roles and
// its direct permissions in one transaction (M41; see BoltStore.DeleteUser).
func (s *PostgresStore) DeleteUser(guid string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM sa_identity_mappings WHERE user_guid = $1`,
		`DELETE FROM sa_user_roles WHERE guid = $1`,
		`DELETE FROM sa_user_permissions WHERE guid = $1`,
		`DELETE FROM sa_users WHERE guid = $1`,
	} {
		if _, err := tx.Exec(q, guid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT data FROM sa_users`)
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
		`INSERT INTO sa_identity_mappings (provider, external_id, user_guid) VALUES ($1, $2, $3)
		 ON CONFLICT (provider, external_id) DO UPDATE SET user_guid = $3`,
		provider, externalID, userGUID,
	)
	return err
}

func (s *PostgresStore) ResolveMapping(provider, externalID string) (string, error) {
	var guid string
	err := s.db.QueryRow(
		`SELECT user_guid FROM sa_identity_mappings WHERE provider = $1 AND external_id = $2`,
		provider, externalID,
	).Scan(&guid)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("mapping not found: %s:%s", provider, externalID)
	}
	return guid, err
}

func (s *PostgresStore) DeleteIdentityMapping(provider, externalID string) error {
	_, err := s.db.Exec(
		`DELETE FROM sa_identity_mappings WHERE provider = $1 AND external_id = $2`,
		provider, externalID,
	)
	return err
}

func (s *PostgresStore) GetMappingsForUser(userGUID string) ([]IdentityMapping, error) {
	rows, err := s.db.Query(
		`SELECT provider, external_id FROM sa_identity_mappings WHERE user_guid = $1`,
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
	rows, err := s.db.Query(`SELECT provider, external_id, user_guid FROM sa_identity_mappings`)
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
		`INSERT INTO sa_user_roles (guid, roles) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET roles = $2`,
		guid, data,
	)
	return err
}

func (s *PostgresStore) GetUserRoles(guid string) ([]string, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT roles FROM sa_user_roles WHERE guid = $1`, guid).Scan(&data)
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
		`INSERT INTO sa_user_permissions (guid, permissions) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET permissions = $2`,
		guid, data,
	)
	return err
}

func (s *PostgresStore) GetUserPermissions(guid string) ([]string, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT permissions FROM sa_user_permissions WHERE guid = $1`, guid).Scan(&data)
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
		`INSERT INTO sa_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`,
		key, value,
	)
	return err
}

func (s *PostgresStore) GetConfigValue(key string) ([]byte, error) {
	var val []byte
	err := s.db.QueryRow(`SELECT value FROM sa_config WHERE key = $1`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return val, err
}

func (s *PostgresStore) DeleteConfigValue(key string) error {
	_, err := s.db.Exec(`DELETE FROM sa_config WHERE key = $1`, key)
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
		`INSERT INTO sa_refresh_tokens (token_id, data) VALUES ($1, $2) ON CONFLICT (token_id) DO UPDATE SET data = $2`,
		rt.TokenID, data,
	)
	return err
}

func (s *PostgresStore) GetRefreshToken(tokenID string) (*RefreshToken, error) {
	var data []byte
	err := s.db.QueryRow(`SELECT data FROM sa_refresh_tokens WHERE token_id = $1`, tokenID).Scan(&data)
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

// ConsumeRefreshToken atomically marks an unused token as used using a
// SELECT ... FOR UPDATE row lock, closing the rotation TOCTOU window (H2). On
// reuse it returns the token (carrying FamilyID) with ErrRefreshTokenReused.
func (s *PostgresStore) ConsumeRefreshToken(tokenID string) (*RefreshToken, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var data []byte
	err = tx.QueryRow(`SELECT data FROM sa_refresh_tokens WHERE token_id = $1 FOR UPDATE`, tokenID).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	var rt RefreshToken
	if err := json.Unmarshal(data, &rt); err != nil {
		return nil, err
	}
	if rt.Used {
		return &rt, ErrRefreshTokenReused
	}
	rt.Used = true
	newData, err := json.Marshal(&rt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE sa_refresh_tokens SET data = $2 WHERE token_id = $1`, tokenID, newData); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &rt, nil
}

func (s *PostgresStore) RevokeTokenFamily(familyID string) error {
	// Single atomic statement that surfaces failure: the old scan-then-loop
	// discarded every per-row DELETE error and always returned nil, so a
	// token-replay family revocation could silently fail (fail-open).
	_, err := s.db.Exec(`DELETE FROM sa_refresh_tokens WHERE data->>'family_id' = $1`, familyID)
	return err
}

func (s *PostgresStore) ListUserSessions(userGUID string) ([]*RefreshToken, error) {
	rows, err := s.db.Query(`SELECT data FROM sa_refresh_tokens`)
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
	// Single atomic statement that surfaces failure (see RevokeTokenFamily).
	// Admin "disable user / log out everywhere" relies on this not failing open.
	_, err := s.db.Exec(`DELETE FROM sa_refresh_tokens WHERE data->>'user_guid' = $1`, userGUID)
	return err
}

func (s *PostgresStore) CleanExpiredOIDCCodes() error {
	_, err := s.db.Exec(`DELETE FROM sa_oidc_auth_codes WHERE (data->>'expires_at')::timestamptz < now()`)
	return err
}

func (s *PostgresStore) CleanExpiredRefreshTokens() error {
	// expires_at is stored inside the JSON data column as an RFC3339 timestamp.
	_, err := s.db.Exec(`DELETE FROM sa_refresh_tokens WHERE (data->>'expires_at')::timestamptz < now()`)
	return err
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
		`INSERT INTO sa_audit_log (id, timestamp, data) VALUES ($1, $2, $3)`,
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
	// Push Event/Actor filters into SQL so LIMIT/OFFSET apply to already-filtered
	// rows. The old code fetched Limit+Offset+100 rows and filtered in Go, which
	// silently dropped matching records whenever the filter out-ran that window.
	if q.Event != "" {
		conditions = append(conditions, fmt.Sprintf("data->>'event' = $%d", argN))
		args = append(args, q.Event)
		argN++
	}
	if q.UserID != "" {
		conditions = append(conditions, fmt.Sprintf("data->>'actor' = $%d", argN))
		args = append(args, q.UserID)
		argN++
	}

	query := `SELECT data FROM sa_audit_log`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argN, argN+1)
	args = append(args, q.Limit, q.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		entries = append(entries, &entry)
	}
	return entries, rows.Err()
}

func (s *PostgresStore) PruneAuditLog(retention time.Duration) error {
	cutoff := time.Now().UTC().Add(-retention)
	_, err := s.db.Exec(`DELETE FROM sa_audit_log WHERE timestamp < $1`, cutoff)
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
	if _, err := tx.Exec(`INSERT INTO sa_users (guid, data) VALUES ($1, $2)`, newUser.GUID, userData); err != nil {
		return nil, err
	}

	allRoles := map[string]bool{}
	allPerms := map[string]bool{}

	for _, srcGUID := range sourceGUIDs {
		// Move identity mappings
		if _, err := tx.Exec(`UPDATE sa_identity_mappings SET user_guid = $1 WHERE user_guid = $2`, newUser.GUID, srcGUID); err != nil {
			return nil, fmt.Errorf("merge: reassign identity mappings for %s: %w", srcGUID, err)
		}

		// Collect roles
		var rolesData []byte
		if err := tx.QueryRow(`SELECT roles FROM sa_user_roles WHERE guid = $1`, srcGUID).Scan(&rolesData); err == nil {
			var roles []string
			json.Unmarshal(rolesData, &roles)
			for _, r := range roles {
				allRoles[r] = true
			}
		}
		if _, err := tx.Exec(`DELETE FROM sa_user_roles WHERE guid = $1`, srcGUID); err != nil {
			return nil, fmt.Errorf("merge: delete source roles for %s: %w", srcGUID, err)
		}

		// Collect permissions
		var permsData []byte
		if err := tx.QueryRow(`SELECT permissions FROM sa_user_permissions WHERE guid = $1`, srcGUID).Scan(&permsData); err == nil {
			var perms []string
			json.Unmarshal(permsData, &perms)
			for _, p := range perms {
				allPerms[p] = true
			}
		}
		if _, err := tx.Exec(`DELETE FROM sa_user_permissions WHERE guid = $1`, srcGUID); err != nil {
			return nil, fmt.Errorf("merge: delete source permissions for %s: %w", srcGUID, err)
		}

		// Mark source as merged
		var srcData []byte
		if err := tx.QueryRow(`SELECT data FROM sa_users WHERE guid = $1`, srcGUID).Scan(&srcData); err == nil {
			var srcUser User
			json.Unmarshal(srcData, &srcUser)
			srcUser.MergedInto = newUser.GUID
			mergedData, _ := json.Marshal(&srcUser)
			if _, err := tx.Exec(`UPDATE sa_users SET data = $1 WHERE guid = $2`, mergedData, srcGUID); err != nil {
				return nil, fmt.Errorf("merge: mark source %s merged: %w", srcGUID, err)
			}
		}
	}

	// Write merged roles
	if len(allRoles) > 0 {
		var roles []string
		for r := range allRoles {
			roles = append(roles, r)
		}
		data, _ := json.Marshal(roles)
		if _, err := tx.Exec(`INSERT INTO sa_user_roles (guid, roles) VALUES ($1, $2)`, newUser.GUID, data); err != nil {
			return nil, fmt.Errorf("merge: write merged roles: %w", err)
		}
	}
	if len(allPerms) > 0 {
		var perms []string
		for p := range allPerms {
			perms = append(perms, p)
		}
		data, _ := json.Marshal(perms)
		if _, err := tx.Exec(`INSERT INTO sa_user_permissions (guid, permissions) VALUES ($1, $2)`, newUser.GUID, data); err != nil {
			return nil, fmt.Errorf("merge: write merged permissions: %w", err)
		}
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
	rows, err := s.db.Query(`SELECT key, value FROM sa_config`)
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
		`INSERT INTO sa_oidc_auth_codes (code, data, expires_at) VALUES ($1, $2, $3)`,
		code.Code, data, code.ExpiresAt,
	)
	return err
}

func (s *PostgresStore) ConsumeOIDCAuthCode(code string) (*OIDCAuthCode, error) {
	var data []byte
	err := s.db.QueryRow(`DELETE FROM sa_oidc_auth_codes WHERE code = $1 RETURNING data`, code).Scan(&data)
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
		`INSERT INTO sa_revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING`,
		jti, expiresAt,
	)
	return err
}

func (s *PostgresStore) IsAccessTokenRevoked(jti string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM sa_revoked_tokens WHERE jti = $1)`, jti).Scan(&exists)
	return exists, err
}

func (s *PostgresStore) CleanExpiredRevocations() error {
	_, err := s.db.Exec(`DELETE FROM sa_revoked_tokens WHERE expires_at < NOW()`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM sa_revoked_users WHERE expires_at < NOW()`)
	return err
}

func (s *PostgresStore) RevokeAllUserAccessTokens(userGUID string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO sa_revoked_users (user_guid, expires_at) VALUES ($1, $2) ON CONFLICT (user_guid) DO UPDATE SET expires_at = $2`,
		userGUID, expiresAt,
	)
	return err
}

func (s *PostgresStore) IsUserAccessRevoked(userGUID string) (bool, error) {
	var exists bool
	err := s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM sa_revoked_users WHERE user_guid = $1 AND expires_at > NOW())`,
		userGUID,
	).Scan(&exists)
	return exists, err
}

// --- Database Info ---

func (s *PostgresStore) DatabaseInfo() (*DatabaseInfo, error) {
	info := &DatabaseInfo{
		Backend: "postgres",
		Health:  "healthy",
	}

	// Version
	s.db.QueryRow("SELECT version()").Scan(&info.Version)

	// Database size
	var sizeBytes int64
	s.db.QueryRow("SELECT pg_database_size(current_database())").Scan(&sizeBytes)
	info.SizeMB = float64(sizeBytes) / 1024 / 1024

	// Connection pool stats
	stats := s.db.Stats()
	info.MaxConnections = stats.MaxOpenConnections
	info.OpenConnections = stats.OpenConnections
	info.InUse = stats.InUse
	info.Idle = stats.Idle

	// Table stats (only sa_ prefixed tables)
	tables := []string{
		"sa_users", "sa_identity_mappings", "sa_user_roles", "sa_user_permissions",
		"sa_config", "sa_refresh_tokens", "sa_audit_log", "sa_oidc_auth_codes",
		"sa_revoked_tokens", "sa_revoked_users",
	}
	for _, t := range tables {
		var count int64
		err := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", t)).Scan(&count)
		if err != nil {
			continue
		}
		var sizeMB float64
		s.db.QueryRow(fmt.Sprintf("SELECT pg_total_relation_size('%s')::float / 1024 / 1024", t)).Scan(&sizeMB)

		info.Tables++
		info.TotalRows += count
		info.TableDetails = append(info.TableDetails, TableInfo{
			Name:   t,
			Rows:   count,
			SizeMB: sizeMB,
		})
	}

	// Health check
	if err := s.db.Ping(); err != nil {
		info.Health = "error"
	}

	return info, nil
}

// --- SSO Sessions ---

func (s *PostgresStore) CreateSession(sess *Session) error {
	_, err := s.db.Exec(
		`INSERT INTO sa_sessions (id, user_guid, created_at, last_used_at, expires_at, user_agent, ip) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sess.ID, sess.UserGUID, sess.CreatedAt, sess.LastUsedAt, sess.ExpiresAt, sess.UserAgent, sess.IP,
	)
	return err
}

func (s *PostgresStore) GetSession(id string) (*Session, error) {
	var sess Session
	err := s.db.QueryRow(
		`SELECT id, user_guid, created_at, last_used_at, expires_at, COALESCE(user_agent, ''), COALESCE(ip, '') FROM sa_sessions WHERE id = $1`,
		id,
	).Scan(&sess.ID, &sess.UserGUID, &sess.CreatedAt, &sess.LastUsedAt, &sess.ExpiresAt, &sess.UserAgent, &sess.IP)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found")
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *PostgresStore) TouchSession(id string, lastUsed time.Time) error {
	_, err := s.db.Exec(`UPDATE sa_sessions SET last_used_at = $1 WHERE id = $2`, lastUsed, id)
	return err
}

func (s *PostgresStore) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sa_sessions WHERE id = $1`, id)
	return err
}

func (s *PostgresStore) DeleteUserSessions(userGUID string) error {
	_, err := s.db.Exec(`DELETE FROM sa_sessions WHERE user_guid = $1`, userGUID)
	return err
}

func (s *PostgresStore) CleanExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sa_sessions WHERE expires_at < NOW()`)
	return err
}
