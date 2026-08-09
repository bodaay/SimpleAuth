package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	bolt "go.etcd.io/bbolt"
)

// MigrationStatus tracks progress of a database migration.
type MigrationStatus struct {
	State         string            `json:"state"`    // idle, running, verifying, completed, failed
	Progress      map[string]string `json:"progress"` // table → status
	TotalItems    int64             `json:"total_items"`
	MigratedItems int64             `json:"migrated_items"`
	StartedAt     int64             `json:"started_at,omitempty"`
	CompletedAt   int64             `json:"completed_at,omitempty"`
	Error         string            `json:"error,omitempty"`
}

// migrationHelper holds common migration logic.
type migrationHelper struct {
	status   MigrationStatus
	statusCh chan<- MigrationStatus
}

func newMigrationHelper(ch chan<- MigrationStatus) *migrationHelper {
	return &migrationHelper{
		status:   MigrationStatus{State: "running", Progress: map[string]string{}, StartedAt: time.Now().Unix()},
		statusCh: ch,
	}
}

func (m *migrationHelper) send() {
	select {
	case m.statusCh <- m.status:
	default:
	}
}

func (m *migrationHelper) fail(err error) error {
	m.status.State = "failed"
	m.status.Error = err.Error()
	m.send()
	return err
}

func (m *migrationHelper) complete() {
	m.status.State = "completed"
	m.status.CompletedAt = time.Now().Unix()
	m.send()
}

// ============================================================================
//  BoltDB → PostgreSQL
// ============================================================================

// MigrateToPostgres copies all data from a BoltStore to a PostgresStore.
// Source is never modified. Target is truncated before copy. Row counts verified.
func MigrateToPostgres(source *BoltStore, target *PostgresStore, statusCh chan<- MigrationStatus) error {
	m := newMigrationHelper(statusCh)

	// Step 1: Truncate target (idempotent — safe to run multiple times)
	m.status.Progress["_prepare"] = "truncating"
	m.send()
	for _, table := range []string{
		"sa_app_authz", "sa_apps",
		"sa_sessions", "sa_oidc_auth_codes", "sa_revoked_tokens", "sa_revoked_users",
		"sa_audit_log", "sa_refresh_tokens", "sa_user_permissions",
		"sa_user_roles", "sa_identity_mappings", "sa_config", "sa_users",
	} {
		target.db.Exec(fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
	}
	m.status.Progress["_prepare"] = "done"

	// Step 2: Count source items
	buckets := []struct {
		name   string
		bucket []byte
	}{
		{"users", bucketUsers},
		{"identity_mappings", bucketIdentityMappings},
		{"idx_mappings_by_guid", bucketIdxMappingsByGUID},
		{"user_roles", bucketUserRoles},
		{"user_permissions", bucketUserPermissions},
		{"config", bucketConfig},
		{"refresh_tokens", bucketRefreshTokens},
		{"audit_log", bucketAuditLog},
		{"oidc_auth_codes", bucketOIDCAuthCodes},
		// Security-relevant state that must survive a backend switch: SSO
		// sessions and the access-token revocation blacklist. Omitting these
		// previously caused revoked tokens to become valid again (H3).
		{"sessions", bucketSessions},
		{"revoked_tokens", bucketRevokedTokens},
		{"revoked_users", bucketRevokedUsers},
		{"apps", bucketApps},
		{"app_authz", bucketAppAuthz},
		{"app_admins", bucketAppAdmins},
	}

	sourceCounts := map[string]int64{}
	source.db.View(func(tx *bolt.Tx) error {
		for _, b := range buckets {
			bucket := tx.Bucket(b.bucket)
			if bucket == nil {
				continue
			}
			var count int64
			bucket.ForEach(func(k, v []byte) error { count++; return nil })
			sourceCounts[b.name] = count
			m.status.TotalItems += count
		}
		return nil
	})
	m.send()

	// The Bolt forward key is the ambiguous composite "provider:externalID"; the
	// reverse index holds the exact halves. Without this, "applocal:<appID>" lands
	// in Postgres as provider="applocal" / external_id="<appID>:<user>", and
	// ResolveMapping("applocal:"+appID, username) — the app-local login lookup —
	// can never match again after the migration (M38).
	var mappingSplitIdx map[string]IdentityMapping
	_ = source.db.View(func(tx *bolt.Tx) error {
		mappingSplitIdx = mappingSplits(tx)
		return nil
	})

	// Step 3: Copy data
	for _, b := range buckets {
		m.status.Progress[b.name] = "migrating"
		m.send()

		err := source.db.View(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(b.bucket)
			if bucket == nil {
				return nil
			}
			return bucket.ForEach(func(k, v []byte) error {
				if err := migrateKV(target, b.name, k, v, mappingSplitIdx); err != nil {
					return fmt.Errorf("%s key=%s: %w", b.name, string(k), err)
				}
				m.status.MigratedItems++
				if m.status.MigratedItems%50 == 0 {
					m.send()
				}
				return nil
			})
		})
		if err != nil {
			return m.fail(err)
		}
		m.status.Progress[b.name] = "done"
		m.send()
	}

	// Step 4: Verify row counts
	m.status.State = "verifying"
	m.send()
	verifyMap := map[string]string{
		"users":             "sa_users",
		"identity_mappings": "sa_identity_mappings",
		"user_roles":        "sa_user_roles",
		"user_permissions":  "sa_user_permissions",
		"config":            "sa_config",
		"refresh_tokens":    "sa_refresh_tokens",
		"audit_log":         "sa_audit_log",
		"oidc_auth_codes":   "sa_oidc_auth_codes",
		"sessions":          "sa_sessions",
		"revoked_tokens":    "sa_revoked_tokens",
		"revoked_users":     "sa_revoked_users",
		"apps":              "sa_apps",
		"app_authz":         "sa_app_authz",
		"app_admins":        "sa_app_admins",
	}
	for boltName, pgTable := range verifyMap {
		expected := sourceCounts[boltName]
		if expected == 0 {
			continue
		}
		var actual int64
		target.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", pgTable)).Scan(&actual)
		if actual != expected {
			return m.fail(fmt.Errorf("verification failed for %s: expected %d rows, got %d", boltName, expected, actual))
		}
	}

	m.complete()
	return nil
}

// migrateKV inserts a single BoltDB key-value pair into the correct Postgres table.
func migrateKV(target *PostgresStore, table string, k, v []byte, mappingSplit map[string]IdentityMapping) error {
	key := string(k)
	switch table {
	case "users":
		_, err := target.db.Exec(`INSERT INTO sa_users (guid, data) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET data = $2`, key, v)
		return err
	case "identity_mappings":
		// Decompose via the reverse index, not the first ':' — see mappingSplits
		// (M38). Getting this wrong silently breaks app-local login after the
		// migration, with no error at migration time.
		m, ok := splitMappingKey(key, mappingSplit)
		if !ok {
			return nil
		}
		_, err := target.db.Exec(`INSERT INTO sa_identity_mappings (provider, external_id, user_guid) VALUES ($1, $2, $3) ON CONFLICT (provider, external_id) DO UPDATE SET user_guid = $3`, m.Provider, m.ExternalID, string(v))
		return err
	case "idx_mappings_by_guid":
		return nil // reverse index — Postgres uses SQL index
	case "user_roles":
		_, err := target.db.Exec(`INSERT INTO sa_user_roles (guid, roles) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET roles = $2`, key, v)
		return err
	case "user_permissions":
		_, err := target.db.Exec(`INSERT INTO sa_user_permissions (guid, permissions) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET permissions = $2`, key, v)
		return err
	case "config":
		_, err := target.db.Exec(`INSERT INTO sa_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`, key, v)
		return err
	case "refresh_tokens":
		_, err := target.db.Exec(`INSERT INTO sa_refresh_tokens (token_id, data) VALUES ($1, $2) ON CONFLICT (token_id) DO UPDATE SET data = $2`, key, v)
		return err
	case "audit_log":
		var entry AuditEntry
		if err := json.Unmarshal(v, &entry); err != nil {
			return nil
		}
		_, err := target.db.Exec(`INSERT INTO sa_audit_log (id, timestamp, data) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, entry.ID, entry.Timestamp, v)
		return err
	case "oidc_auth_codes":
		var ac OIDCAuthCode
		if err := json.Unmarshal(v, &ac); err != nil {
			return nil
		}
		_, err := target.db.Exec(`INSERT INTO sa_oidc_auth_codes (code, data, expires_at) VALUES ($1, $2, $3) ON CONFLICT (code) DO NOTHING`, key, v, ac.ExpiresAt)
		return err
	case "sessions":
		var sess Session
		if err := json.Unmarshal(v, &sess); err != nil {
			return nil
		}
		_, err := target.db.Exec(`INSERT INTO sa_sessions (id, user_guid, created_at, last_used_at, expires_at, user_agent, ip) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`,
			sess.ID, sess.UserGUID, sess.CreatedAt, sess.LastUsedAt, sess.ExpiresAt, sess.UserAgent, sess.IP)
		return err
	case "revoked_tokens":
		var expiresAt time.Time
		if err := json.Unmarshal(v, &expiresAt); err != nil {
			return nil
		}
		_, err := target.db.Exec(`INSERT INTO sa_revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING`, key, expiresAt)
		return err
	case "revoked_users":
		var expiresAt time.Time
		if err := json.Unmarshal(v, &expiresAt); err != nil {
			return nil
		}
		_, err := target.db.Exec(`INSERT INTO sa_revoked_users (user_guid, expires_at) VALUES ($1, $2) ON CONFLICT (user_guid) DO UPDATE SET expires_at = $2`, key, expiresAt)
		return err
	case "apps":
		_, err := target.db.Exec(`INSERT INTO sa_apps (app_id, data) VALUES ($1, $2) ON CONFLICT (app_id) DO UPDATE SET data = $2`, key, v)
		return err
	case "app_authz":
		_, err := target.db.Exec(`INSERT INTO sa_app_authz (app_id, data) VALUES ($1, $2) ON CONFLICT (app_id) DO UPDATE SET data = $2`, key, v)
		return err
	case "app_admins":
		var a AppAdmin
		if err := json.Unmarshal(v, &a); err != nil {
			return nil
		}
		_, err := target.db.Exec(`INSERT INTO sa_app_admins (app_id, user_guid, added_by, added_at) VALUES ($1, $2, $3, $4) ON CONFLICT (app_id, user_guid) DO NOTHING`, a.AppID, a.UserGUID, a.AddedBy, a.AddedAt)
		return err
	default:
		return nil
	}
}

// ============================================================================
//  PostgreSQL → BoltDB
// ============================================================================

// MigrateFromPostgres copies all data from a PostgresStore to a fresh BoltStore.
// Source is never modified. Target BoltDB is opened fresh (empty).
func MigrateFromPostgres(source *PostgresStore, target *BoltStore, statusCh chan<- MigrationStatus) error {
	m := newMigrationHelper(statusCh)

	tables := []struct {
		name  string
		table string
		query string
	}{
		{"users", "sa_users", `SELECT guid, data FROM sa_users`},
		{"identity_mappings", "sa_identity_mappings", `SELECT provider, external_id, user_guid FROM sa_identity_mappings`},
		{"user_roles", "sa_user_roles", `SELECT guid, roles FROM sa_user_roles`},
		{"user_permissions", "sa_user_permissions", `SELECT guid, permissions FROM sa_user_permissions`},
		{"config", "sa_config", `SELECT key, value FROM sa_config`},
		{"refresh_tokens", "sa_refresh_tokens", `SELECT token_id, data FROM sa_refresh_tokens`},
		{"audit_log", "sa_audit_log", `SELECT id, data FROM sa_audit_log`},
		{"oidc_auth_codes", "sa_oidc_auth_codes", `SELECT code, data FROM sa_oidc_auth_codes`},
		{"sessions", "sa_sessions", `SELECT id, user_guid, created_at, last_used_at, expires_at, user_agent, ip FROM sa_sessions`},
		{"revoked_tokens", "sa_revoked_tokens", `SELECT jti, expires_at FROM sa_revoked_tokens`},
		{"revoked_users", "sa_revoked_users", `SELECT user_guid, expires_at FROM sa_revoked_users`},
		{"apps", "sa_apps", `SELECT app_id, data FROM sa_apps`},
		{"app_authz", "sa_app_authz", `SELECT app_id, data FROM sa_app_authz`},
		{"app_admins", "sa_app_admins", `SELECT app_id, user_guid, added_by, added_at FROM sa_app_admins`},
	}

	// Count totals
	sourceCounts := map[string]int64{}
	for _, t := range tables {
		var count int64
		source.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", t.table)).Scan(&count)
		sourceCounts[t.name] = count
		m.status.TotalItems += count
	}
	m.send()

	// Clean slate. admin_migration reopens OpenBolt(dataDir), so the target may
	// be an existing auth.db reused on the same data dir (e.g. the deployment
	// previously ran on BoltDB, switched to Postgres, and is now migrating back).
	// Wipe every bucket we are about to repopulate so stale users, sessions,
	// refresh tokens and — most importantly — the revoked-tokens / revoked-users
	// blacklists from the prior BoltDB era cannot resurface, which would make
	// already-revoked credentials valid again.
	migratedBuckets := [][]byte{
		bucketUsers, bucketIdentityMappings, bucketIdxMappingsByGUID,
		bucketUserRoles, bucketUserPermissions, bucketConfig,
		bucketRefreshTokens, bucketAuditLog, bucketOIDCAuthCodes,
		bucketSessions, bucketRevokedTokens, bucketRevokedUsers,
		bucketApps, bucketAppAuthz, bucketAppAdmins,
	}
	if err := target.db.Update(func(tx *bolt.Tx) error {
		for _, name := range migratedBuckets {
			if tx.Bucket(name) != nil {
				if err := tx.DeleteBucket(name); err != nil {
					return err
				}
			}
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return m.fail(fmt.Errorf("clear target buckets: %w", err))
	}

	// Copy each table
	for _, t := range tables {
		m.status.Progress[t.name] = "migrating"
		m.send()

		rows, err := source.db.Query(t.query)
		if err != nil {
			return m.fail(fmt.Errorf("query %s: %w", t.name, err))
		}

		for rows.Next() {
			var writeErr error
			switch t.name {
			case "users":
				var guid string
				var data []byte
				rows.Scan(&guid, &data)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketUsers).Put([]byte(guid), data)
				})
			case "identity_mappings":
				var provider, externalID, userGUID string
				rows.Scan(&provider, &externalID, &userGUID)
				writeErr = target.SetIdentityMapping(provider, externalID, userGUID)
			case "user_roles":
				var guid string
				var roles []byte
				rows.Scan(&guid, &roles)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketUserRoles).Put([]byte(guid), roles)
				})
			case "user_permissions":
				var guid string
				var perms []byte
				rows.Scan(&guid, &perms)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketUserPermissions).Put([]byte(guid), perms)
				})
			case "config":
				var key string
				var value []byte
				rows.Scan(&key, &value)
				writeErr = target.SetConfigValue(key, value)
			case "refresh_tokens":
				var tokenID string
				var data []byte
				rows.Scan(&tokenID, &data)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketRefreshTokens).Put([]byte(tokenID), data)
				})
			case "audit_log":
				var id string
				var data []byte
				rows.Scan(&id, &data)
				var entry AuditEntry
				if json.Unmarshal(data, &entry) == nil {
					key := []byte(entry.Timestamp.Format(time.RFC3339Nano) + ":" + entry.ID)
					writeErr = target.db.Update(func(tx *bolt.Tx) error {
						return tx.Bucket(bucketAuditLog).Put(key, data)
					})
				}
			case "oidc_auth_codes":
				var code string
				var data []byte
				rows.Scan(&code, &data)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketOIDCAuthCodes).Put([]byte(code), data)
				})
			case "sessions":
				var sess Session
				var ua, ip sql.NullString
				rows.Scan(&sess.ID, &sess.UserGUID, &sess.CreatedAt, &sess.LastUsedAt, &sess.ExpiresAt, &ua, &ip)
				sess.UserAgent = ua.String
				sess.IP = ip.String
				data, _ := json.Marshal(&sess)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketSessions).Put([]byte(sess.ID), data)
				})
			case "revoked_tokens":
				var jti string
				var expiresAt time.Time
				rows.Scan(&jti, &expiresAt)
				data, _ := json.Marshal(expiresAt)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketRevokedTokens).Put([]byte(jti), data)
				})
			case "revoked_users":
				var userGUID string
				var expiresAt time.Time
				rows.Scan(&userGUID, &expiresAt)
				data, _ := json.Marshal(expiresAt)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketRevokedUsers).Put([]byte(userGUID), data)
				})
			case "apps":
				var appID string
				var data []byte
				rows.Scan(&appID, &data)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketApps).Put([]byte(appID), data)
				})
			case "app_authz":
				var appID string
				var data []byte
				rows.Scan(&appID, &data)
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketAppAuthz).Put([]byte(appID), data)
				})
			case "app_admins":
				var appID, guid, addedBy string
				var addedAt time.Time
				rows.Scan(&appID, &guid, &addedBy, &addedAt)
				data, _ := json.Marshal(&AppAdmin{AppID: appID, UserGUID: guid, AddedBy: addedBy, AddedAt: addedAt})
				writeErr = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketAppAdmins).Put(appAdminKey(appID, guid), data)
				})
			}
			if writeErr != nil {
				rows.Close()
				return m.fail(fmt.Errorf("write %s: %w", t.name, writeErr))
			}
			m.status.MigratedItems++
			if m.status.MigratedItems%50 == 0 {
				m.send()
			}
		}
		rows.Close()

		m.status.Progress[t.name] = "done"
		m.send()
	}

	// Verify row counts
	m.status.State = "verifying"
	m.send()
	for _, t := range tables {
		// identity_mappings: BoltDB stores forward + reverse index entries, so its
		// bucket count legitimately differs from the SQL row count — skip strict
		// verification for it (but it was still cleared + recopied above).
		if t.name == "identity_mappings" {
			continue
		}
		expected := sourceCounts[t.name]
		var actual int64
		target.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(t.name))
			if b == nil {
				return nil
			}
			b.ForEach(func(k, v []byte) error { actual++; return nil })
			return nil
		})
		// Verify even when expected == 0: after the clean-slate wipe the bucket
		// must be empty, so a non-zero actual means stale data leaked through.
		if actual != expected {
			return m.fail(fmt.Errorf("verification failed for %s: expected %d rows, got %d", t.name, expected, actual))
		}
	}

	m.complete()
	return nil
}

// ============================================================================
//  Test Connection + Auto-Create Database
// ============================================================================

// TestPostgresConnection tests if a Postgres DSN is reachable.
// If the target database doesn't exist, it auto-creates it.
func TestPostgresConnection(dsn string) error {
	// First try connecting directly
	pg, err := OpenPostgres(dsn)
	if err == nil {
		pg.Close()
		return nil
	}

	// If it failed, try to auto-create the database
	if createErr := autoCreateDatabase(dsn); createErr != nil {
		return fmt.Errorf("%v (auto-create also failed: %v)", err, createErr)
	}

	// Retry after creation
	pg, err = OpenPostgres(dsn)
	if err != nil {
		return err
	}
	pg.Close()
	return nil
}

// autoCreateDatabase connects to the "postgres" maintenance DB and creates
// the target database if it doesn't exist.
func autoCreateDatabase(dsn string) error {
	dbName := ""
	maintDSN := dsn

	if idx := strings.LastIndex(dsn, "/"); idx > 0 {
		rest := dsn[idx+1:]
		if qIdx := strings.Index(rest, "?"); qIdx >= 0 {
			dbName = rest[:qIdx]
			maintDSN = dsn[:idx] + "/postgres" + rest[qIdx:]
		} else {
			dbName = rest
			maintDSN = dsn[:idx] + "/postgres"
		}
	}
	if dbName == "" || dbName == "postgres" {
		return fmt.Errorf("cannot determine database name from DSN")
	}

	db, err := sql.Open("pgx", maintDSN)
	if err != nil {
		return fmt.Errorf("connect to maintenance db: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}

	var exists bool
	err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbName).Scan(&exists)
	if err != nil {
		return fmt.Errorf("check database: %w", err)
	}
	if exists {
		return fmt.Errorf("database %q exists but connection failed", dbName)
	}

	// Validate database name (prevent SQL injection)
	for _, c := range dbName {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return fmt.Errorf("invalid database name %q", dbName)
		}
	}

	_, err = db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %q", dbName))
	if err != nil {
		return fmt.Errorf("create database %q: %w", dbName, err)
	}

	log.Printf("[store] Auto-created PostgreSQL database %q", dbName)
	return nil
}
