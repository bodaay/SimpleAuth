package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// MigrationStatus tracks progress of a BoltDB → Postgres migration.
type MigrationStatus struct {
	State         string            `json:"state"`          // idle, running, completed, failed
	Progress      map[string]string `json:"progress"`       // table → status
	TotalItems    int64             `json:"total_items"`
	MigratedItems int64             `json:"migrated_items"`
	StartedAt     int64             `json:"started_at,omitempty"`
	CompletedAt   int64             `json:"completed_at,omitempty"`
	Error         string            `json:"error,omitempty"`
}

// MigrateToPostgres copies all data from a BoltStore to a PostgresStore.
// Progress updates are sent on statusCh (non-blocking).
func MigrateToPostgres(source *BoltStore, target *PostgresStore, statusCh chan<- MigrationStatus) error {
	status := MigrationStatus{
		State:     "running",
		Progress:  map[string]string{},
		StartedAt: time.Now().Unix(),
	}
	send := func() {
		select {
		case statusCh <- status:
		default:
		}
	}

	// Reset target schema (drop + recreate) to ensure clean migration
	if err := target.ResetSchema(); err != nil {
		status.State = "failed"
		status.Error = fmt.Sprintf("reset target schema: %v", err)
		send()
		return err
	}

	// Count total items across all buckets
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
	}

	source.db.View(func(tx *bolt.Tx) error {
		for _, b := range buckets {
			bucket := tx.Bucket(b.bucket)
			if bucket == nil {
				continue
			}
			bucket.ForEach(func(k, v []byte) error {
				status.TotalItems++
				return nil
			})
		}
		return nil
	})

	send()

	// Migrate each bucket
	for _, b := range buckets {
		status.Progress[b.name] = "migrating"
		send()

		err := source.db.View(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(b.bucket)
			if bucket == nil {
				return nil
			}
			return bucket.ForEach(func(k, v []byte) error {
				if err := migrateKV(target, b.name, k, v); err != nil {
					return fmt.Errorf("migrate %s key=%s: %w", b.name, string(k), err)
				}
				status.MigratedItems++
				if status.MigratedItems%50 == 0 {
					send()
				}
				return nil
			})
		})

		if err != nil {
			status.State = "failed"
			status.Error = err.Error()
			send()
			return err
		}

		status.Progress[b.name] = "done"
		send()
	}

	status.State = "completed"
	status.CompletedAt = time.Now().Unix()
	send()
	return nil
}

// migrateKV inserts a single BoltDB key-value pair into the correct Postgres table.
func migrateKV(target *PostgresStore, table string, k, v []byte) error {
	key := string(k)

	switch table {
	case "users":
		_, err := target.db.Exec(
			`INSERT INTO users (guid, data) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET data = $2`,
			key, v,
		)
		return err

	case "identity_mappings":
		// Key is "provider:externalID", value is userGUID
		idx := strings.Index(key, ":")
		if idx < 0 {
			return nil
		}
		provider := key[:idx]
		externalID := key[idx+1:]
		_, err := target.db.Exec(
			`INSERT INTO identity_mappings (provider, external_id, user_guid) VALUES ($1, $2, $3)
			 ON CONFLICT (provider, external_id) DO UPDATE SET user_guid = $3`,
			provider, externalID, string(v),
		)
		return err

	case "idx_mappings_by_guid":
		// Skip — this is a reverse index that Postgres doesn't need (uses SQL index instead)
		return nil

	case "user_roles":
		_, err := target.db.Exec(
			`INSERT INTO user_roles (guid, roles) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET roles = $2`,
			key, v,
		)
		return err

	case "user_permissions":
		_, err := target.db.Exec(
			`INSERT INTO user_permissions (guid, permissions) VALUES ($1, $2) ON CONFLICT (guid) DO UPDATE SET permissions = $2`,
			key, v,
		)
		return err

	case "config":
		_, err := target.db.Exec(
			`INSERT INTO config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2`,
			key, v,
		)
		return err

	case "refresh_tokens":
		_, err := target.db.Exec(
			`INSERT INTO refresh_tokens (token_id, data) VALUES ($1, $2) ON CONFLICT (token_id) DO UPDATE SET data = $2`,
			key, v,
		)
		return err

	case "audit_log":
		// Key is "timestamp:id", value is JSON AuditEntry
		var entry AuditEntry
		if err := json.Unmarshal(v, &entry); err != nil {
			return nil // skip corrupt entries
		}
		_, err := target.db.Exec(
			`INSERT INTO audit_log (id, timestamp, data) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`,
			entry.ID, entry.Timestamp, v,
		)
		return err

	case "oidc_auth_codes":
		var ac OIDCAuthCode
		if err := json.Unmarshal(v, &ac); err != nil {
			return nil
		}
		_, err := target.db.Exec(
			`INSERT INTO oidc_auth_codes (code, data, expires_at) VALUES ($1, $2, $3) ON CONFLICT (code) DO NOTHING`,
			key, v, ac.ExpiresAt,
		)
		return err

	default:
		return nil
	}
}

// MigrateFromPostgres copies all data from a PostgresStore to a BoltStore.
func MigrateFromPostgres(source *PostgresStore, target *BoltStore, statusCh chan<- MigrationStatus) error {
	status := MigrationStatus{
		State:     "running",
		Progress:  map[string]string{},
		StartedAt: time.Now().Unix(),
	}
	send := func() {
		select {
		case statusCh <- status:
		default:
		}
	}

	tables := []struct {
		name  string
		query string
	}{
		{"users", `SELECT guid, data FROM users`},
		{"identity_mappings", `SELECT provider, external_id, user_guid FROM identity_mappings`},
		{"user_roles", `SELECT guid, roles FROM user_roles`},
		{"user_permissions", `SELECT guid, permissions FROM user_permissions`},
		{"config", `SELECT key, value FROM config`},
		{"refresh_tokens", `SELECT token_id, data FROM refresh_tokens`},
		{"audit_log", `SELECT id, data FROM audit_log`},
		{"oidc_auth_codes", `SELECT code, data FROM oidc_auth_codes`},
	}

	// Count totals
	for _, t := range tables {
		var count int64
		source.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", t.name)).Scan(&count)
		status.TotalItems += count
	}
	send()

	for _, t := range tables {
		status.Progress[t.name] = "migrating"
		send()

		rows, err := source.db.Query(t.query)
		if err != nil {
			status.State = "failed"
			status.Error = fmt.Sprintf("query %s: %v", t.name, err)
			send()
			return fmt.Errorf("query %s: %w", t.name, err)
		}

		for rows.Next() {
			var err error
			switch t.name {
			case "users":
				var guid string
				var data []byte
				rows.Scan(&guid, &data)
				err = target.SetConfigValue("__skip__", nil) // dummy to keep interface
				_ = err
				err = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketUsers).Put([]byte(guid), data)
				})
			case "identity_mappings":
				var provider, externalID, userGUID string
				rows.Scan(&provider, &externalID, &userGUID)
				err = target.SetIdentityMapping(provider, externalID, userGUID)
			case "user_roles":
				var guid string
				var roles []byte
				rows.Scan(&guid, &roles)
				err = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketUserRoles).Put([]byte(guid), roles)
				})
			case "user_permissions":
				var guid string
				var perms []byte
				rows.Scan(&guid, &perms)
				err = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketUserPermissions).Put([]byte(guid), perms)
				})
			case "config":
				var key string
				var value []byte
				rows.Scan(&key, &value)
				err = target.SetConfigValue(key, value)
			case "refresh_tokens":
				var tokenID string
				var data []byte
				rows.Scan(&tokenID, &data)
				err = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketRefreshTokens).Put([]byte(tokenID), data)
				})
			case "audit_log":
				var id string
				var data []byte
				rows.Scan(&id, &data)
				var entry AuditEntry
				if json.Unmarshal(data, &entry) == nil {
					key := []byte(entry.Timestamp.Format(time.RFC3339Nano) + ":" + entry.ID)
					err = target.db.Update(func(tx *bolt.Tx) error {
						return tx.Bucket(bucketAuditLog).Put(key, data)
					})
				}
			case "oidc_auth_codes":
				var code string
				var data []byte
				rows.Scan(&code, &data)
				err = target.db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket(bucketOIDCAuthCodes).Put([]byte(code), data)
				})
			}
			if err != nil {
				rows.Close()
				status.State = "failed"
				status.Error = fmt.Sprintf("migrate %s: %v", t.name, err)
				send()
				return fmt.Errorf("migrate %s: %w", t.name, err)
			}
			status.MigratedItems++
			if status.MigratedItems%50 == 0 {
				send()
			}
		}
		rows.Close()

		status.Progress[t.name] = "done"
		send()
	}

	status.State = "completed"
	status.CompletedAt = time.Now().Unix()
	send()
	return nil
}

// TestPostgresConnection tests if a Postgres DSN is reachable.
func TestPostgresConnection(dsn string) error {
	pg, err := OpenPostgres(dsn)
	if err != nil {
		return err
	}
	pg.Close()
	return nil
}
