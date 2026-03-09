package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func New(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, err
	}

	dbPath := filepath.Join(dataDir, "auth.db")
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS config (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT ''
		);

		CREATE TABLE IF NOT EXISTS users (
			username      TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL DEFAULT '',
			display_name  TEXT NOT NULL DEFAULT '',
			email         TEXT NOT NULL DEFAULT '',
			disabled      BOOLEAN NOT NULL DEFAULT FALSE,
			created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS user_roles (
			username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
			role     TEXT NOT NULL,
			PRIMARY KEY (username, role)
		);

		CREATE TABLE IF NOT EXISTS user_permissions (
			username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
			permission TEXT NOT NULL,
			PRIMARY KEY (username, permission)
		);
	`)
	return err
}

// --- Config (LDAP settings) ---

type LDAPConfig struct {
	URL             string `json:"url"`
	BaseDN          string `json:"base_dn"`
	BindDN          string `json:"bind_dn"`
	BindPassword    string `json:"bind_password"`
	UserFilter      string `json:"user_filter"`
	UseTLS          bool   `json:"use_tls"`
	SkipTLSVerify   bool   `json:"skip_tls_verify"`
	DisplayNameAttr string `json:"display_name_attr"`
	EmailAttr       string `json:"email_attr"`
	GroupsAttr      string `json:"groups_attr"`
}

var ldapConfigKeys = []string{
	"ldap_url", "ldap_base_dn", "ldap_bind_dn", "ldap_bind_password",
	"ldap_user_filter", "ldap_use_tls", "ldap_skip_tls_verify",
	"ldap_display_name_attr", "ldap_email_attr", "ldap_groups_attr",
}

func (s *Store) GetLDAP() *LDAPConfig {
	cfg := &LDAPConfig{}
	var val string

	for _, key := range ldapConfigKeys {
		err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&val)
		if err != nil {
			continue
		}
		switch key {
		case "ldap_url":
			cfg.URL = val
		case "ldap_base_dn":
			cfg.BaseDN = val
		case "ldap_bind_dn":
			cfg.BindDN = val
		case "ldap_bind_password":
			cfg.BindPassword = val
		case "ldap_user_filter":
			cfg.UserFilter = val
		case "ldap_use_tls":
			cfg.UseTLS = val == "true"
		case "ldap_skip_tls_verify":
			cfg.SkipTLSVerify = val == "true"
		case "ldap_display_name_attr":
			cfg.DisplayNameAttr = val
		case "ldap_email_attr":
			cfg.EmailAttr = val
		case "ldap_groups_attr":
			cfg.GroupsAttr = val
		}
	}

	if cfg.URL == "" {
		return nil
	}
	return cfg
}

func (s *Store) SetLDAP(cfg *LDAPConfig) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	set := func(key, value string) error {
		_, err := tx.Exec(
			"INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
			key, value, value,
		)
		return err
	}

	boolStr := func(b bool) string {
		if b {
			return "true"
		}
		return "false"
	}

	if err := set("ldap_url", cfg.URL); err != nil {
		return err
	}
	if err := set("ldap_base_dn", cfg.BaseDN); err != nil {
		return err
	}
	if err := set("ldap_bind_dn", cfg.BindDN); err != nil {
		return err
	}
	if err := set("ldap_bind_password", cfg.BindPassword); err != nil {
		return err
	}
	if err := set("ldap_user_filter", cfg.UserFilter); err != nil {
		return err
	}
	if err := set("ldap_use_tls", boolStr(cfg.UseTLS)); err != nil {
		return err
	}
	if err := set("ldap_skip_tls_verify", boolStr(cfg.SkipTLSVerify)); err != nil {
		return err
	}
	if err := set("ldap_display_name_attr", cfg.DisplayNameAttr); err != nil {
		return err
	}
	if err := set("ldap_email_attr", cfg.EmailAttr); err != nil {
		return err
	}
	if err := set("ldap_groups_attr", cfg.GroupsAttr); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) DeleteLDAP() error {
	_, err := s.db.Exec("DELETE FROM config WHERE key LIKE 'ldap_%'")
	return err
}

// --- Users ---

type User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"-"`
	DisplayName  string   `json:"display_name"`
	Email        string   `json:"email"`
	Disabled     bool     `json:"disabled"`
	Roles        []string `json:"roles"`
	Permissions  []string `json:"permissions"`
}

func (s *Store) GetUser(username string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(
		"SELECT username, password_hash, display_name, email, disabled FROM users WHERE username = ?",
		username,
	).Scan(&u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &u.Disabled)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	u.Roles, _ = s.getUserStrings("user_roles", "role", username)
	u.Permissions, _ = s.getUserStrings("user_permissions", "permission", username)
	return u, nil
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query("SELECT username, display_name, email, disabled FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.DisplayName, &u.Email, &u.Disabled); err != nil {
			return nil, err
		}
		u.Roles, _ = s.getUserStrings("user_roles", "role", u.Username)
		u.Permissions, _ = s.getUserStrings("user_permissions", "permission", u.Username)
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) CreateUser(username, passwordHash, displayName, email string) error {
	_, err := s.db.Exec(
		"INSERT INTO users (username, password_hash, display_name, email) VALUES (?, ?, ?, ?)",
		username, passwordHash, displayName, email,
	)
	return err
}

func (s *Store) UpdateUser(username, displayName, email string) error {
	_, err := s.db.Exec(
		"UPDATE users SET display_name = ?, email = ? WHERE username = ?",
		displayName, email, username,
	)
	return err
}

func (s *Store) SetPassword(username, passwordHash string) error {
	_, err := s.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", passwordHash, username)
	return err
}

func (s *Store) SetDisabled(username string, disabled bool) error {
	_, err := s.db.Exec("UPDATE users SET disabled = ? WHERE username = ?", disabled, username)
	return err
}

func (s *Store) DeleteUser(username string) error {
	_, err := s.db.Exec("DELETE FROM users WHERE username = ?", username)
	return err
}

// EnsureUser creates a user if they don't exist (used after LDAP auth).
func (s *Store) EnsureUser(username, displayName, email string) error {
	_, err := s.db.Exec(
		`INSERT INTO users (username, display_name, email) VALUES (?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET
		   display_name = CASE WHEN excluded.display_name != '' THEN excluded.display_name ELSE users.display_name END,
		   email = CASE WHEN excluded.email != '' THEN excluded.email ELSE users.email END`,
		username, displayName, email,
	)
	return err
}

// --- Roles ---

func (s *Store) SetRoles(username string, roles []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tx.Exec("DELETE FROM user_roles WHERE username = ?", username)
	for _, role := range roles {
		if role = strings.TrimSpace(role); role != "" {
			tx.Exec("INSERT INTO user_roles (username, role) VALUES (?, ?)", username, role)
		}
	}
	return tx.Commit()
}

func (s *Store) GetRoles(username string) ([]string, error) {
	return s.getUserStrings("user_roles", "role", username)
}

// --- Permissions ---

func (s *Store) SetPermissions(username string, perms []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tx.Exec("DELETE FROM user_permissions WHERE username = ?", username)
	for _, perm := range perms {
		if perm = strings.TrimSpace(perm); perm != "" {
			tx.Exec("INSERT INTO user_permissions (username, permission) VALUES (?, ?)", username, perm)
		}
	}
	return tx.Commit()
}

func (s *Store) GetPermissions(username string) ([]string, error) {
	return s.getUserStrings("user_permissions", "permission", username)
}

// --- Helpers ---

func (s *Store) getUserStrings(table, column, username string) ([]string, error) {
	rows, err := s.db.Query(
		fmt.Sprintf("SELECT %s FROM %s WHERE username = ? ORDER BY %s", column, table, column),
		username,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}

// --- Default Roles (assigned to new LDAP users) ---

func (s *Store) GetDefaultRoles() []string {
	var val string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = 'default_roles'").Scan(&val)
	if err != nil || val == "" {
		return []string{"user"}
	}
	return strings.Split(val, ",")
}

func (s *Store) SetDefaultRoles(roles []string) error {
	val := strings.Join(roles, ",")
	_, err := s.db.Exec(
		"INSERT INTO config (key, value) VALUES ('default_roles', ?) ON CONFLICT(key) DO UPDATE SET value = ?",
		val, val,
	)
	return err
}
