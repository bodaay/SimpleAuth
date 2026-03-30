package store

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"github.com/google/uuid"
)

var (
	bucketConfig           = []byte("config")
	bucketUsers            = []byte("users")
	bucketIdentityMappings = []byte("identity_mappings")
	bucketUserRoles        = []byte("user_roles")
	bucketUserPermissions  = []byte("user_permissions")
	bucketRefreshTokens    = []byte("refresh_tokens")
	bucketAuditLog         = []byte("audit_log")
	bucketIdxMappingsByGUID = []byte("idx_mappings_by_guid")
	bucketRegTokens        = []byte("reg_tokens")
	bucketOIDCAuthCodes    = []byte("oidc_auth_codes")
)

// BoltStore implements the Store interface using BoltDB (bbolt).
type BoltStore struct {
	db *bolt.DB
}

// OpenBolt creates a new BoltStore.
func OpenBolt(dataDir string) (*BoltStore, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	dbPath := filepath.Join(dataDir, "auth.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}
	s := &BoltStore{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	s.migrateRolesAndPermissions()
	return s, nil
}

func (s *BoltStore) Close() error {
	return s.db.Close()
}

func (s *BoltStore) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			bucketConfig, bucketUsers,
			bucketIdentityMappings, bucketUserRoles, bucketUserPermissions,
			bucketRefreshTokens, bucketAuditLog,
			bucketIdxMappingsByGUID,
			bucketRegTokens,
			bucketOIDCAuthCodes,
		} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

// migrateRolesAndPermissions ensures any roles already assigned to users
// are registered in the role registry, and any permissions already assigned
// to users or roles are registered in the permissions registry.
// Runs once on startup so existing data isn't rejected by the new validation.
func (s *BoltStore) migrateRolesAndPermissions() {
	// Collect all roles assigned to users
	roleSet := map[string]struct{}{}
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUserRoles).ForEach(func(k, v []byte) error {
			var roles []string
			if json.Unmarshal(v, &roles) == nil {
				for _, r := range roles {
					roleSet[r] = struct{}{}
				}
			}
			return nil
		})
	})

	// Collect all permissions assigned to users
	permSet := map[string]struct{}{}
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUserPermissions).ForEach(func(k, v []byte) error {
			var perms []string
			if json.Unmarshal(v, &perms) == nil {
				for _, p := range perms {
					permSet[p] = struct{}{}
				}
			}
			return nil
		})
	})

	// Merge user-assigned roles into role registry
	mapping, _ := s.GetRolePermissions()
	if mapping == nil {
		mapping = map[string][]string{}
	}
	changed := false
	for r := range roleSet {
		if _, exists := mapping[r]; !exists {
			mapping[r] = []string{}
			changed = true
		}
	}
	if changed {
		_ = s.SetRolePermissions(mapping)
	}

	// Also collect permissions from role mappings
	for _, perms := range mapping {
		for _, p := range perms {
			permSet[p] = struct{}{}
		}
	}

	// Merge into permissions registry
	defined, _ := s.GetDefinedPermissions()
	defSet := map[string]struct{}{}
	for _, p := range defined {
		defSet[p] = struct{}{}
	}
	permChanged := false
	for p := range permSet {
		if _, exists := defSet[p]; !exists {
			defined = append(defined, p)
			permChanged = true
		}
	}
	if permChanged {
		sort.Strings(defined)
		_ = s.SetDefinedPermissions(defined)
	}
}

// --- Users ---

func (s *BoltStore) CreateUser(u *User) error {
	if u.GUID == "" {
		u.GUID = uuid.New().String()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(u)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUsers).Put([]byte(u.GUID), data)
	})
}

func (s *BoltStore) GetUser(guid string) (*User, error) {
	var u User
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketUsers).Get([]byte(guid))
		if data == nil {
			return fmt.Errorf("user not found: %s", guid)
		}
		return json.Unmarshal(data, &u)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ResolveUser follows merged_into chains to find the active user.
func (s *BoltStore) ResolveUser(guid string) (*User, error) {
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

func (s *BoltStore) UpdateUser(u *User) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		existing := tx.Bucket(bucketUsers).Get([]byte(u.GUID))
		if existing == nil {
			return fmt.Errorf("user not found: %s", u.GUID)
		}
		data, err := json.Marshal(u)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUsers).Put([]byte(u.GUID), data)
	})
}

func (s *BoltStore) DeleteUser(guid string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUsers).Delete([]byte(guid))
	})
}

func (s *BoltStore) ListUsers() ([]*User, error) {
	var users []*User
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUsers).ForEach(func(k, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			users = append(users, &u)
			return nil
		})
	})
	return users, err
}

// --- LDAP Config (single) ---

func (s *BoltStore) GetLDAPConfig() (*LDAPConfig, error) {
	var cfg LDAPConfig
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketConfig).Get([]byte("ldap:config"))
		if data == nil {
			return fmt.Errorf("ldap not configured")
		}
		return json.Unmarshal(data, &cfg)
	})
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *BoltStore) SaveLDAPConfig(cfg *LDAPConfig) error {
	if cfg.ConfiguredAt.IsZero() {
		cfg.ConfiguredAt = time.Now().UTC()
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketConfig).Put([]byte("ldap:config"), data)
	})
}

func (s *BoltStore) DeleteLDAPConfig() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Delete([]byte("ldap:config"))
	})
}

// --- Identity Mappings ---

func mappingKey(provider, externalID string) []byte {
	return []byte(provider + ":" + externalID)
}

func (s *BoltStore) SetIdentityMapping(provider, externalID, userGUID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := mappingKey(provider, externalID)
		if err := tx.Bucket(bucketIdentityMappings).Put(key, []byte(userGUID)); err != nil {
			return err
		}
		// Update reverse index
		return s.addMappingToIndex(tx, userGUID, IdentityMapping{Provider: provider, ExternalID: externalID})
	})
}

func (s *BoltStore) ResolveMapping(provider, externalID string) (string, error) {
	var guid string
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketIdentityMappings).Get(mappingKey(provider, externalID))
		if v == nil {
			return fmt.Errorf("mapping not found: %s:%s", provider, externalID)
		}
		guid = string(v)
		return nil
	})
	return guid, err
}

func (s *BoltStore) DeleteIdentityMapping(provider, externalID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := mappingKey(provider, externalID)
		// Find the GUID first for reverse index cleanup
		guid := tx.Bucket(bucketIdentityMappings).Get(key)
		if guid == nil {
			return nil
		}
		if err := tx.Bucket(bucketIdentityMappings).Delete(key); err != nil {
			return err
		}
		return s.removeMappingFromIndex(tx, string(guid), IdentityMapping{Provider: provider, ExternalID: externalID})
	})
}

func (s *BoltStore) GetMappingsForUser(userGUID string) ([]IdentityMapping, error) {
	var mappings []IdentityMapping
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketIdxMappingsByGUID).Get([]byte(userGUID))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &mappings)
	})
	return mappings, err
}

func (s *BoltStore) addMappingToIndex(tx *bolt.Tx, userGUID string, m IdentityMapping) error {
	var mappings []IdentityMapping
	data := tx.Bucket(bucketIdxMappingsByGUID).Get([]byte(userGUID))
	if data != nil {
		json.Unmarshal(data, &mappings)
	}
	// Avoid duplicates
	for _, existing := range mappings {
		if existing.Provider == m.Provider && existing.ExternalID == m.ExternalID {
			return nil
		}
	}
	mappings = append(mappings, m)
	newData, err := json.Marshal(mappings)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketIdxMappingsByGUID).Put([]byte(userGUID), newData)
}

func (s *BoltStore) removeMappingFromIndex(tx *bolt.Tx, userGUID string, m IdentityMapping) error {
	var mappings []IdentityMapping
	data := tx.Bucket(bucketIdxMappingsByGUID).Get([]byte(userGUID))
	if data == nil {
		return nil
	}
	json.Unmarshal(data, &mappings)
	var filtered []IdentityMapping
	for _, existing := range mappings {
		if existing.Provider == m.Provider && existing.ExternalID == m.ExternalID {
			continue
		}
		filtered = append(filtered, existing)
	}
	if len(filtered) == 0 {
		return tx.Bucket(bucketIdxMappingsByGUID).Delete([]byte(userGUID))
	}
	newData, err := json.Marshal(filtered)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketIdxMappingsByGUID).Put([]byte(userGUID), newData)
}

func (s *BoltStore) ListAllMappings() ([]IdentityMappingEntry, error) {
	var result []IdentityMappingEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketIdentityMappings)
		return b.ForEach(func(k, v []byte) error {
			key := string(k)
			idx := strings.Index(key, ":")
			if idx < 0 {
				return nil
			}
			result = append(result, IdentityMappingEntry{
				Provider:   key[:idx],
				ExternalID: key[idx+1:],
				UserGUID:   string(v),
			})
			return nil
		})
	})
	return result, err
}

// --- Roles & Permissions (no app scoping) ---

func (s *BoltStore) SetUserRoles(guid string, roles []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(roles)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUserRoles).Put([]byte(guid), data)
	})
}

func (s *BoltStore) GetUserRoles(guid string) ([]string, error) {
	var roles []string
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketUserRoles).Get([]byte(guid))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &roles)
	})
	return roles, err
}

func (s *BoltStore) SetUserPermissions(guid string, perms []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(perms)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUserPermissions).Put([]byte(guid), data)
	})
}

func (s *BoltStore) GetUserPermissions(guid string) ([]string, error) {
	var perms []string
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketUserPermissions).Get([]byte(guid))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &perms)
	})
	return perms, err
}

// ListAllRoles returns all defined roles (from the role registry).
func (s *BoltStore) ListAllRoles() ([]string, error) {
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

// ListAllPermissions returns all defined permissions (from the master list).
func (s *BoltStore) ListAllPermissions() ([]string, error) {
	return s.GetDefinedPermissions()
}

// --- Config (generic key-value in config bucket) ---

func (s *BoltStore) SetConfigValue(key string, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Put([]byte(key), value)
	})
}

func (s *BoltStore) GetConfigValue(key string) ([]byte, error) {
	var val []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketConfig).Get([]byte(key))
		if data != nil {
			val = make([]byte, len(data))
			copy(val, data)
		}
		return nil
	})
	return val, err
}

func (s *BoltStore) DeleteConfigValue(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Delete([]byte(key))
	})
}

// --- Default Roles ---

func (s *BoltStore) GetDefaultRoles() ([]string, error) {
	var roles []string
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketConfig).Get([]byte("default_roles"))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &roles)
	})
	return roles, err
}

func (s *BoltStore) SetDefaultRoles(roles []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(roles)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketConfig).Put([]byte("default_roles"), data)
	})
}

// --- Role → Permissions Mapping (role registry) ---

// GetRolePermissions returns the role→permissions mapping.
// This is also the role registry: keys are all defined roles.
func (s *BoltStore) GetRolePermissions() (map[string][]string, error) {
	var mapping map[string][]string
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketConfig).Get([]byte("role_permissions"))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &mapping)
	})
	return mapping, err
}

// SetRolePermissions sets the role→permissions mapping.
func (s *BoltStore) SetRolePermissions(mapping map[string][]string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(mapping)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketConfig).Put([]byte("role_permissions"), data)
	})
}

// RoleExists checks if a role is defined in the role registry.
func (s *BoltStore) RoleExists(role string) (bool, error) {
	mapping, err := s.GetRolePermissions()
	if err != nil {
		return false, err
	}
	if mapping == nil {
		return false, nil
	}
	_, exists := mapping[role]
	return exists, nil
}

// GetDefinedPermissions returns the master list of defined permissions.
func (s *BoltStore) GetDefinedPermissions() ([]string, error) {
	var perms []string
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketConfig).Get([]byte("defined_permissions"))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &perms)
	})
	return perms, err
}

// SetDefinedPermissions sets the master list of defined permissions.
func (s *BoltStore) SetDefinedPermissions(perms []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(perms)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketConfig).Put([]byte("defined_permissions"), data)
	})
}

// PermissionExists checks if a permission is defined in the master list.
func (s *BoltStore) PermissionExists(perm string) (bool, error) {
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

// ValidateRolesExist checks that all given roles exist in the role registry.
// Returns the first invalid role name, or empty string if all valid.
func (s *BoltStore) ValidateRolesExist(roles []string) (string, error) {
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

// ValidatePermissionsExist checks that all given permissions exist in the master list.
// Returns the first invalid permission name, or empty string if all valid.
func (s *BoltStore) ValidatePermissionsExist(perms []string) (string, error) {
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

// ResolvePermissions expands roles into permissions using the role→permissions mapping,
// then merges with direct permissions (deduplicated).
func (s *BoltStore) ResolvePermissions(roles, directPerms []string) ([]string, error) {
	mapping, err := s.GetRolePermissions()
	if err != nil {
		return directPerms, err
	}
	if mapping == nil {
		return directPerms, nil
	}

	seen := make(map[string]bool)
	var merged []string
	// Role-derived permissions first
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
	// Then direct permissions
	for _, p := range directPerms {
		if !seen[p] {
			seen[p] = true
			merged = append(merged, p)
		}
	}
	return merged, nil
}

// --- Refresh Tokens ---

func (s *BoltStore) SaveRefreshToken(rt *RefreshToken) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(rt)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketRefreshTokens).Put([]byte(rt.TokenID), data)
	})
}

func (s *BoltStore) GetRefreshToken(tokenID string) (*RefreshToken, error) {
	var rt RefreshToken
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketRefreshTokens).Get([]byte(tokenID))
		if data == nil {
			return fmt.Errorf("refresh token not found")
		}
		return json.Unmarshal(data, &rt)
	})
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (s *BoltStore) MarkRefreshTokenUsed(tokenID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketRefreshTokens).Get([]byte(tokenID))
		if data == nil {
			return fmt.Errorf("refresh token not found")
		}
		var rt RefreshToken
		if err := json.Unmarshal(data, &rt); err != nil {
			return err
		}
		rt.Used = true
		newData, err := json.Marshal(&rt)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketRefreshTokens).Put([]byte(tokenID), newData)
	})
}

// RevokeTokenFamily deletes all refresh tokens belonging to a family.
func (s *BoltStore) RevokeTokenFamily(familyID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRefreshTokens)
		var toDelete [][]byte
		b.ForEach(func(k, v []byte) error {
			var rt RefreshToken
			if err := json.Unmarshal(v, &rt); err == nil && rt.FamilyID == familyID {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListUserSessions returns active (non-expired, non-used) refresh tokens for a user.
func (s *BoltStore) ListUserSessions(userGUID string) ([]*RefreshToken, error) {
	var sessions []*RefreshToken
	now := time.Now()
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRefreshTokens).ForEach(func(k, v []byte) error {
			var rt RefreshToken
			if err := json.Unmarshal(v, &rt); err != nil {
				return nil
			}
			if rt.UserGUID == userGUID && !rt.Used && rt.ExpiresAt.After(now) {
				sessions = append(sessions, &rt)
			}
			return nil
		})
	})
	return sessions, err
}

// RevokeUserTokens deletes all refresh tokens for a user.
func (s *BoltStore) RevokeUserTokens(userGUID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRefreshTokens)
		var toDelete [][]byte
		b.ForEach(func(k, v []byte) error {
			var rt RefreshToken
			if err := json.Unmarshal(v, &rt); err == nil && rt.UserGUID == userGUID {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// --- Audit Log ---

func (s *BoltStore) WriteAuditLog(entry *AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		key := []byte(entry.Timestamp.Format(time.RFC3339Nano) + ":" + entry.ID)
		return tx.Bucket(bucketAuditLog).Put(key, data)
	})
}

func (s *BoltStore) QueryAuditLog(q AuditQuery) ([]*AuditEntry, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	var entries []*AuditEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAuditLog).Cursor()
		skipped := 0
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var entry AuditEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				continue
			}
			if !q.From.IsZero() && entry.Timestamp.Before(q.From) {
				break
			}
			if !q.To.IsZero() && entry.Timestamp.After(q.To) {
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
		return nil
	})
	return entries, err
}

func (s *BoltStore) PruneAuditLog(retention time.Duration) error {
	cutoff := time.Now().UTC().Add(-retention)
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAuditLog)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var entry AuditEntry
			if err := json.Unmarshal(v, &entry); err != nil {
				continue
			}
			if entry.Timestamp.Before(cutoff) {
				b.Delete(k)
			} else {
				break
			}
		}
		return nil
	})
}

// --- User Merge ---

func (s *BoltStore) MergeUsers(sourceGUIDs []string, displayName, email string) (*User, error) {
	newUser := &User{
		GUID:        uuid.New().String(),
		DisplayName: displayName,
		Email:       email,
		CreatedAt:   time.Now().UTC(),
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		// Create the new user
		userData, err := json.Marshal(newUser)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bucketUsers).Put([]byte(newUser.GUID), userData); err != nil {
			return err
		}

		allRoles := map[string]bool{}
		allPerms := map[string]bool{}

		for _, srcGUID := range sourceGUIDs {
			// Get source user
			srcData := tx.Bucket(bucketUsers).Get([]byte(srcGUID))
			if srcData == nil {
				return fmt.Errorf("source user not found: %s", srcGUID)
			}

			// Move identity mappings
			mappingsData := tx.Bucket(bucketIdxMappingsByGUID).Get([]byte(srcGUID))
			if mappingsData != nil {
				var mappings []IdentityMapping
				json.Unmarshal(mappingsData, &mappings)
				for _, m := range mappings {
					key := mappingKey(m.Provider, m.ExternalID)
					tx.Bucket(bucketIdentityMappings).Put(key, []byte(newUser.GUID))
					s.addMappingToIndex(tx, newUser.GUID, m)
				}
				tx.Bucket(bucketIdxMappingsByGUID).Delete([]byte(srcGUID))
			}

			// Collect roles
			rolesData := tx.Bucket(bucketUserRoles).Get([]byte(srcGUID))
			if rolesData != nil {
				var roles []string
				json.Unmarshal(rolesData, &roles)
				for _, r := range roles {
					allRoles[r] = true
				}
				tx.Bucket(bucketUserRoles).Delete([]byte(srcGUID))
			}

			// Collect permissions
			permsData := tx.Bucket(bucketUserPermissions).Get([]byte(srcGUID))
			if permsData != nil {
				var perms []string
				json.Unmarshal(permsData, &perms)
				for _, p := range perms {
					allPerms[p] = true
				}
				tx.Bucket(bucketUserPermissions).Delete([]byte(srcGUID))
			}

			// Mark source as merged
			var srcUser User
			json.Unmarshal(srcData, &srcUser)
			srcUser.MergedInto = newUser.GUID
			mergedData, _ := json.Marshal(&srcUser)
			tx.Bucket(bucketUsers).Put([]byte(srcGUID), mergedData)
		}

		// Write merged roles
		if len(allRoles) > 0 {
			var roles []string
			for r := range allRoles {
				roles = append(roles, r)
			}
			data, _ := json.Marshal(roles)
			tx.Bucket(bucketUserRoles).Put([]byte(newUser.GUID), data)
		}
		// Write merged permissions
		if len(allPerms) > 0 {
			var perms []string
			for p := range allPerms {
				perms = append(perms, p)
			}
			data, _ := json.Marshal(perms)
			tx.Bucket(bucketUserPermissions).Put([]byte(newUser.GUID), data)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	return newUser, nil
}

func (s *BoltStore) UnmergeUser(guid string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketUsers).Get([]byte(guid))
		if data == nil {
			return fmt.Errorf("user not found: %s", guid)
		}
		var u User
		if err := json.Unmarshal(data, &u); err != nil {
			return err
		}
		if u.MergedInto == "" {
			return fmt.Errorf("user %s is not merged", guid)
		}
		u.MergedInto = ""
		newData, err := json.Marshal(&u)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUsers).Put([]byte(guid), newData)
	})
}

// --- Backup ---

func (s *BoltStore) Backup(path string) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return tx.CopyFile(path, 0600)
	})
}

func (s *BoltStore) BackupWriter(w io.Writer) error {
	return s.db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(w)
		return err
	})
}

// Restore replaces the current database with data from an io.Reader.
// It closes the current DB, writes the new file, and reopens.
func (s *BoltStore) Restore(r io.Reader) error {
	dbPath := s.db.Path()

	// Close current DB
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close current db: %w", err)
	}

	// Write backup to a temp file first, then rename (atomic)
	tmpPath := dbPath + ".restore.tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		// Try to reopen old DB
		s.reopen(dbPath)
		return fmt.Errorf("create temp file: %w", err)
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmpPath)
		s.reopen(dbPath)
		return fmt.Errorf("write restore data: %w", err)
	}
	f.Close()

	// Validate: try opening the uploaded file as a BoltDB
	testDB, err := bolt.Open(tmpPath, 0600, &bolt.Options{ReadOnly: true, Timeout: 3 * time.Second})
	if err != nil {
		os.Remove(tmpPath)
		s.reopen(dbPath)
		return fmt.Errorf("invalid backup file: %w", err)
	}
	testDB.Close()

	// Replace
	if err := os.Rename(tmpPath, dbPath); err != nil {
		os.Remove(tmpPath)
		s.reopen(dbPath)
		return fmt.Errorf("replace db file: %w", err)
	}

	// Reopen
	return s.reopen(dbPath)
}

func (s *BoltStore) reopen(dbPath string) error {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return fmt.Errorf("reopen db: %w", err)
	}
	s.db = db
	return nil
}

// --- OIDC Authorization Codes ---

func (s *BoltStore) SaveOIDCAuthCode(code *OIDCAuthCode) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(code)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketOIDCAuthCodes).Put([]byte(code.Code), data)
	})
}

// ConsumeOIDCAuthCode retrieves and deletes an auth code atomically.
func (s *BoltStore) ConsumeOIDCAuthCode(code string) (*OIDCAuthCode, error) {
	var ac OIDCAuthCode
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketOIDCAuthCodes)
		data := b.Get([]byte(code))
		if data == nil {
			return fmt.Errorf("auth code not found")
		}
		if err := json.Unmarshal(data, &ac); err != nil {
			return err
		}
		if time.Now().After(ac.ExpiresAt) {
			b.Delete([]byte(code))
			return fmt.Errorf("auth code expired")
		}
		// Delete after consumption (single-use)
		return b.Delete([]byte(code))
	})
	if err != nil {
		return nil, err
	}
	return &ac, nil
}
