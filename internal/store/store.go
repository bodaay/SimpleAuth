package store

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"github.com/google/uuid"
)

var (
	bucketConfig           = []byte("config")
	bucketLDAPProviders    = []byte("ldap_providers")
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

type Store struct {
	db *bolt.DB
}

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
}

type LDAPProvider struct {
	ProviderID      string    `json:"provider_id"`
	Name            string    `json:"name"`
	URL             string    `json:"url"`
	BaseDN          string    `json:"base_dn"`
	BindDN          string    `json:"bind_dn"`
	BindPassword    string    `json:"bind_password"`
	UserFilter      string    `json:"user_filter"`
	UseTLS          bool      `json:"use_tls"`
	SkipTLSVerify   bool      `json:"skip_tls_verify"`
	DisplayNameAttr string    `json:"display_name_attr"`
	EmailAttr       string    `json:"email_attr"`
	DepartmentAttr  string    `json:"department_attr"`
	CompanyAttr     string    `json:"company_attr"`
	JobTitleAttr    string    `json:"job_title_attr"`
	GroupsAttr      string    `json:"groups_attr"`
	Priority        int       `json:"priority"`
	CreatedAt       time.Time `json:"created_at"`
}

type IdentityMapping struct {
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
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

// --- Store Init ---

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	dbPath := filepath.Join(dataDir, "auth.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}
	s := &Store{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) init() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			bucketConfig, bucketLDAPProviders, bucketUsers,
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

// --- Users ---

func (s *Store) CreateUser(u *User) error {
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

func (s *Store) GetUser(guid string) (*User, error) {
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
func (s *Store) ResolveUser(guid string) (*User, error) {
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

func (s *Store) UpdateUser(u *User) error {
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

func (s *Store) DeleteUser(guid string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUsers).Delete([]byte(guid))
	})
}

func (s *Store) ListUsers() ([]*User, error) {
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

// --- LDAP Providers ---

func (s *Store) CreateLDAPProvider(p *LDAPProvider) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketLDAPProviders).Put([]byte(p.ProviderID), data)
	})
}

func (s *Store) GetLDAPProvider(providerID string) (*LDAPProvider, error) {
	var p LDAPProvider
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketLDAPProviders).Get([]byte(providerID))
		if data == nil {
			return fmt.Errorf("ldap provider not found: %s", providerID)
		}
		return json.Unmarshal(data, &p)
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) UpdateLDAPProvider(p *LDAPProvider) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketLDAPProviders).Put([]byte(p.ProviderID), data)
	})
}

func (s *Store) DeleteLDAPProvider(providerID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketLDAPProviders).Delete([]byte(providerID))
	})
}

func (s *Store) ListLDAPProviders() ([]*LDAPProvider, error) {
	var providers []*LDAPProvider
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketLDAPProviders).ForEach(func(k, v []byte) error {
			var p LDAPProvider
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			providers = append(providers, &p)
			return nil
		})
	})
	return providers, err
}

// --- Identity Mappings ---

func mappingKey(provider, externalID string) []byte {
	return []byte(provider + ":" + externalID)
}

func (s *Store) SetIdentityMapping(provider, externalID, userGUID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		key := mappingKey(provider, externalID)
		if err := tx.Bucket(bucketIdentityMappings).Put(key, []byte(userGUID)); err != nil {
			return err
		}
		// Update reverse index
		return s.addMappingToIndex(tx, userGUID, IdentityMapping{Provider: provider, ExternalID: externalID})
	})
}

func (s *Store) ResolveMapping(provider, externalID string) (string, error) {
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

func (s *Store) DeleteIdentityMapping(provider, externalID string) error {
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

func (s *Store) GetMappingsForUser(userGUID string) ([]IdentityMapping, error) {
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

func (s *Store) addMappingToIndex(tx *bolt.Tx, userGUID string, m IdentityMapping) error {
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

func (s *Store) removeMappingFromIndex(tx *bolt.Tx, userGUID string, m IdentityMapping) error {
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

// ListAllMappings returns all identity mappings with their associated user GUIDs.
type IdentityMappingEntry struct {
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
	UserGUID   string `json:"user_guid"`
}

func (s *Store) ListAllMappings() ([]IdentityMappingEntry, error) {
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

func (s *Store) SetUserRoles(guid string, roles []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(roles)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUserRoles).Put([]byte(guid), data)
	})
}

func (s *Store) GetUserRoles(guid string) ([]string, error) {
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

func (s *Store) SetUserPermissions(guid string, perms []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(perms)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUserPermissions).Put([]byte(guid), data)
	})
}

func (s *Store) GetUserPermissions(guid string) ([]string, error) {
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

// --- Config (generic key-value in config bucket) ---

func (s *Store) SetConfigValue(key string, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Put([]byte(key), value)
	})
}

func (s *Store) GetConfigValue(key string) ([]byte, error) {
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

func (s *Store) DeleteConfigValue(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Delete([]byte(key))
	})
}

// --- Default Roles ---

func (s *Store) GetDefaultRoles() ([]string, error) {
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

func (s *Store) SetDefaultRoles(roles []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(roles)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketConfig).Put([]byte("default_roles"), data)
	})
}

// --- Role → Permissions Mapping ---

// GetRolePermissions returns the role→permissions mapping.
func (s *Store) GetRolePermissions() (map[string][]string, error) {
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
func (s *Store) SetRolePermissions(mapping map[string][]string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(mapping)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketConfig).Put([]byte("role_permissions"), data)
	})
}

// ResolvePermissions expands roles into permissions using the role→permissions mapping,
// then merges with direct permissions (deduplicated).
func (s *Store) ResolvePermissions(roles, directPerms []string) ([]string, error) {
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

func (s *Store) SaveRefreshToken(rt *RefreshToken) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(rt)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketRefreshTokens).Put([]byte(rt.TokenID), data)
	})
}

func (s *Store) GetRefreshToken(tokenID string) (*RefreshToken, error) {
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

func (s *Store) MarkRefreshTokenUsed(tokenID string) error {
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
func (s *Store) RevokeTokenFamily(familyID string) error {
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
func (s *Store) ListUserSessions(userGUID string) ([]*RefreshToken, error) {
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
func (s *Store) RevokeUserTokens(userGUID string) error {
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

func (s *Store) WriteAuditLog(entry *AuditEntry) error {
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

type AuditQuery struct {
	Event  string
	UserID string
	From   time.Time
	To     time.Time
	Limit  int
	Offset int
}

func (s *Store) QueryAuditLog(q AuditQuery) ([]*AuditEntry, error) {
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

func (s *Store) PruneAuditLog(retention time.Duration) error {
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

func (s *Store) MergeUsers(sourceGUIDs []string, displayName, email string) (*User, error) {
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

func (s *Store) UnmergeUser(guid string) error {
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

func (s *Store) Backup(path string) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return tx.CopyFile(path, 0600)
	})
}

func (s *Store) BackupWriter(w io.Writer) error {
	return s.db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(w)
		return err
	})
}

// Restore replaces the current database with data from an io.Reader.
// It closes the current DB, writes the new file, and reopens.
func (s *Store) Restore(r io.Reader) error {
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

func (s *Store) reopen(dbPath string) error {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return fmt.Errorf("reopen db: %w", err)
	}
	s.db = db
	return nil
}

// --- One-Time Tokens ---

type OneTimeToken struct {
	Token     string    `json:"token"`
	Scope     string    `json:"scope"`
	Label     string    `json:"label"`
	Used      bool      `json:"used"`
	UsedBy    string    `json:"used_by,omitempty"`
	UsedAt    time.Time `json:"used_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// generateToken creates a token in XXX-XXXX format (all caps letters + digits).
func generateToken() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 7)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b[:3]) + "-" + string(b[3:])
}

func (s *Store) CreateOneTimeToken(scope, label string, ttl time.Duration) (*OneTimeToken, error) {
	tok := &OneTimeToken{
		Token:     generateToken(),
		Scope:     scope,
		Label:     label,
		ExpiresAt: time.Now().UTC().Add(ttl),
		CreatedAt: time.Now().UTC(),
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(tok)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketRegTokens).Put([]byte(tok.Token), data)
	})
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func (s *Store) GetOneTimeToken(token string) (*OneTimeToken, error) {
	var ot OneTimeToken
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketRegTokens).Get([]byte(token))
		if data == nil {
			return fmt.Errorf("token not found")
		}
		return json.Unmarshal(data, &ot)
	})
	if err != nil {
		return nil, err
	}
	return &ot, nil
}

// UseOneTimeToken validates scope, marks used, returns error if invalid/used/expired.
func (s *Store) UseOneTimeToken(token, scope, usedBy string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketRegTokens).Get([]byte(token))
		if data == nil {
			return fmt.Errorf("token not found")
		}
		var ot OneTimeToken
		if err := json.Unmarshal(data, &ot); err != nil {
			return err
		}
		if ot.Used {
			return fmt.Errorf("token already used")
		}
		if time.Now().After(ot.ExpiresAt) {
			return fmt.Errorf("token expired")
		}
		if ot.Scope != scope {
			return fmt.Errorf("token scope mismatch")
		}
		ot.Used = true
		ot.UsedBy = usedBy
		ot.UsedAt = time.Now().UTC()
		newData, err := json.Marshal(&ot)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketRegTokens).Put([]byte(token), newData)
	})
}

func (s *Store) ListOneTimeTokens(scope string) ([]*OneTimeToken, error) {
	var tokens []*OneTimeToken
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRegTokens).ForEach(func(k, v []byte) error {
			var ot OneTimeToken
			if err := json.Unmarshal(v, &ot); err != nil {
				return nil
			}
			if scope == "" || ot.Scope == scope {
				tokens = append(tokens, &ot)
			}
			return nil
		})
	})
	return tokens, err
}

func (s *Store) DeleteOneTimeToken(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRegTokens).Delete([]byte(token))
	})
}

// --- OIDC Authorization Codes ---

type OIDCAuthCode struct {
	Code        string    `json:"code"`
	UserGUID    string    `json:"user_guid"`
	RedirectURI string    `json:"redirect_uri"`
	Scope       string    `json:"scope"`
	Nonce       string    `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Store) SaveOIDCAuthCode(code *OIDCAuthCode) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(code)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketOIDCAuthCodes).Put([]byte(code.Code), data)
	})
}

// ConsumeOIDCAuthCode retrieves and deletes an auth code atomically.
func (s *Store) ConsumeOIDCAuthCode(code string) (*OIDCAuthCode, error) {
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
