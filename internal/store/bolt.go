package store

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketConfig            = []byte("config")
	bucketUsers             = []byte("users")
	bucketIdentityMappings  = []byte("identity_mappings")
	bucketUserRoles         = []byte("user_roles")
	bucketUserPermissions   = []byte("user_permissions")
	bucketRefreshTokens     = []byte("refresh_tokens")
	bucketAuditLog          = []byte("audit_log")
	bucketIdxMappingsByGUID = []byte("idx_mappings_by_guid")
	bucketRegTokens         = []byte("reg_tokens")
	bucketOIDCAuthCodes     = []byte("oidc_auth_codes")
	bucketRevokedTokens     = []byte("revoked_tokens")
	bucketRevokedUsers      = []byte("revoked_users")
	bucketSessions          = []byte("sessions")
	bucketApps              = []byte("apps")
	bucketAppAuthz          = []byte("app_authz")
	bucketAppAdmins         = []byte("app_admins")
)

// BoltStore implements the Store interface using BoltDB (bbolt).
type BoltStore struct {
	mu sync.RWMutex // guards db against the close/reopen swap performed by Restore
	db *bolt.DB
}

// view/update run a bbolt transaction against the current handle, reading the
// pointer under the read lock so a concurrent Restore (which swaps the handle
// under the write lock for its whole close→replace→reopen sequence) can never
// race the field access. Previously Restore reassigned s.db with no
// synchronization while other goroutines read it — a data race that could panic
// or brick the store.
func (s *BoltStore) view(fn func(*bolt.Tx) error) error {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	return db.View(fn)
}

func (s *BoltStore) update(fn func(*bolt.Tx) error) error {
	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	return db.Update(fn)
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
	// Prune reverse-index entries a pre-H14 SetIdentityMapping left stranded on a
	// previous owner. Cheap (one pass over the index) and idempotent.
	s.repairMappingIndex()
	return s, nil
}

func (s *BoltStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// --- Apps (v2) ---

func (s *BoltStore) CreateApp(a *App) error {
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketApps)
		if b.Get([]byte(a.AppID)) != nil {
			return ErrAppExists
		}
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		return b.Put([]byte(a.AppID), data)
	})
}

func (s *BoltStore) GetApp(appID string) (*App, error) {
	var a App
	err := s.view(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketApps).Get([]byte(appID))
		if data == nil {
			return ErrAppNotFound
		}
		return json.Unmarshal(data, &a)
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *BoltStore) ListApps() ([]*App, error) {
	var apps []*App
	err := s.view(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketApps).ForEach(func(k, v []byte) error {
			var a App
			if err := json.Unmarshal(v, &a); err != nil {
				return err
			}
			apps = append(apps, &a)
			return nil
		})
	})
	return apps, err
}

func (s *BoltStore) UpdateApp(a *App) error {
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketApps)
		if b.Get([]byte(a.AppID)) == nil {
			return fmt.Errorf("app not found")
		}
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		return b.Put([]byte(a.AppID), data)
	})
}

func (s *BoltStore) DeleteApp(appID string) error {
	return s.update(func(tx *bolt.Tx) error {
		// Cascade: delete the app's app-local users and every identity mapping they
		// own, so re-registering the same app_id cannot resurrect ghost accounts
		// (and their password hashes) under a new owner (H8). Collect first —
		// BoltDB forbids mutating a bucket mid-ForEach.
		var localGUIDs []string
		if err := tx.Bucket(bucketUsers).ForEach(func(k, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				return nil
			}
			if u.OwnerAppID == appID {
				localGUIDs = append(localGUIDs, u.GUID)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, guid := range localGUIDs {
			if err := tx.Bucket(bucketUsers).Delete([]byte(guid)); err != nil {
				return err
			}
			if data := tx.Bucket(bucketIdxMappingsByGUID).Get([]byte(guid)); data != nil {
				var mappings []IdentityMapping
				if json.Unmarshal(data, &mappings) == nil {
					for _, m := range mappings {
						mk := mappingKey(m.Provider, m.ExternalID)
						// Only delete a forward entry this user still actually owns.
						// The reverse index is derived state; if it ever drifts again,
						// the H8 cascade must not delete a live mapping belonging to
						// somebody else (H14). Postgres cascades by
						// `WHERE user_guid IN (...)`, which is inherently owner-scoped —
						// this makes Bolt identical.
						if owner := tx.Bucket(bucketIdentityMappings).Get(mk); owner == nil || string(owner) != guid {
							continue
						}
						if err := tx.Bucket(bucketIdentityMappings).Delete(mk); err != nil {
							return err
						}
					}
				}
				if err := tx.Bucket(bucketIdxMappingsByGUID).Delete([]byte(guid)); err != nil {
					return err
				}
			}
		}
		if err := tx.Bucket(bucketApps).Delete([]byte(appID)); err != nil {
			return err
		}
		// Cascade: drop the app's authorization data.
		if err := tx.Bucket(bucketAppAuthz).Delete([]byte(appID)); err != nil {
			return err
		}
		// Cascade: drop the app's admins so a reused app_id cannot resurrect them.
		admins := tx.Bucket(bucketAppAdmins)
		prefix := appID + "\x00"
		var adminKeys [][]byte
		c := admins.Cursor()
		for k, _ := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix); k, _ = c.Next() {
			adminKeys = append(adminKeys, append([]byte(nil), k...))
		}
		for _, k := range adminKeys {
			if err := admins.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *BoltStore) GetAppAuthz(appID string) (*AppAuthz, error) {
	authz := &AppAuthz{AppID: appID}
	err := s.view(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketAppAuthz).Get([]byte(appID))
		if data == nil {
			return nil // none stored — return zero-value
		}
		return json.Unmarshal(data, authz)
	})
	if err != nil {
		return nil, err
	}
	return authz, nil
}

func (s *BoltStore) SaveAppAuthz(authz *AppAuthz) error {
	return s.update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(authz)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketAppAuthz).Put([]byte(authz.AppID), data)
	})
}

// appAdminKey is the (app_id, user_guid) membership key. The NUL separator can't
// appear in an app_id or a UUID, so prefix scans by "app_id\x00" are unambiguous.
func appAdminKey(appID, userGUID string) []byte {
	return []byte(appID + "\x00" + userGUID)
}

func (s *BoltStore) AddAppAdmin(appID, userGUID, addedBy string) error {
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAppAdmins)
		key := appAdminKey(appID, userGUID)
		if b.Get(key) != nil {
			return nil // already an admin — preserve the original AddedBy/AddedAt
		}
		data, err := json.Marshal(&AppAdmin{AppID: appID, UserGUID: userGUID, AddedBy: addedBy, AddedAt: time.Now().UTC()})
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

func (s *BoltStore) RemoveAppAdmin(appID, userGUID string) error {
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAppAdmins).Delete(appAdminKey(appID, userGUID))
	})
}

func (s *BoltStore) IsAppAdmin(appID, userGUID string) (bool, error) {
	var ok bool
	err := s.view(func(tx *bolt.Tx) error {
		ok = tx.Bucket(bucketAppAdmins).Get(appAdminKey(appID, userGUID)) != nil
		return nil
	})
	return ok, err
}

func (s *BoltStore) ListAppAdmins(appID string) ([]*AppAdmin, error) {
	var out []*AppAdmin
	prefix := appID + "\x00"
	err := s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAppAdmins).Cursor()
		for k, v := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix); k, v = c.Next() {
			a := &AppAdmin{}
			if json.Unmarshal(v, a) == nil {
				out = append(out, a)
			}
		}
		return nil
	})
	return out, err
}

func (s *BoltStore) init() error {
	return s.update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			bucketConfig, bucketUsers,
			bucketIdentityMappings, bucketUserRoles, bucketUserPermissions,
			bucketRefreshTokens, bucketAuditLog,
			bucketIdxMappingsByGUID,
			bucketRegTokens,
			bucketOIDCAuthCodes,
			bucketRevokedTokens,
			bucketRevokedUsers,
			bucketSessions,
			bucketApps,
			bucketAppAuthz,
			bucketAppAdmins,
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
	_ = s.view(func(tx *bolt.Tx) error {
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
	_ = s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(u)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUsers).Put([]byte(u.GUID), data)
	})
}

func (s *BoltStore) GetUser(guid string) (*User, error) {
	var u User
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketUsers).Delete([]byte(guid))
	})
}

func (s *BoltStore) ListUsers() ([]*User, error) {
	var users []*User
	err := s.view(func(tx *bolt.Tx) error {
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
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketConfig).Put([]byte("ldap:config"), data)
	})
}

func (s *BoltStore) DeleteLDAPConfig() error {
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Delete([]byte("ldap:config"))
	})
}

// --- Identity Mappings ---

func mappingKey(provider, externalID string) []byte {
	return []byte(provider + ":" + externalID)
}

// mappingSplits builds forwardKey -> {Provider, ExternalID} from the reverse
// index, which records both halves verbatim.
//
// The Bolt forward key is the composite "provider:externalID" and BOTH halves may
// contain ':' — app-local users are keyed under the provider "applocal:<appID>",
// and handleSetMapping accepts an arbitrary provider string — so splitting on the
// first ':' is guesswork. Postgres keeps the halves in separate columns and never
// has to guess; this is how Bolt matches it (M38).
func mappingSplits(tx *bolt.Tx) map[string]IdentityMapping {
	out := map[string]IdentityMapping{}
	idx := tx.Bucket(bucketIdxMappingsByGUID)
	if idx == nil {
		return out
	}
	_ = idx.ForEach(func(_, v []byte) error {
		var mappings []IdentityMapping
		if json.Unmarshal(v, &mappings) != nil {
			return nil
		}
		for _, m := range mappings {
			out[string(mappingKey(m.Provider, m.ExternalID))] = m
		}
		return nil
	})
	return out
}

// splitMappingKey decomposes a forward key, preferring the reverse index and
// falling back to the first ':' only for a key the index does not cover (which
// only happens in already-corrupt data — fall back rather than drop the row).
func splitMappingKey(key string, known map[string]IdentityMapping) (IdentityMapping, bool) {
	if m, ok := known[key]; ok {
		return m, true
	}
	i := strings.Index(key, ":")
	if i < 0 {
		return IdentityMapping{}, false
	}
	return IdentityMapping{Provider: key[:i], ExternalID: key[i+1:]}, true
}

// SetIdentityMapping points provider:externalID at userGUID, re-pointing the
// mapping if it currently resolves to somebody else.
//
// The forward bucket is authoritative and bucketIdxMappingsByGUID is only a
// derived reverse index, so a re-point MUST retract the entry from the previous
// owner in the SAME transaction. Previously only addMappingToIndex ran, so after
// an admin created a local account under a username an LDAP JIT user already
// owned, BOTH GUIDs claimed it. The loser kept a phantom {local,<name>} that
// resolvePreferredUsername stamped into every access and ID token as the standard
// `preferred_username` claim — handing an RP that authorizes on that claim the
// wrong user — and that the delete cascades (handleDeleteLocalUser, DeleteApp)
// followed to delete the REAL owner's live mapping (H14).
//
// Postgres has no reverse index — ON CONFLICT (provider, external_id) DO UPDATE
// already makes the single row the whole truth — so this restores backend parity.
func (s *BoltStore) SetIdentityMapping(provider, externalID, userGUID string) error {
	return s.update(func(tx *bolt.Tx) error {
		key := mappingKey(provider, externalID)
		m := IdentityMapping{Provider: provider, ExternalID: externalID}

		// Read the incumbent BEFORE the Put. bbolt hands back a slice into the
		// mmap'd page, which Put may invalidate, so copy it out with string().
		var prevOwner string
		if v := tx.Bucket(bucketIdentityMappings).Get(key); v != nil {
			prevOwner = string(v)
		}
		if err := tx.Bucket(bucketIdentityMappings).Put(key, []byte(userGUID)); err != nil {
			return err
		}
		// Retract from the loser first, then index the winner. The
		// prevOwner == userGUID case is skipped outright: a naive remove-then-add
		// on the same GUID would strip the entry addMappingToIndex just wrote, and
		// re-setting the same mapping must stay idempotent.
		if prevOwner != "" && prevOwner != userGUID {
			if err := s.removeMappingFromIndex(tx, prevOwner, m); err != nil {
				return err
			}
		}
		return s.addMappingToIndex(tx, userGUID, m)
	})
}

func (s *BoltStore) ResolveMapping(provider, externalID string) (string, error) {
	var guid string
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
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
	err := s.view(func(tx *bolt.Tx) error {
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

// repairMappingIndex prunes reverse-index entries the forward bucket no longer
// backs. Fixing the writer does not clean data a deployment already corrupted,
// and a single orphan entry is enough on its own to stamp another user's
// `preferred_username` into live tokens and to make the delete cascades destroy
// the real owner's mapping — so repair on open, alongside
// migrateRolesAndPermissions (H14).
//
// PRUNE ONLY, never rebuild. Reconstructing index entries from forward keys would
// have to re-split the ambiguous composite key and would corrupt the exactly
// recorded "applocal:<appID>" providers the index already holds correctly. Every
// writer adds forward + index in one transaction (SetIdentityMapping, MergeUsers)
// and every deleter removes both, so "index entry with no matching forward owner"
// is the only corruption this bug can produce.
//
// Each pruned claim is logged individually, not just counted: this deletes
// identity data at startup on data we have never seen, so the log must be
// sufficient to reconstruct by hand what was removed. Set
// SA_SKIP_MAPPING_REPAIR=1 to report without writing — an operator who sees an
// unexpected prune count can use it to inspect before committing.
func (s *BoltStore) repairMappingIndex() {
	type change struct {
		guid    string
		kept    []IdentityMapping
		dropped []IdentityMapping
	}
	var changes []change

	// Collect under a read tx; bbolt forbids mutating a bucket mid-ForEach.
	_ = s.view(func(tx *bolt.Tx) error {
		fwd := tx.Bucket(bucketIdentityMappings)
		return tx.Bucket(bucketIdxMappingsByGUID).ForEach(func(k, v []byte) error {
			var mappings []IdentityMapping
			if json.Unmarshal(v, &mappings) != nil {
				return nil
			}
			guid := string(k) // k is only valid inside the callback
			kept := make([]IdentityMapping, 0, len(mappings))
			var dropped []IdentityMapping
			for _, m := range mappings {
				if owner := fwd.Get(mappingKey(m.Provider, m.ExternalID)); owner != nil && string(owner) == guid {
					kept = append(kept, m)
				} else {
					dropped = append(dropped, m)
				}
			}
			if len(dropped) > 0 {
				changes = append(changes, change{guid: guid, kept: kept, dropped: dropped})
			}
			return nil
		})
	})
	if len(changes) == 0 {
		return
	}

	// Log the full plan BEFORE writing, so the record survives even if the write
	// fails or the result turns out to be wrong.
	for _, c := range changes {
		for _, m := range c.dropped {
			log.Printf("[store] mapping-index repair: user=%s no longer owns %s:%s — pruning stale claim (H14)",
				c.guid, m.Provider, m.ExternalID)
		}
	}
	if os.Getenv("SA_SKIP_MAPPING_REPAIR") == "1" {
		log.Printf("[store] mapping-index repair: SA_SKIP_MAPPING_REPAIR=1 — reported %d user(s), no changes written", len(changes))
		return
	}

	if err := s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketIdxMappingsByGUID)
		for _, c := range changes {
			if len(c.kept) == 0 {
				if err := b.Delete([]byte(c.guid)); err != nil {
					return err
				}
				continue
			}
			data, err := json.Marshal(c.kept)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(c.guid), data); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		log.Printf("[store] mapping-index repair FAILED: %v", err)
		return
	}
	log.Printf("[store] mapping-index repair: pruned stale claims for %d user(s) (H14)", len(changes))
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
	err := s.view(func(tx *bolt.Tx) error {
		// Decompose via the reverse index rather than guessing at the first ':',
		// so an "applocal:<appID>" provider round-trips intact and matches what
		// Postgres reports from its two columns (M38).
		known := mappingSplits(tx)
		return tx.Bucket(bucketIdentityMappings).ForEach(func(k, v []byte) error {
			m, ok := splitMappingKey(string(k), known)
			if !ok {
				return nil
			}
			result = append(result, IdentityMappingEntry{
				Provider:   m.Provider,
				ExternalID: m.ExternalID,
				UserGUID:   string(v),
			})
			return nil
		})
	})
	return result, err
}

// --- Roles & Permissions (no app scoping) ---

func (s *BoltStore) SetUserRoles(guid string, roles []string) error {
	return s.update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(roles)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUserRoles).Put([]byte(guid), data)
	})
}

func (s *BoltStore) GetUserRoles(guid string) ([]string, error) {
	var roles []string
	err := s.view(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketUserRoles).Get([]byte(guid))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &roles)
	})
	return roles, err
}

func (s *BoltStore) SetUserPermissions(guid string, perms []string) error {
	return s.update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(perms)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketUserPermissions).Put([]byte(guid), data)
	})
}

func (s *BoltStore) GetUserPermissions(guid string) ([]string, error) {
	var perms []string
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Put([]byte(key), value)
	})
}

func (s *BoltStore) GetConfigValue(key string) ([]byte, error) {
	var val []byte
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketConfig).Delete([]byte(key))
	})
}

// --- Default Roles ---

func (s *BoltStore) GetDefaultRoles() ([]string, error) {
	var roles []string
	err := s.view(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketConfig).Get([]byte("default_roles"))
		if data == nil {
			return nil
		}
		return json.Unmarshal(data, &roles)
	})
	return roles, err
}

func (s *BoltStore) SetDefaultRoles(roles []string) error {
	return s.update(func(tx *bolt.Tx) error {
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
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
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
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(rt)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketRefreshTokens).Put([]byte(rt.TokenID), data)
	})
}

func (s *BoltStore) GetRefreshToken(tokenID string) (*RefreshToken, error) {
	var rt RefreshToken
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
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

// ConsumeRefreshToken atomically checks-and-marks a refresh token as used within
// a single write transaction, closing the rotation TOCTOU window (H2). On reuse
// it returns the token (so the caller can revoke its family) with
// ErrRefreshTokenReused.
func (s *BoltStore) ConsumeRefreshToken(tokenID string) (*RefreshToken, error) {
	var rt RefreshToken
	err := s.update(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketRefreshTokens).Get([]byte(tokenID))
		if data == nil {
			return ErrRefreshTokenNotFound
		}
		if err := json.Unmarshal(data, &rt); err != nil {
			return err
		}
		if rt.Used {
			return ErrRefreshTokenReused
		}
		rt.Used = true
		newData, err := json.Marshal(&rt)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketRefreshTokens).Put([]byte(tokenID), newData)
	})
	if err != nil {
		return &rt, err
	}
	return &rt, nil
}

// RevokeTokenFamily deletes all refresh tokens belonging to a family.
func (s *BoltStore) RevokeTokenFamily(familyID string) error {
	return s.update(func(tx *bolt.Tx) error {
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
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
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
	err := s.view(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
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

	err := s.update(func(tx *bolt.Tx) error {
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
	return s.update(func(tx *bolt.Tx) error {
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
	return s.view(func(tx *bolt.Tx) error {
		return tx.CopyFile(path, 0600)
	})
}

func (s *BoltStore) BackupWriter(w io.Writer) error {
	return s.view(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(w)
		return err
	})
}

// Restore replaces the current database with data from an io.Reader.
// It closes the current DB, writes the new file, and reopens.
func (s *BoltStore) Restore(r io.Reader) error {
	// Hold the write lock for the entire close→replace→reopen sequence so no
	// view/update transaction can read the db handle mid-swap. view/update block
	// on the read lock until the restore completes.
	s.mu.Lock()
	defer s.mu.Unlock()

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

// reopen reassigns the db handle. It assumes the caller holds s.mu for writing
// (it is only ever called from Restore, which does).
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
	return s.update(func(tx *bolt.Tx) error {
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
	err := s.update(func(tx *bolt.Tx) error {
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

// --- Runtime Settings ---

func (s *BoltStore) GetRuntimeSettings() (*RuntimeSettings, error) {
	val, err := s.GetConfigValue("runtime_settings")
	if err != nil || val == nil {
		return nil, err
	}
	var rs RuntimeSettings
	return &rs, json.Unmarshal(val, &rs)
}

func (s *BoltStore) SaveRuntimeSettings(rs *RuntimeSettings) error {
	data, err := json.Marshal(rs)
	if err != nil {
		return err
	}
	return s.SetConfigValue("runtime_settings", data)
}

// --- Token Revocation ---

func (s *BoltStore) RevokeAccessToken(jti string, expiresAt time.Time) error {
	return s.update(func(tx *bolt.Tx) error {
		data, _ := json.Marshal(expiresAt)
		return tx.Bucket(bucketRevokedTokens).Put([]byte(jti), data)
	})
}

func (s *BoltStore) IsAccessTokenRevoked(jti string) (bool, error) {
	var revoked bool
	err := s.view(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketRevokedTokens).Get([]byte(jti))
		if data != nil {
			revoked = true
		}
		return nil
	})
	return revoked, err
}

func (s *BoltStore) CleanExpiredRevocations() error {
	now := time.Now()
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRevokedTokens)
		var toDelete [][]byte
		b.ForEach(func(k, v []byte) error {
			var expiresAt time.Time
			if json.Unmarshal(v, &expiresAt) == nil && expiresAt.Before(now) {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			b.Delete(k)
		}
		// Also clean expired user revocations
		ub := tx.Bucket(bucketRevokedUsers)
		toDelete = nil
		ub.ForEach(func(k, v []byte) error {
			var expiresAt time.Time
			if json.Unmarshal(v, &expiresAt) == nil && expiresAt.Before(now) {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			ub.Delete(k)
		}
		return nil
	})
}

func (s *BoltStore) RevokeAllUserAccessTokens(userGUID string, expiresAt time.Time) error {
	return s.update(func(tx *bolt.Tx) error {
		data, _ := json.Marshal(expiresAt)
		return tx.Bucket(bucketRevokedUsers).Put([]byte(userGUID), data)
	})
}

func (s *BoltStore) IsUserAccessRevoked(userGUID string) (bool, error) {
	var revoked bool
	err := s.view(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketRevokedUsers).Get([]byte(userGUID))
		if data != nil {
			var expiresAt time.Time
			if json.Unmarshal(data, &expiresAt) == nil && expiresAt.After(time.Now()) {
				revoked = true
			}
		}
		return nil
	})
	return revoked, err
}

// --- Database Info ---

func (s *BoltStore) DatabaseInfo() (*DatabaseInfo, error) {
	info := &DatabaseInfo{
		Backend: "boltdb",
		Health:  "healthy",
	}

	// Get file size
	s.mu.RLock()
	path := s.db.Path()
	s.mu.RUnlock()
	if fi, err := os.Stat(path); err == nil {
		info.SizeMB = float64(fi.Size()) / 1024 / 1024
	}

	// Count rows per bucket
	s.view(func(tx *bolt.Tx) error {
		for _, bname := range []string{
			"users", "identity_mappings", "user_roles", "user_permissions",
			"config", "refresh_tokens", "audit_log", "oidc_auth_codes",
			"revoked_tokens", "revoked_users",
		} {
			b := tx.Bucket([]byte(bname))
			if b == nil {
				continue
			}
			var count int64
			b.ForEach(func(k, v []byte) error {
				count++
				return nil
			})
			info.Tables++
			info.TotalRows += count
			info.TableDetails = append(info.TableDetails, TableInfo{
				Name: bname,
				Rows: count,
			})
		}
		return nil
	})

	return info, nil
}

// --- SSO Sessions ---

func (s *BoltStore) CreateSession(sess *Session) error {
	return s.update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(sess)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketSessions).Put([]byte(sess.ID), data)
	})
}

func (s *BoltStore) GetSession(id string) (*Session, error) {
	var sess Session
	err := s.view(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketSessions).Get([]byte(id))
		if data == nil {
			return fmt.Errorf("session not found")
		}
		return json.Unmarshal(data, &sess)
	})
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *BoltStore) TouchSession(id string, lastUsed time.Time) error {
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("session not found")
		}
		var sess Session
		if err := json.Unmarshal(data, &sess); err != nil {
			return err
		}
		sess.LastUsedAt = lastUsed
		updated, err := json.Marshal(&sess)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), updated)
	})
}

func (s *BoltStore) DeleteSession(id string) error {
	return s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSessions).Delete([]byte(id))
	})
}

func (s *BoltStore) DeleteUserSessions(userGUID string) error {
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		var toDelete [][]byte
		b.ForEach(func(k, v []byte) error {
			var sess Session
			if json.Unmarshal(v, &sess) == nil && sess.UserGUID == userGUID {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			b.Delete(k)
		}
		return nil
	})
}

func (s *BoltStore) CleanExpiredOIDCCodes() error {
	now := time.Now()
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketOIDCAuthCodes)
		if b == nil {
			return nil
		}
		var toDelete [][]byte
		b.ForEach(func(k, v []byte) error {
			var c OIDCAuthCode
			if json.Unmarshal(v, &c) == nil && c.ExpiresAt.Before(now) {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			b.Delete(k)
		}
		return nil
	})
}

func (s *BoltStore) CleanExpiredRefreshTokens() error {
	now := time.Now()
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRefreshTokens)
		if b == nil {
			return nil
		}
		var toDelete [][]byte
		b.ForEach(func(k, v []byte) error {
			var rt RefreshToken
			if json.Unmarshal(v, &rt) == nil && rt.ExpiresAt.Before(now) {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			b.Delete(k)
		}
		return nil
	})
}

func (s *BoltStore) CleanExpiredSessions() error {
	now := time.Now()
	return s.update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		var toDelete [][]byte
		b.ForEach(func(k, v []byte) error {
			var sess Session
			if json.Unmarshal(v, &sess) == nil && sess.ExpiresAt.Before(now) {
				toDelete = append(toDelete, k)
			}
			return nil
		})
		for _, k := range toDelete {
			b.Delete(k)
		}
		return nil
	})
}
