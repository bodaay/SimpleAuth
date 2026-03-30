package handler

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// initEncryptionKey loads or generates the data encryption key.
// Stored in data_dir/encrypt.key — independent of admin key so
// changing admin key doesn't break encrypted secrets.
func (h *Handler) initEncryptionKey() {
	keyPath := filepath.Join(h.cfg.DataDir, "encrypt.key")
	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == 64 { // 32 bytes hex-encoded
		key, err := hex.DecodeString(string(data))
		if err == nil && len(key) == 32 {
			h.encKey = key
			return
		}
	}
	// Generate new key
	h.encKey = make([]byte, 32)
	rand.Read(h.encKey)
	os.WriteFile(keyPath, []byte(hex.EncodeToString(h.encKey)), 0600)
	log.Printf("[secrets] Generated data encryption key")
}

// getLDAPConfigDecrypted reads LDAP config and decrypts the bind password.
func (h *Handler) getLDAPConfigDecrypted() (*store.LDAPConfig, error) {
	cfg, err := h.store.GetLDAPConfig()
	if err != nil {
		return nil, err
	}
	if auth.IsEncrypted(cfg.BindPassword) {
		plaintext, err := auth.DecryptSecret(cfg.BindPassword, h.encKey)
		if err != nil {
			log.Printf("[secrets] Failed to decrypt LDAP bind password: %v", err)
			return cfg, nil
		}
		cfg.BindPassword = plaintext
	}
	return cfg, nil
}

// saveLDAPConfigEncrypted encrypts the bind password and saves.
func (h *Handler) saveLDAPConfigEncrypted(cfg *store.LDAPConfig) error {
	if cfg.BindPassword != "" && !auth.IsEncrypted(cfg.BindPassword) {
		encrypted, err := auth.EncryptSecret(cfg.BindPassword, h.encKey)
		if err != nil {
			return err
		}
		cfg.BindPassword = encrypted
	}
	return h.store.SaveLDAPConfig(cfg)
}

// encryptDBConfig encrypts the Postgres URL in db.json.
func encryptDBConfigSecret(dataDir string, encKey []byte, cfg *store.DBConfig) error {
	if cfg.PostgresURL != "" && !auth.IsEncrypted(cfg.PostgresURL) {
		encrypted, err := auth.EncryptSecret(cfg.PostgresURL, encKey)
		if err != nil {
			return err
		}
		cfg.PostgresURL = encrypted
	}
	return store.SaveDBConfig(dataDir, cfg)
}

// decryptDBConfigSecret decrypts the Postgres URL from db.json.
func decryptDBConfigSecret(encKey []byte, cfg *store.DBConfig) {
	if auth.IsEncrypted(cfg.PostgresURL) {
		if plaintext, err := auth.DecryptSecret(cfg.PostgresURL, encKey); err == nil {
			cfg.PostgresURL = plaintext
		}
	}
}
