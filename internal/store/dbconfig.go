package store

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// DBConfig persists the active backend choice in a local JSON file.
// This lives outside the DB so it can be read before opening any store.
type DBConfig struct {
	Backend     string `json:"backend"`      // "boltdb" or "postgres"
	PostgresURL string `json:"postgres_url"`  // connection string (only when backend=postgres)
}

// DBConfigPath returns the path to db.json in the data directory.
func DBConfigPath(dataDir string) string {
	return filepath.Join(dataDir, "db.json")
}

// LoadDBConfig reads the backend config from db.json.
// Returns nil if the file doesn't exist (first run).
func LoadDBConfig(dataDir string) (*DBConfig, error) {
	path := DBConfigPath(dataDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read db config: %w", err)
	}
	var cfg DBConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse db config: %w", err)
	}
	return &cfg, nil
}

// SaveDBConfig writes the backend config to db.json.
func SaveDBConfig(dataDir string, cfg *DBConfig) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(DBConfigPath(dataDir), data, 0600)
}

// readEncryptionKey reads the encryption key from data_dir/encrypt.key if it exists.
func readEncryptionKey(dataDir string) []byte {
	data, err := os.ReadFile(filepath.Join(dataDir, "encrypt.key"))
	if err != nil || len(data) != 64 {
		return nil
	}
	key, err := hex.DecodeString(string(data))
	if err != nil || len(key) != 32 {
		return nil
	}
	return key
}

// decryptIfNeeded decrypts a string if it starts with "enc::".
func decryptIfNeeded(s string, key []byte) string {
	if key == nil || !strings.HasPrefix(s, "enc::") {
		return s
	}
	b64 := s[5:]
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return s
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return s
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return s
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return s
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return s
	}
	return string(plaintext)
}

// OpenSmart opens the appropriate store based on:
// 1. db.json in dataDir (if exists — UI-managed backend choice)
// 2. postgresURL from env/config (backward compat)
// 3. Falls back to BoltDB
//
// If Postgres is configured but fails, it falls back to BoltDB with a warning.
func OpenSmart(dataDir, envPostgresURL string) (Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	encKey := readEncryptionKey(dataDir)

	// Check db.json first (UI-managed)
	dbCfg, _ := LoadDBConfig(dataDir)
	if dbCfg != nil && dbCfg.Backend == "postgres" && dbCfg.PostgresURL != "" {
		pgURL := decryptIfNeeded(dbCfg.PostgresURL, encKey)
		s, err := OpenPostgres(pgURL)
		if err != nil {
			log.Printf("[store] WARNING: Postgres failed (%v) — falling back to BoltDB", err)
			return OpenBolt(dataDir)
		}
		log.Printf("[store] Using PostgreSQL backend")
		return s, nil
	}

	// Check env/config postgres URL (backward compat)
	if envPostgresURL != "" {
		s, err := OpenPostgres(envPostgresURL)
		if err != nil {
			log.Printf("[store] WARNING: Postgres failed (%v) — falling back to BoltDB", err)
			return OpenBolt(dataDir)
		}
		// Save to db.json so UI knows the backend
		SaveDBConfig(dataDir, &DBConfig{Backend: "postgres", PostgresURL: envPostgresURL})
		log.Printf("[store] Using PostgreSQL backend (from env)")
		return s, nil
	}

	// Default: BoltDB
	log.Printf("[store] Using BoltDB backend")
	return OpenBolt(dataDir)
}
