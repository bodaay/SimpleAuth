package store

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
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

	// Check db.json first (UI-managed)
	dbCfg, _ := LoadDBConfig(dataDir)
	if dbCfg != nil && dbCfg.Backend == "postgres" && dbCfg.PostgresURL != "" {
		pgURL := dbCfg.PostgresURL
		// Retry Postgres connection with backoff (handles Docker startup ordering)
		var s *PostgresStore
		var err error
		for attempt := 1; attempt <= 5; attempt++ {
			s, err = OpenPostgres(pgURL)
			if err == nil {
				break
			}
			if attempt < 5 {
				log.Printf("[store] Postgres not ready (attempt %d/5): %v — retrying in %ds...", attempt, err, attempt*2)
				time.Sleep(time.Duration(attempt*2) * time.Second)
			}
		}
		if err != nil {
			// db.json explicitly says Postgres — don't silently fall back to stale BoltDB
			return nil, fmt.Errorf("postgres configured in db.json but connection failed after 5 attempts: %w", err)
		}
		log.Printf("[store] Using PostgreSQL backend")
		return s, nil
	}

	// Check env/config postgres URL (backward compat)
	if envPostgresURL != "" {
		var s *PostgresStore
		var err error
		for attempt := 1; attempt <= 5; attempt++ {
			s, err = OpenPostgres(envPostgresURL)
			if err == nil {
				break
			}
			if attempt < 5 {
				log.Printf("[store] Postgres not ready (attempt %d/5): %v — retrying in %ds...", attempt, err, attempt*2)
				time.Sleep(time.Duration(attempt*2) * time.Second)
			}
		}
		if err != nil {
			log.Printf("[store] WARNING: Postgres failed after retries (%v) — falling back to BoltDB", err)
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
