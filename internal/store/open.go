package store

// Open creates a store using the default backend (BoltDB).
// For PostgreSQL, use OpenPostgres() instead.
func Open(dataDir string) (Store, error) {
	return OpenBolt(dataDir)
}

// OpenWithConfig opens the appropriate store backend based on config.
// If postgresURL is non-empty, it connects to PostgreSQL.
// Otherwise, it falls back to BoltDB in the given data directory.
func OpenWithConfig(dataDir, postgresURL string) (Store, error) {
	if postgresURL != "" {
		return OpenPostgres(postgresURL)
	}
	return OpenBolt(dataDir)
}
