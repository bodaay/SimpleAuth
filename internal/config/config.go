package config

import (
	"os"
	"strconv"
)

// Config holds bootstrap configuration from environment variables.
// Runtime config (LDAP, local users) is stored in the data directory.
type Config struct {
	Port      int
	DataDir   string
	AdminKey  string
	JWTIssuer string
}

func Load() *Config {
	return &Config{
		Port:      getEnvInt("AUTH_PORT", 9090),
		DataDir:   getEnv("AUTH_DATA_DIR", "./data"),
		AdminKey:  getEnv("AUTH_ADMIN_KEY", ""),
		JWTIssuer: getEnv("AUTH_JWT_ISSUER", "auth-server"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
