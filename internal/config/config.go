package config

import (
	"os"
	"time"
)

type Config struct {
	Port            string
	DataDir         string
	AdminKey        string
	JWTIssuer       string
	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	ImpersonateTTL  time.Duration
	KRB5Keytab      string
	KRB5Realm       string
	TLSCert         string
	TLSKey          string
	AuditRetention  time.Duration
}

func Load() *Config {
	return &Config{
		Port:            envOr("AUTH_PORT", "9090"),
		DataDir:         envOr("AUTH_DATA_DIR", "./data"),
		AdminKey:        os.Getenv("AUTH_ADMIN_KEY"),
		JWTIssuer:       envOr("AUTH_JWT_ISSUER", "simpleauth"),
		AccessTTL:       parseDuration("AUTH_JWT_ACCESS_TTL", 8*time.Hour),
		RefreshTTL:      parseDuration("AUTH_JWT_REFRESH_TTL", 720*time.Hour),
		ImpersonateTTL:  parseDuration("AUTH_IMPERSONATE_TTL", 1*time.Hour),
		KRB5Keytab:      os.Getenv("AUTH_KRB5_KEYTAB"),
		KRB5Realm:       os.Getenv("AUTH_KRB5_REALM"),
		TLSCert:         os.Getenv("AUTH_TLS_CERT"),
		TLSKey:          os.Getenv("AUTH_TLS_KEY"),
		AuditRetention:  parseDuration("AUTH_AUDIT_RETENTION", 90*24*time.Hour),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
