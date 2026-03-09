package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Hostname        string        `yaml:"hostname"`
	Port            string        `yaml:"port"`
	DataDir         string        `yaml:"data_dir"`
	AdminKey        string        `yaml:"admin_key"`
	JWTIssuer       string        `yaml:"jwt_issuer"`
	AccessTTL       time.Duration `yaml:"access_ttl"`
	RefreshTTL      time.Duration `yaml:"refresh_ttl"`
	ImpersonateTTL  time.Duration `yaml:"impersonate_ttl"`
	KRB5Keytab      string        `yaml:"krb5_keytab"`
	KRB5Realm       string        `yaml:"krb5_realm"`
	TLSCert         string        `yaml:"tls_cert"`
	TLSKey          string        `yaml:"tls_key"`
	AuditRetention  time.Duration `yaml:"audit_retention"`
	RateLimitMax    int           `yaml:"rate_limit_max"`
	RateLimitWindow time.Duration `yaml:"rate_limit_window"`
	CORSOrigins     string        `yaml:"cors_origins"`
	HTTPPort        string        `yaml:"http_port"`
}

// configFile is an intermediate struct for YAML parsing with string durations.
type configFile struct {
	Hostname        string `yaml:"hostname"`
	Port            string `yaml:"port"`
	DataDir         string `yaml:"data_dir"`
	AdminKey        string `yaml:"admin_key"`
	JWTIssuer       string `yaml:"jwt_issuer"`
	AccessTTL       string `yaml:"access_ttl"`
	RefreshTTL      string `yaml:"refresh_ttl"`
	ImpersonateTTL  string `yaml:"impersonate_ttl"`
	KRB5Keytab      string `yaml:"krb5_keytab"`
	KRB5Realm       string `yaml:"krb5_realm"`
	TLSCert         string `yaml:"tls_cert"`
	TLSKey          string `yaml:"tls_key"`
	AuditRetention  string `yaml:"audit_retention"`
	RateLimitMax    int    `yaml:"rate_limit_max"`
	RateLimitWindow string `yaml:"rate_limit_window"`
	CORSOrigins     string `yaml:"cors_origins"`
	HTTPPort        string `yaml:"http_port"`
}

// Load reads config with priority: config file > env vars > defaults.
// Config file is looked up at: ./simpleauth.yaml, /etc/simpleauth/config.yaml,
// or the path specified by AUTH_CONFIG_FILE env var.
func Load() *Config {
	cfg := &Config{
		Port:            "9090",
		DataDir:         "./data",
		JWTIssuer:       "simpleauth",
		AccessTTL:       8 * time.Hour,
		RefreshTTL:      720 * time.Hour,
		ImpersonateTTL:  1 * time.Hour,
		AuditRetention:  90 * 24 * time.Hour,
		RateLimitMax:    10,
		RateLimitWindow: 1 * time.Minute,
		HTTPPort:        "80",
	}

	// Try to load config file
	loadConfigFile(cfg)

	// Env vars override config file values
	applyEnvOverrides(cfg)

	// Ensure data directory exists
	os.MkdirAll(cfg.DataDir, 0700)

	// Default hostname to OS hostname if not set
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}

	// Auto-generate TLS cert if not configured (self-signed in data dir)
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		certPath := filepath.Join(cfg.DataDir, "tls.crt")
		keyPath := filepath.Join(cfg.DataDir, "tls.key")

		needRegen := false
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			needRegen = true
		} else if !certMatchesHostname(certPath, cfg.Hostname) {
			log.Printf("Hostname changed — regenerating self-signed certificate for %s", cfg.Hostname)
			needRegen = true
		}

		if needRegen {
			log.Printf("Generating self-signed certificate for %s...", cfg.Hostname)
			if err := generateSelfSignedCert(certPath, keyPath, cfg.Hostname); err != nil {
				log.Fatalf("Failed to generate self-signed certificate: %v", err)
			}
			log.Printf("Self-signed certificate saved to %s", certPath)
		}

		cfg.TLSCert = certPath
		cfg.TLSKey = keyPath
	}

	return cfg
}

// WriteDefaultConfig writes a default config file to the given path.
func WriteDefaultConfig(path string) error {
	defaultYAML := `# SimpleAuth Configuration
# Priority: this file < environment variables (env vars override file values)

# The FQDN clients use to access SimpleAuth (used for TLS certificate SANs)
# This should match the Kerberos SPN hostname if using SPNEGO
hostname: ""

# Server port (HTTPS)
port: "9090"

# HTTP port for redirect to HTTPS (set to "" to disable HTTP redirect)
http_port: "80"

# Data directory for database, keytabs, and certificates
data_dir: "./data"

# Master admin API key (required)
admin_key: ""

# JWT settings
jwt_issuer: "simpleauth"
access_ttl: "8h"
refresh_ttl: "720h"
impersonate_ttl: "1h"

# TLS certificate and key paths (auto-generated if empty)
# tls_cert: "/path/to/cert.pem"
# tls_key: "/path/to/key.pem"

# Kerberos settings (usually auto-configured via admin UI)
# krb5_keytab: "/path/to/krb5.keytab"
# krb5_realm: "CORP.LOCAL"

# Audit log retention
audit_retention: "2160h"  # 90 days

# Rate limiting
rate_limit_max: 10
rate_limit_window: "1m"

# CORS origins (comma-separated, or "*" for all)
# cors_origins: "https://app.example.com"
`
	return os.WriteFile(path, []byte(defaultYAML), 0600)
}

func loadConfigFile(cfg *Config) {
	// Determine config file path
	configPath := os.Getenv("AUTH_CONFIG_FILE")
	if configPath == "" {
		candidates := []string{
			"simpleauth.yaml",
			"simpleauth.yml",
			"/etc/simpleauth/config.yaml",
			"/etc/simpleauth/config.yml",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				configPath = c
				break
			}
		}
	}

	if configPath == "" {
		return
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Warning: could not read config file %s: %v", configPath, err)
		return
	}

	var fc configFile
	if err := yaml.Unmarshal(data, &fc); err != nil {
		log.Printf("Warning: could not parse config file %s: %v", configPath, err)
		return
	}

	log.Printf("Loaded config from %s", configPath)

	if fc.Hostname != "" {
		cfg.Hostname = fc.Hostname
	}
	if fc.Port != "" {
		cfg.Port = fc.Port
	}
	if fc.DataDir != "" {
		cfg.DataDir = fc.DataDir
	}
	if fc.AdminKey != "" {
		cfg.AdminKey = fc.AdminKey
	}
	if fc.JWTIssuer != "" {
		cfg.JWTIssuer = fc.JWTIssuer
	}
	if fc.AccessTTL != "" {
		if d, err := time.ParseDuration(fc.AccessTTL); err == nil {
			cfg.AccessTTL = d
		}
	}
	if fc.RefreshTTL != "" {
		if d, err := time.ParseDuration(fc.RefreshTTL); err == nil {
			cfg.RefreshTTL = d
		}
	}
	if fc.ImpersonateTTL != "" {
		if d, err := time.ParseDuration(fc.ImpersonateTTL); err == nil {
			cfg.ImpersonateTTL = d
		}
	}
	if fc.KRB5Keytab != "" {
		cfg.KRB5Keytab = fc.KRB5Keytab
	}
	if fc.KRB5Realm != "" {
		cfg.KRB5Realm = fc.KRB5Realm
	}
	if fc.TLSCert != "" {
		cfg.TLSCert = fc.TLSCert
	}
	if fc.TLSKey != "" {
		cfg.TLSKey = fc.TLSKey
	}
	if fc.AuditRetention != "" {
		if d, err := time.ParseDuration(fc.AuditRetention); err == nil {
			cfg.AuditRetention = d
		}
	}
	if fc.RateLimitMax > 0 {
		cfg.RateLimitMax = fc.RateLimitMax
	}
	if fc.RateLimitWindow != "" {
		if d, err := time.ParseDuration(fc.RateLimitWindow); err == nil {
			cfg.RateLimitWindow = d
		}
	}
	if fc.CORSOrigins != "" {
		cfg.CORSOrigins = fc.CORSOrigins
	}
	if fc.HTTPPort != "" {
		cfg.HTTPPort = fc.HTTPPort
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("AUTH_HOSTNAME"); v != "" {
		cfg.Hostname = v
	}
	if v := os.Getenv("AUTH_PORT"); v != "" {
		cfg.Port = v
	}
	if v := os.Getenv("AUTH_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("AUTH_ADMIN_KEY"); v != "" {
		cfg.AdminKey = v
	}
	if v := os.Getenv("AUTH_JWT_ISSUER"); v != "" {
		cfg.JWTIssuer = v
	}
	if v := os.Getenv("AUTH_JWT_ACCESS_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.AccessTTL = d
		}
	}
	if v := os.Getenv("AUTH_JWT_REFRESH_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.RefreshTTL = d
		}
	}
	if v := os.Getenv("AUTH_IMPERSONATE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ImpersonateTTL = d
		}
	}
	if v := os.Getenv("AUTH_KRB5_KEYTAB"); v != "" {
		cfg.KRB5Keytab = v
	}
	if v := os.Getenv("AUTH_KRB5_REALM"); v != "" {
		cfg.KRB5Realm = v
	}
	if v := os.Getenv("AUTH_TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv("AUTH_TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv("AUTH_AUDIT_RETENTION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.AuditRetention = d
		}
	}
	if v := os.Getenv("AUTH_RATE_LIMIT_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimitMax = n
		}
	}
	if v := os.Getenv("AUTH_RATE_LIMIT_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.RateLimitWindow = d
		}
	}
	if v := os.Getenv("AUTH_CORS_ORIGINS"); v != "" {
		cfg.CORSOrigins = v
	}
	if v := os.Getenv("AUTH_HTTP_PORT"); v != "" {
		cfg.HTTPPort = v
	}
}

// certMatchesHostname checks if an existing certificate includes the given hostname in its SANs.
func certMatchesHostname(certPath, hostname string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	for _, name := range cert.DNSNames {
		if name == hostname {
			return true
		}
	}
	return false
}

// generateSelfSignedCert creates a self-signed TLS certificate.
func generateSelfSignedCert(certPath, keyPath, hostname string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Collect SANs: configured hostname + OS hostname + all non-loopback IPs
	osHostname, _ := os.Hostname()
	dnsNames := []string{"localhost"}
	if hostname != "" {
		dnsNames = append(dnsNames, hostname)
	}
	if osHostname != "" && osHostname != hostname {
		dnsNames = append(dnsNames, osHostname)
	}
	var ipAddrs []net.IP
	ipAddrs = append(ipAddrs, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				ipAddrs = append(ipAddrs, ipnet.IP)
			}
		}
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"SimpleAuth"}, CommonName: hostname},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return nil
}
