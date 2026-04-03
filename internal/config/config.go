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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

var deploymentNameRe = regexp.MustCompile(`^[a-zA-Z]{1,6}$`)

type Config struct {
	Hostname       string        `yaml:"hostname"`
	Port           string        `yaml:"port"`
	DataDir        string        `yaml:"data_dir"`
	AdminKey       string        `yaml:"admin_key"`
	DeploymentName string        `yaml:"deployment_name"`
	JWTIssuer       string        `yaml:"jwt_issuer"`
	AccessTTL       time.Duration `yaml:"access_ttl"`
	RefreshTTL      time.Duration `yaml:"refresh_ttl"`
	ImpersonateTTL  time.Duration `yaml:"impersonate_ttl"`
	KRB5Keytab      string        `yaml:"krb5_keytab"`
	KRB5Realm       string        `yaml:"krb5_realm"`
	TLSCert         string        `yaml:"tls_cert"`
	TLSKey          string        `yaml:"tls_key"`
	TLSDisabled     bool          `yaml:"tls_disabled"`
	TrustedProxies   []string      `yaml:"trusted_proxies"`
	TrustedProxyCIDRs []*net.IPNet `yaml:"-"`
	BasePath        string        `yaml:"base_path"`
	AuditRetention  time.Duration `yaml:"audit_retention"`
	RateLimitMax    int           `yaml:"rate_limit_max"`
	RateLimitWindow time.Duration `yaml:"rate_limit_window"`
	CORSOrigins     string        `yaml:"cors_origins"`
	HTTPPort        string        `yaml:"http_port"`
	ClientID        string        `yaml:"client_id"`
	ClientSecret    string        `yaml:"client_secret"`
	RedirectURI     string        `yaml:"redirect_uri"`
	RedirectURIs    []string      `yaml:"redirect_uris"`
	DefaultRoles    []string      `yaml:"default_roles"`

	// Password policy
	PasswordMinLength        int           `yaml:"password_min_length"`
	PasswordRequireUppercase bool          `yaml:"password_require_uppercase"`
	PasswordRequireLowercase bool          `yaml:"password_require_lowercase"`
	PasswordRequireDigit     bool          `yaml:"password_require_digit"`
	PasswordRequireSpecial   bool          `yaml:"password_require_special"`
	PasswordHistoryCount     int           `yaml:"password_history_count"`
	AccountLockoutThreshold  int           `yaml:"account_lockout_threshold"`
	AccountLockoutDuration   time.Duration `yaml:"account_lockout_duration"`

	// SSO
	AutoSSO      bool `yaml:"auto_sso"`
	AutoSSODelay int  `yaml:"auto_sso_delay"` // seconds, default 3

	// Database
	PostgresURL string `yaml:"postgres_url"`
}

// configFile is an intermediate struct for YAML parsing with string durations.
type configFile struct {
	Hostname        string `yaml:"hostname"`
	Port            string `yaml:"port"`
	DataDir         string `yaml:"data_dir"`
	AdminKey        string `yaml:"admin_key"`
	DeploymentName     string `yaml:"deployment_name"`
	JWTIssuer       string `yaml:"jwt_issuer"`
	AccessTTL       string `yaml:"access_ttl"`
	RefreshTTL      string `yaml:"refresh_ttl"`
	ImpersonateTTL  string `yaml:"impersonate_ttl"`
	KRB5Keytab      string `yaml:"krb5_keytab"`
	KRB5Realm       string `yaml:"krb5_realm"`
	TLSCert         string `yaml:"tls_cert"`
	TLSKey          string `yaml:"tls_key"`
	TLSDisabled     bool     `yaml:"tls_disabled"`
	TrustedProxies  []string `yaml:"trusted_proxies"`
	BasePath        string   `yaml:"base_path"`
	AuditRetention  string `yaml:"audit_retention"`
	RateLimitMax    int    `yaml:"rate_limit_max"`
	RateLimitWindow string `yaml:"rate_limit_window"`
	CORSOrigins     string   `yaml:"cors_origins"`
	HTTPPort        string   `yaml:"http_port"`
	ClientID        string   `yaml:"client_id"`
	ClientSecret    string   `yaml:"client_secret"`
	RedirectURI     string   `yaml:"redirect_uri"`
	RedirectURIs    []string `yaml:"redirect_uris"`
	DefaultRoles    []string `yaml:"default_roles"`

	PasswordMinLength        int    `yaml:"password_min_length"`
	PasswordRequireUppercase bool   `yaml:"password_require_uppercase"`
	PasswordRequireLowercase bool   `yaml:"password_require_lowercase"`
	PasswordRequireDigit     bool   `yaml:"password_require_digit"`
	PasswordRequireSpecial   bool   `yaml:"password_require_special"`
	PasswordHistoryCount     int    `yaml:"password_history_count"`
	AccountLockoutThreshold  int    `yaml:"account_lockout_threshold"`
	AccountLockoutDuration   string `yaml:"account_lockout_duration"`
}

// Load reads config with priority: env vars > config file > defaults.
// Config file is looked up at: ./simpleauth.yaml, /etc/simpleauth/config.yaml,
// or the path specified by AUTH_CONFIG_FILE env var.
//
// Load only populates the config struct — it does not validate or generate
// certificates. Call Validate() after applying any programmatic overrides.
func Load() *Config {
	cfg := &Config{
		Port:            "9090",
		DataDir:         "./data",
		BasePath:        "/sauth",
		DeploymentName:     "sauth",
		JWTIssuer:       "simpleauth",
		AccessTTL:       15 * time.Minute,
		RefreshTTL:      720 * time.Hour,
		ImpersonateTTL:  1 * time.Hour,
		AuditRetention:  90 * 24 * time.Hour,
		RateLimitMax:    10,
		RateLimitWindow: 1 * time.Minute,
		HTTPPort:        "80",
		AutoSSODelay:           3,
		PasswordMinLength:      8,
		AccountLockoutDuration: 30 * time.Minute,
	}

	// Try to load config file
	loadConfigFile(cfg)

	// Env vars override config file values
	applyEnvOverrides(cfg)

	return cfg
}

// Validate checks required fields, generates TLS certs if needed, parses
// trusted proxies, normalizes paths, and auto-generates OIDC credentials.
// Returns an error instead of calling log.Fatalf, so callers control their
// own process lifecycle.
func (cfg *Config) Validate() error {
	// Ensure data directory exists
	os.MkdirAll(cfg.DataDir, 0700)

	// Hostname is mandatory
	if cfg.Hostname == "" {
		return fmt.Errorf("hostname is required — set it in config file (hostname:) or AUTH_HOSTNAME env var")
	}

	// Validate deployment name: 1-6 letters only
	if !deploymentNameRe.MatchString(cfg.DeploymentName) {
		return fmt.Errorf("deployment_name must be 1-6 letters only (a-z/A-Z), got: %q", cfg.DeploymentName)
	}

	// Auto-generate TLS cert if not configured and TLS is not disabled
	if cfg.TLSDisabled {
		log.Printf("TLS disabled — serving plain HTTP (ensure a reverse proxy handles TLS)")
	} else if cfg.TLSCert == "" || cfg.TLSKey == "" {
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
				return fmt.Errorf("failed to generate self-signed certificate: %w", err)
			}
			log.Printf("Self-signed certificate saved to %s", certPath)
		}

		cfg.TLSCert = certPath
		cfg.TLSKey = keyPath
	}

	// Parse trusted proxy CIDRs
	if len(cfg.TrustedProxies) > 0 {
		for _, p := range cfg.TrustedProxies {
			p = strings.TrimSpace(p)
			if !strings.Contains(p, "/") {
				// Bare IP — make it a /32 or /128
				if strings.Contains(p, ":") {
					p += "/128"
				} else {
					p += "/32"
				}
			}
			_, cidr, err := net.ParseCIDR(p)
			if err != nil {
				log.Printf("Warning: invalid trusted proxy CIDR %q: %v", p, err)
				continue
			}
			cfg.TrustedProxyCIDRs = append(cfg.TrustedProxyCIDRs, cidr)
		}
		log.Printf("Trusted proxies: %v", cfg.TrustedProxies)
	}

	// Normalize base path: ensure leading /, strip trailing /
	if cfg.BasePath != "" {
		cfg.BasePath = "/" + strings.Trim(cfg.BasePath, "/")
		if cfg.BasePath == "/" {
			cfg.BasePath = ""
		}
		if cfg.BasePath != "" {
			log.Printf("Base path: %s", cfg.BasePath)
		}
	}

	// Merge redirect_uri into redirect_uris list (deduplicated)
	if cfg.RedirectURI != "" {
		found := false
		for _, u := range cfg.RedirectURIs {
			if u == cfg.RedirectURI {
				found = true
				break
			}
		}
		if !found {
			cfg.RedirectURIs = append([]string{cfg.RedirectURI}, cfg.RedirectURIs...)
		}
	}
	// Keep RedirectURI set to first entry for backward compat
	if cfg.RedirectURI == "" && len(cfg.RedirectURIs) > 0 {
		cfg.RedirectURI = cfg.RedirectURIs[0]
	}

	// Auto-generate OIDC client credentials if not configured
	if cfg.ClientID == "" {
		cfg.ClientID = "simpleauth"
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = uuid.New().String()
		log.Printf("No client_secret configured — generated: %s", cfg.ClientSecret)
	}

	return nil
}

// WriteDefaultConfig writes a default config file to the given path.
func WriteDefaultConfig(path string) error {
	defaultYAML := `# SimpleAuth Configuration
# Priority: env vars > this file > defaults (env vars always win)

# REQUIRED: The FQDN clients use to access SimpleAuth
# Used for TLS certificate SANs, Kerberos SPN, and AD setup scripts
hostname: ""

# Deployment name (1-6 letters only, used in AD service account: svc-sauth-{name})
# Default: "sauth" — change if running multiple instances against the same AD
deployment_name: "sauth"

# Server port (HTTPS)
port: "9090"

# HTTP port for redirect to HTTPS (set to "" to disable HTTP redirect)
http_port: "80"

# Data directory for database, keytabs, and certificates
data_dir: "./data"

# Master admin API key (auto-generated if empty)
admin_key: ""

# JWT settings
jwt_issuer: "simpleauth"
access_ttl: "15m"
refresh_ttl: "720h"
impersonate_ttl: "1h"

# TLS certificate and key paths (auto-generated if empty)
# tls_cert: "/path/to/cert.pem"
# tls_key: "/path/to/key.pem"

# Set to true to disable TLS (use when behind a reverse proxy like nginx)
# tls_disabled: false

# Trusted proxy IPs/CIDRs — X-Forwarded-For and X-Real-IP headers are only
# trusted when the request comes from these addresses. If empty, headers are
# trusted from any source (not recommended in production).
# trusted_proxies:
#   - "172.16.0.0/12"
#   - "10.0.0.0/8"
#   - "192.168.0.0/16"

# Base path prefix (default: "/sauth")
# SimpleAuth is accessible at https://hostname:port/sauth/
base_path: "/sauth"

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

# OIDC client credentials for this instance (single-app mode)
# client_id is auto-generated as "simpleauth" if empty
# client_secret is auto-generated (UUID) if empty
client_id: ""
client_secret: ""

# Redirect URI — where the app receives tokens after login
# redirect_uri: "https://app.example.com/callback"

# Default roles assigned to new users on first login (comma-separated in env var)
# default_roles:
#   - "user"

# Password policy
password_min_length: 8
# password_require_uppercase: false
# password_require_lowercase: false
# password_require_digit: false
# password_require_special: false

# Password history — prevent reusing the last N passwords (0 = disabled)
# password_history_count: 0

# Account lockout — lock account after N consecutive failed login attempts (0 = disabled)
# account_lockout_threshold: 0
# account_lockout_duration: "30m"
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
		log.Printf("No config file found — using defaults + env vars (run 'simpleauth init-config' to create one)")
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
	if fc.DeploymentName != "" {
		cfg.DeploymentName = fc.DeploymentName
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
	if fc.TLSDisabled {
		cfg.TLSDisabled = true
	}
	if len(fc.TrustedProxies) > 0 {
		cfg.TrustedProxies = fc.TrustedProxies
	}
	if fc.BasePath != "" {
		cfg.BasePath = fc.BasePath
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
	if fc.ClientID != "" {
		cfg.ClientID = fc.ClientID
	}
	if fc.ClientSecret != "" {
		cfg.ClientSecret = fc.ClientSecret
	}
	if fc.RedirectURI != "" {
		cfg.RedirectURI = fc.RedirectURI
	}
	if len(fc.RedirectURIs) > 0 {
		cfg.RedirectURIs = fc.RedirectURIs
	}
	if len(fc.DefaultRoles) > 0 {
		cfg.DefaultRoles = fc.DefaultRoles
	}
	if fc.PasswordMinLength > 0 {
		cfg.PasswordMinLength = fc.PasswordMinLength
	}
	if fc.PasswordRequireUppercase {
		cfg.PasswordRequireUppercase = true
	}
	if fc.PasswordRequireLowercase {
		cfg.PasswordRequireLowercase = true
	}
	if fc.PasswordRequireDigit {
		cfg.PasswordRequireDigit = true
	}
	if fc.PasswordRequireSpecial {
		cfg.PasswordRequireSpecial = true
	}
	if fc.PasswordHistoryCount > 0 {
		cfg.PasswordHistoryCount = fc.PasswordHistoryCount
	}
	if fc.AccountLockoutThreshold > 0 {
		cfg.AccountLockoutThreshold = fc.AccountLockoutThreshold
	}
	if fc.AccountLockoutDuration != "" {
		if d, err := time.ParseDuration(fc.AccountLockoutDuration); err == nil {
			cfg.AccountLockoutDuration = d
		}
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
	if v := os.Getenv("AUTH_DEPLOYMENT_NAME"); v != "" {
		cfg.DeploymentName = v
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
	if v := os.Getenv("AUTH_TLS_DISABLED"); v != "" {
		cfg.TLSDisabled = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("AUTH_TRUSTED_PROXIES"); v != "" {
		cfg.TrustedProxies = strings.Split(v, ",")
	}
	if v := os.Getenv("AUTH_BASE_PATH"); v != "" {
		cfg.BasePath = v
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
	if v := os.Getenv("AUTH_CLIENT_ID"); v != "" {
		cfg.ClientID = v
	}
	if v := os.Getenv("AUTH_CLIENT_SECRET"); v != "" {
		cfg.ClientSecret = v
	}
	if v := os.Getenv("AUTH_REDIRECT_URI"); v != "" {
		cfg.RedirectURI = v
	}
	if v := os.Getenv("AUTH_REDIRECT_URIS"); v != "" {
		cfg.RedirectURIs = strings.Split(v, ",")
	}
	if v := os.Getenv("AUTH_DEFAULT_ROLES"); v != "" {
		cfg.DefaultRoles = strings.Split(v, ",")
	}
	if v := os.Getenv("AUTH_PASSWORD_MIN_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.PasswordMinLength = n
		}
	}
	if v := os.Getenv("AUTH_PASSWORD_REQUIRE_UPPERCASE"); v != "" {
		cfg.PasswordRequireUppercase = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("AUTH_PASSWORD_REQUIRE_LOWERCASE"); v != "" {
		cfg.PasswordRequireLowercase = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("AUTH_PASSWORD_REQUIRE_DIGIT"); v != "" {
		cfg.PasswordRequireDigit = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("AUTH_PASSWORD_REQUIRE_SPECIAL"); v != "" {
		cfg.PasswordRequireSpecial = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("AUTH_PASSWORD_HISTORY_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.PasswordHistoryCount = n
		}
	}
	if v := os.Getenv("AUTH_ACCOUNT_LOCKOUT_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.AccountLockoutThreshold = n
		}
	}
	if v := os.Getenv("AUTH_ACCOUNT_LOCKOUT_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.AccountLockoutDuration = d
		}
	}
	if v := os.Getenv("AUTH_AUTO_SSO"); v != "" {
		cfg.AutoSSO = v == "true" || v == "1" || v == "yes"
	}
	if v := os.Getenv("AUTH_AUTO_SSO_DELAY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.AutoSSODelay = n
		}
	}
	if v := os.Getenv("AUTH_POSTGRES_URL"); v != "" {
		cfg.PostgresURL = v
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
