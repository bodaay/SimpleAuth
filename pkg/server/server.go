// Package server provides an embeddable SimpleAuth server for Go applications.
//
// Usage:
//
//	import (
//	    "simpleauth/pkg/server"
//	    "simpleauth/ui"
//	)
//
//	sa, err := server.New(server.Config{
//	    Hostname: "auth.example.com",
//	    AdminKey: "my-secret-key",
//	    DataDir:  "./simpleauth-data",
//	}, ui.FS())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer sa.Close()
//
//	mux := http.NewServeMux()
//	mux.Handle("/auth/", http.StripPrefix("/auth", sa.Handler()))
//	mux.Handle("/", myAppHandler)
//	http.ListenAndServe(":8080", mux)
package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/config"
	"simpleauth/internal/handler"
	"simpleauth/internal/store"
)

// Config holds configuration for the embedded SimpleAuth server.
// Any zero-value field falls through to environment variables (AUTH_*),
// then to config file, then to defaults — same as the standalone binary.
type Config struct {
	// Hostname is the public hostname (e.g. "auth.example.com").
	Hostname string
	// Port for the embedded handler (informational — you manage your own listener).
	Port string
	// DataDir is the directory for BoltDB and RSA keys. Default: "./data"
	DataDir string
	// AdminKey for admin API authentication. If empty, a random key is generated and logged.
	AdminKey string
	// JWTIssuer is the "iss" claim in issued tokens. Default: derived from hostname.
	JWTIssuer string
	// AccessTTL is the lifetime of access tokens. Default: 15m.
	AccessTTL time.Duration
	// RefreshTTL is the lifetime of refresh tokens. Default: 7 days.
	RefreshTTL time.Duration
	// DefaultRoles are assigned to new users on first login.
	DefaultRoles []string
	// CORSOrigins is a comma-separated list of allowed CORS origins.
	CORSOrigins string
	// ClientID for OIDC. If empty, falls through to env/config.
	ClientID string
	// ClientSecret for OIDC. If empty, falls through to env/config.
	ClientSecret string
	// RedirectURI for OIDC callback. If empty, falls through to env/config.
	RedirectURI string
	// BasePath prefix if mounted under a subpath (e.g. "/auth").
	BasePath string

	// Password policy
	PasswordMinLength        int
	PasswordRequireUppercase bool
	PasswordRequireLowercase bool
	PasswordRequireDigit     bool
	PasswordRequireSpecial   bool
	PasswordHistoryCount     int
	AccountLockoutThreshold  int
	AccountLockoutDuration   time.Duration
}

// Server is an embedded SimpleAuth instance.
type Server struct {
	handler *handler.Handler
	store   *store.Store
}

// New creates a new embedded SimpleAuth server. The uiFS parameter provides
// the admin UI filesystem (use ui.FS() from the simpleauth/ui package, or
// pass nil to run without a UI).
//
// Fields set in cfg override environment variables. Unset fields (zero values)
// fall through to AUTH_* env vars, config file, then defaults.
func New(cfg Config, uiFS fs.FS) (*Server, error) {
	// Load base config from env/file (same as standalone)
	base := config.Load()

	// Override with any explicitly set fields
	applyOverrides(base, &cfg)

	if base.AdminKey == "" {
		base.AdminKey = generateKey()
		log.Printf("[simpleauth] No admin_key configured — generated temporary key: %s", base.AdminKey)
	}

	s, err := store.Open(base.DataDir)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: open store: %w", err)
	}

	if len(base.DefaultRoles) > 0 {
		existing, _ := s.GetDefaultRoles()
		if len(existing) == 0 {
			s.SetDefaultRoles(base.DefaultRoles)
		}
	}

	jwtMgr, err := auth.NewJWTManager(base.DataDir, base.JWTIssuer)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("simpleauth: init JWT: %w", err)
	}

	h := handler.New(base, s, jwtMgr, uiFS, "embedded")

	h.StartAuditPruner()

	return &Server{handler: h, store: s}, nil
}

// Handler returns the http.Handler for SimpleAuth.
// Mount this on your router at the desired path.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Close shuts down the SimpleAuth server and releases resources.
func (s *Server) Close() error {
	return s.store.Close()
}

func applyOverrides(base *config.Config, cfg *Config) {
	if cfg.Hostname != "" {
		base.Hostname = cfg.Hostname
	}
	if cfg.Port != "" {
		base.Port = cfg.Port
	}
	if cfg.DataDir != "" {
		base.DataDir = cfg.DataDir
	}
	if cfg.AdminKey != "" {
		base.AdminKey = cfg.AdminKey
	}
	if cfg.JWTIssuer != "" {
		base.JWTIssuer = cfg.JWTIssuer
	}
	if cfg.AccessTTL != 0 {
		base.AccessTTL = cfg.AccessTTL
	}
	if cfg.RefreshTTL != 0 {
		base.RefreshTTL = cfg.RefreshTTL
	}
	if cfg.DefaultRoles != nil {
		base.DefaultRoles = cfg.DefaultRoles
	}
	if cfg.CORSOrigins != "" {
		base.CORSOrigins = cfg.CORSOrigins
	}
	if cfg.ClientID != "" {
		base.ClientID = cfg.ClientID
	}
	if cfg.ClientSecret != "" {
		base.ClientSecret = cfg.ClientSecret
	}
	if cfg.RedirectURI != "" {
		base.RedirectURI = cfg.RedirectURI
	}
	if cfg.BasePath != "" {
		base.BasePath = cfg.BasePath
	}
	if cfg.PasswordMinLength != 0 {
		base.PasswordMinLength = cfg.PasswordMinLength
	}
	if cfg.PasswordRequireUppercase {
		base.PasswordRequireUppercase = true
	}
	if cfg.PasswordRequireLowercase {
		base.PasswordRequireLowercase = true
	}
	if cfg.PasswordRequireDigit {
		base.PasswordRequireDigit = true
	}
	if cfg.PasswordRequireSpecial {
		base.PasswordRequireSpecial = true
	}
	if cfg.PasswordHistoryCount != 0 {
		base.PasswordHistoryCount = cfg.PasswordHistoryCount
	}
	if cfg.AccountLockoutThreshold != 0 {
		base.AccountLockoutThreshold = cfg.AccountLockoutThreshold
	}
	if cfg.AccountLockoutDuration != 0 {
		base.AccountLockoutDuration = cfg.AccountLockoutDuration
	}
}

func generateKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
