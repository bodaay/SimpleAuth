// Package server provides an embeddable SimpleAuth server for Go applications.
//
// Usage:
//
//	sa, err := server.New(&server.Config{
//	    Hostname:    "auth.example.com",
//	    AdminKey:    "my-secret-key",
//	    DataDir:     "./simpleauth-data",
//	    TLSDisabled: true,
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
//
// Pass nil as the first argument to load config from env vars / config file
// (same behavior as the standalone binary):
//
//	sa, err := server.New(nil, ui.FS())
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

// Config holds all configuration for SimpleAuth. This is the same struct
// used by the standalone binary — every field is available.
//
// When passed to New(), the config is used as-is. Sensible defaults are
// applied for zero-value fields (see Defaults()). Environment variables
// are NOT read — the caller has full control.
//
// To load from env vars instead, pass nil to New().
type Config = config.Config

// Defaults returns a Config populated with sensible defaults.
// Use this as a starting point when configuring programmatically:
//
//	cfg := server.Defaults()
//	cfg.Hostname = "auth.example.com"
//	cfg.AdminKey = "my-secret-key"
//	cfg.TLSDisabled = true
//	cfg.DataDir = "./auth-data"
func Defaults() *Config {
	return &Config{
		Port:            "9090",
		DataDir:         "./data",
		DeploymentName:  "sauth",
		JWTIssuer:       "simpleauth",
		AccessTTL:       8 * time.Hour,
		RefreshTTL:      720 * time.Hour,
		ImpersonateTTL:  1 * time.Hour,
		AuditRetention:  90 * 24 * time.Hour,
		RateLimitMax:    10,
		RateLimitWindow: 1 * time.Minute,
		HTTPPort:        "80",
		PasswordMinLength:      8,
		AccountLockoutDuration: 30 * time.Minute,
	}
}

// Server is an embedded SimpleAuth instance.
type Server struct {
	handler *handler.Handler
	store   store.Store
}

// New creates a new embedded SimpleAuth server.
//
// If cfg is non-nil, it is used directly — env vars and config files are NOT
// read. Zero-value fields get sensible defaults (same as Defaults()).
//
// If cfg is nil, config is loaded from env vars / config file / defaults,
// exactly like the standalone binary.
//
// The uiFS parameter provides the admin UI filesystem. Use ui.FS() from
// the simpleauth/ui package, or pass nil for API-only mode (no admin UI).
func New(cfg *Config, uiFS fs.FS) (*Server, error) {
	if cfg == nil {
		// Load from env/file — same as standalone binary
		cfg = config.Load()
	} else {
		// Programmatic config — fill in defaults for zero values
		applyDefaults(cfg)
	}

	// Validate (generates TLS certs, parses CIDRs, etc.)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("simpleauth: %w", err)
	}

	if cfg.AdminKey == "" {
		cfg.AdminKey = generateKey()
		log.Printf("[simpleauth] No admin_key configured — generated temporary key: %s", cfg.AdminKey)
	}

	s, err := store.OpenWithConfig(cfg.DataDir, cfg.PostgresURL)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: open store: %w", err)
	}

	if len(cfg.DefaultRoles) > 0 {
		existing, _ := s.GetDefaultRoles()
		if len(existing) == 0 {
			s.SetDefaultRoles(cfg.DefaultRoles)
		}
	}

	jwtMgr, err := auth.NewJWTManager(cfg.DataDir, cfg.JWTIssuer)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("simpleauth: init JWT: %w", err)
	}

	h := handler.New(cfg, s, jwtMgr, uiFS, "embedded")

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

func applyDefaults(cfg *Config) {
	defaults := Defaults()
	if cfg.Port == "" {
		cfg.Port = defaults.Port
	}
	if cfg.DataDir == "" {
		cfg.DataDir = defaults.DataDir
	}
	if cfg.DeploymentName == "" {
		cfg.DeploymentName = defaults.DeploymentName
	}
	if cfg.JWTIssuer == "" {
		cfg.JWTIssuer = defaults.JWTIssuer
	}
	if cfg.AccessTTL == 0 {
		cfg.AccessTTL = defaults.AccessTTL
	}
	if cfg.RefreshTTL == 0 {
		cfg.RefreshTTL = defaults.RefreshTTL
	}
	if cfg.ImpersonateTTL == 0 {
		cfg.ImpersonateTTL = defaults.ImpersonateTTL
	}
	if cfg.AuditRetention == 0 {
		cfg.AuditRetention = defaults.AuditRetention
	}
	if cfg.RateLimitMax == 0 {
		cfg.RateLimitMax = defaults.RateLimitMax
	}
	if cfg.RateLimitWindow == 0 {
		cfg.RateLimitWindow = defaults.RateLimitWindow
	}
	if cfg.HTTPPort == "" {
		cfg.HTTPPort = defaults.HTTPPort
	}
	if cfg.PasswordMinLength == 0 {
		cfg.PasswordMinLength = defaults.PasswordMinLength
	}
	if cfg.AccountLockoutDuration == 0 {
		cfg.AccountLockoutDuration = defaults.AccountLockoutDuration
	}
}

func generateKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
