package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"

	"simpleauth/internal/auth"
	"simpleauth/internal/config"
	"simpleauth/internal/handler"
	"simpleauth/internal/store"
)

//go:embed ui/dist/*
var uiFiles embed.FS

func main() {
	cfg := config.Load()

	if cfg.AdminKey == "" {
		fmt.Fprintln(os.Stderr, "FATAL: AUTH_ADMIN_KEY environment variable is required")
		os.Exit(1)
	}

	// Open BoltDB store
	s, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to open store: %v", err)
	}
	defer s.Close()

	// Initialize JWT manager (auto-generates RSA keys on first run)
	jwtMgr, err := auth.NewJWTManager(cfg.DataDir, cfg.JWTIssuer)
	if err != nil {
		log.Fatalf("Failed to initialize JWT manager: %v", err)
	}

	// Prepare embedded UI filesystem
	uiFS, err := fs.Sub(uiFiles, "ui/dist")
	if err != nil {
		log.Fatalf("Failed to load embedded UI: %v", err)
	}

	// Create handler
	h := handler.New(cfg, s, jwtMgr, uiFS)

	// Start audit log pruner
	h.StartAuditPruner()

	addr := ":" + cfg.Port
	log.Printf("SimpleAuth starting on %s", addr)
	log.Printf("Data directory: %s", cfg.DataDir)

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("TLS enabled")
		if err := http.ListenAndServeTLS(addr, cfg.TLSCert, cfg.TLSKey, h); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	} else {
		if err := http.ListenAndServe(addr, h); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}
