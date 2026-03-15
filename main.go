package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"simpleauth/internal/auth"
	"simpleauth/internal/config"
	"simpleauth/internal/handler"
	"simpleauth/internal/store"
	saui "simpleauth/ui"
)

var (
	Version   = "0.2.3"
	BuildTime = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("simpleauth %s (built %s)\n", Version, BuildTime)
			return
		case "init-config":
			path := "simpleauth.yaml"
			if len(os.Args) > 2 {
				path = os.Args[2]
			}
			if err := config.WriteDefaultConfig(path); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Default config written to %s\n", path)
			return
		}
	}

	cfg := config.Load()

	if cfg.AdminKey == "" {
		cfg.AdminKey = generateAdminKey()
		log.Printf("No admin_key configured — generated temporary key: %s", cfg.AdminKey)
		log.Printf("Set admin_key in config file or AUTH_ADMIN_KEY env var to make it permanent")
	}

	// Open BoltDB store
	s, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to open store: %v", err)
	}
	defer s.Close()

	// Seed default roles from config if store has none
	if len(cfg.DefaultRoles) > 0 {
		existing, _ := s.GetDefaultRoles()
		if len(existing) == 0 {
			s.SetDefaultRoles(cfg.DefaultRoles)
			log.Printf("Default roles set from config: %v", cfg.DefaultRoles)
		}
	}

	// Initialize JWT manager (auto-generates RSA keys on first run)
	jwtMgr, err := auth.NewJWTManager(cfg.DataDir, cfg.JWTIssuer)
	if err != nil {
		log.Fatalf("Failed to initialize JWT manager: %v", err)
	}

	// Create handler
	h := handler.New(cfg, s, jwtMgr, saui.FS(), Version)

	// Start audit log pruner
	h.StartAuditPruner()

	log.Printf("SimpleAuth %s starting", Version)
	log.Printf("Hostname: %s", cfg.Hostname)
	log.Printf("Data directory: %s", cfg.DataDir)
	log.Printf("Admin UI: %s/admin", cfg.BasePath)

	// Print access URLs
	if cfg.TLSDisabled {
		// Behind reverse proxy — show the public URL and internal Docker/container URL
		log.Printf("Public URL:   https://%s%s", cfg.Hostname, cfg.BasePath)
		internalHost, _ := os.Hostname()
		if internalHost == "" {
			internalHost = "0.0.0.0"
		}
		log.Printf("Internal URL: http://%s:%s%s", internalHost, cfg.Port, cfg.BasePath)
	} else {
		port := cfg.Port
		portSuffix := ":" + port
		if port == "443" {
			portSuffix = ""
		}
		log.Printf("Access: https://%s%s%s", cfg.Hostname, portSuffix, cfg.BasePath)
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					log.Printf("Access: https://%s%s%s", ipnet.IP, portSuffix, cfg.BasePath)
				}
			}
		}
	}

	if cfg.TLSDisabled {
		// HTTP-only mode (behind reverse proxy)
		addr := ":" + cfg.Port
		log.Printf("HTTP listening on %s (TLS disabled — reverse proxy mode)", addr)
		if err := http.ListenAndServe(addr, h); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	} else {
		// Start HTTP → HTTPS redirect server
		if cfg.HTTPPort != "" {
			go func() {
				httpAddr := ":" + cfg.HTTPPort
				httpsPort := cfg.Port
				log.Printf("HTTP redirect :%s → HTTPS :%s", cfg.HTTPPort, httpsPort)
				redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					host := r.Host
					// Strip port from host if present
					if h, _, err := net.SplitHostPort(host); err == nil {
						host = h
					}
					target := "https://" + host
					if httpsPort != "443" {
						target += ":" + httpsPort
					}
					target += r.URL.RequestURI()
					http.Redirect(w, r, target, http.StatusMovedPermanently)
				})
				if err := http.ListenAndServe(httpAddr, redirectHandler); err != nil {
					log.Printf("HTTP redirect server failed: %v (non-fatal)", err)
				}
			}()
		}

		// Serve HTTPS
		tlsAddr := ":" + cfg.Port
		log.Printf("HTTPS listening on %s", tlsAddr)
		if err := http.ListenAndServeTLS(tlsAddr, cfg.TLSCert, cfg.TLSKey, h); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}
}

func generateAdminKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
