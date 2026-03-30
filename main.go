package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/config"
	"simpleauth/internal/handler"
	"simpleauth/internal/store"
	saui "simpleauth/ui"
)

var (
	Version   = "dev"
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

	for {
		if exit := runServer(); exit {
			break
		}
		log.Println("Restarting SimpleAuth...")
		time.Sleep(500 * time.Millisecond)
	}
}

func runServer() (exit bool) {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Config error: %v", err)
	}

	if cfg.AdminKey == "" {
		cfg.AdminKey = generateAdminKey()
		log.Printf("No admin_key configured — generated temporary key: %s", cfg.AdminKey)
		log.Printf("Set admin_key in config file or AUTH_ADMIN_KEY env var to make it permanent")
	}

	// Open store (PostgreSQL if configured, otherwise BoltDB)
	s, err := store.OpenWithConfig(cfg.DataDir, cfg.PostgresURL)
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

	// Set up restart channel
	restartCh := make(chan struct{}, 1)
	h.SetRestartChannel(restartCh)

	// Start audit log pruner
	h.StartAuditPruner()

	log.Printf("SimpleAuth %s starting", Version)
	log.Printf("Hostname: %s", cfg.Hostname)
	log.Printf("Data directory: %s", cfg.DataDir)
	if cfg.PostgresURL != "" {
		log.Printf("Database: PostgreSQL")
	} else {
		log.Printf("Database: BoltDB (%s/auth.db)", cfg.DataDir)
	}
	log.Printf("Admin UI: %s/admin", cfg.BasePath)

	// Print access URLs
	if cfg.TLSDisabled {
		log.Printf("Listening:    http://0.0.0.0:%s%s", cfg.Port, cfg.BasePath)
		log.Printf("Admin UI:     http://0.0.0.0:%s%s/admin", cfg.Port, cfg.BasePath)
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

	var srv *http.Server

	if cfg.TLSDisabled {
		addr := ":" + cfg.Port
		log.Printf("HTTP listening on %s (TLS disabled — reverse proxy mode)", addr)
		srv = &http.Server{Addr: addr, Handler: h}
	} else {
		// Start HTTP → HTTPS redirect server
		if cfg.HTTPPort != "" {
			go func() {
				httpAddr := ":" + cfg.HTTPPort
				httpsPort := cfg.Port
				log.Printf("HTTP redirect :%s → HTTPS :%s", cfg.HTTPPort, httpsPort)
				redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					host := r.Host
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
				http.ListenAndServe(httpAddr, redirectHandler)
			}()
		}

		addr := ":" + cfg.Port
		log.Printf("HTTPS listening on %s", addr)
		srv = &http.Server{Addr: addr, Handler: h}
	}

	// Listen for restart signal
	go func() {
		<-restartCh
		log.Println("Graceful shutdown initiated by admin...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	// Start serving
	if cfg.TLSDisabled {
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	}

	if err == http.ErrServerClosed {
		// Graceful shutdown — restart
		return false
	}
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
	return true
}

func generateAdminKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
