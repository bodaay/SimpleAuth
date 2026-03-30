package handler

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"simpleauth/internal/store"
)

// migrationState tracks in-flight migration progress.
type migrationState struct {
	mu     sync.RWMutex
	status store.MigrationStatus
}

func (h *Handler) initMigrationState() {
	h.migration = &migrationState{
		status: store.MigrationStatus{State: "idle", Progress: map[string]string{}},
	}
}

// handleDatabaseInfo returns info about the current database backend.
// GET /api/admin/database/info
func (h *Handler) handleDatabaseInfo(w http.ResponseWriter, r *http.Request) {
	dbCfg, _ := store.LoadDBConfig(h.cfg.DataDir)
	info := map[string]interface{}{
		"backend": h.storeBackend(),
	}
	if dbCfg != nil && dbCfg.PostgresURL != "" {
		// Mask password in URL for display
		info["postgres_configured"] = true
	}
	jsonResp(w, info, http.StatusOK)
}

func (h *Handler) storeBackend() string {
	switch h.store.(type) {
	case *store.BoltStore:
		return "boltdb"
	case *store.PostgresStore:
		return "postgres"
	default:
		return "unknown"
	}
}

// handleMigrateTest tests a Postgres connection.
// POST /api/admin/database/test
func (h *Handler) handleMigrateTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PostgresURL string `json:"postgres_url"`
	}
	if err := readJSON(r, &req); err != nil || req.PostgresURL == "" {
		jsonError(w, "postgres_url is required", http.StatusBadRequest)
		return
	}

	if err := store.TestPostgresConnection(req.PostgresURL); err != nil {
		jsonResp(w, map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		}, http.StatusOK)
		return
	}

	jsonResp(w, map[string]interface{}{"ok": true}, http.StatusOK)
}

// handleMigrateStart starts a migration (BoltDB→Postgres or Postgres→BoltDB).
// POST /api/admin/database/migrate
func (h *Handler) handleMigrateStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PostgresURL string `json:"postgres_url"` // required for bolt→pg
		Direction   string `json:"direction"`     // "to_postgres" (default) or "to_boltdb"
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Direction == "" {
		req.Direction = "to_postgres"
	}

	h.migration.mu.RLock()
	if h.migration.status.State == "running" {
		h.migration.mu.RUnlock()
		jsonError(w, "migration already in progress", http.StatusConflict)
		return
	}
	h.migration.mu.RUnlock()

	// Reset status
	h.migration.mu.Lock()
	h.migration.status = store.MigrationStatus{State: "running", Progress: map[string]string{}}
	h.migration.mu.Unlock()

	statusCh := make(chan store.MigrationStatus, 100)

	// Consume status updates in background
	consumeStatus := func() chan struct{} {
		done := make(chan struct{})
		go func() {
			for s := range statusCh {
				h.migration.mu.Lock()
				h.migration.status = s
				h.migration.mu.Unlock()
			}
			close(done)
		}()
		return done
	}

	switch req.Direction {
	case "to_postgres":
		if req.PostgresURL == "" {
			jsonError(w, "postgres_url is required", http.StatusBadRequest)
			return
		}
		boltStore, ok := h.store.(*store.BoltStore)
		if !ok {
			jsonError(w, "current backend is not BoltDB", http.StatusBadRequest)
			return
		}
		target, err := store.OpenPostgres(req.PostgresURL)
		if err != nil {
			jsonError(w, "failed to connect to postgres: "+err.Error(), http.StatusBadRequest)
			return
		}

		go func() {
			done := consumeStatus()
			err := store.MigrateToPostgres(boltStore, target, statusCh)
			close(statusCh)
			<-done
			target.Close()

			if err != nil {
				h.migration.mu.Lock()
				h.migration.status.State = "failed"
				h.migration.status.Error = err.Error()
				h.migration.mu.Unlock()
			}
		}()

		h.audit("migration_started", "admin", getClientIP(r), map[string]interface{}{
			"direction": "to_postgres",
		})

	case "to_boltdb":
		pgStore, ok := h.store.(*store.PostgresStore)
		if !ok {
			jsonError(w, "current backend is not PostgreSQL", http.StatusBadRequest)
			return
		}
		target, err := store.OpenBolt(h.cfg.DataDir)
		if err != nil {
			jsonError(w, "failed to open BoltDB: "+err.Error(), http.StatusInternalServerError)
			return
		}

		go func() {
			done := consumeStatus()
			err := store.MigrateFromPostgres(pgStore, target, statusCh)
			close(statusCh)
			<-done
			target.Close()

			if err != nil {
				h.migration.mu.Lock()
				h.migration.status.State = "failed"
				h.migration.status.Error = err.Error()
				h.migration.mu.Unlock()
			}
		}()

		h.audit("migration_started", "admin", getClientIP(r), map[string]interface{}{
			"direction": "to_boltdb",
		})

	default:
		jsonError(w, "direction must be 'to_postgres' or 'to_boltdb'", http.StatusBadRequest)
		return
	}

	jsonResp(w, map[string]string{"status": "started"}, http.StatusAccepted)
}

// handleMigrateStatus returns current migration progress.
// GET /api/admin/database/migrate/status
func (h *Handler) handleMigrateStatus(w http.ResponseWriter, r *http.Request) {
	h.migration.mu.RLock()
	status := h.migration.status
	h.migration.mu.RUnlock()

	data, _ := json.Marshal(status)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleSwitchBackend saves the backend choice to db.json and triggers restart.
// POST /api/admin/database/switch
func (h *Handler) handleSwitchBackend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Backend     string `json:"backend"`      // "boltdb" or "postgres"
		PostgresURL string `json:"postgres_url"`  // required when backend=postgres
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	switch req.Backend {
	case "boltdb":
		if err := store.SaveDBConfig(h.cfg.DataDir, &store.DBConfig{Backend: "boltdb"}); err != nil {
			jsonError(w, "failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	case "postgres":
		if req.PostgresURL == "" {
			jsonError(w, "postgres_url is required", http.StatusBadRequest)
			return
		}
		if err := store.TestPostgresConnection(req.PostgresURL); err != nil {
			jsonError(w, "postgres connection failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := store.SaveDBConfig(h.cfg.DataDir, &store.DBConfig{Backend: "postgres", PostgresURL: req.PostgresURL}); err != nil {
			jsonError(w, "failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		jsonError(w, "backend must be 'boltdb' or 'postgres'", http.StatusBadRequest)
		return
	}

	h.audit("backend_switched", "admin", getClientIP(r), map[string]interface{}{
		"backend": req.Backend,
	})

	jsonResp(w, map[string]string{"status": "saved", "backend": req.Backend}, http.StatusOK)

	// Trigger restart if channel available
	if h.restartCh != nil {
		go func() {
			time.Sleep(200 * time.Millisecond)
			select {
			case h.restartCh <- struct{}{}:
			default:
			}
		}()
	}
}
