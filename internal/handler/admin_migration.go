package handler

import (
	"encoding/json"
	"net/http"
	"sync"

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
	info := map[string]interface{}{
		"backend": h.storeBackend(),
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

// handleMigrateStart starts a BoltDB → Postgres migration.
// POST /api/admin/database/migrate
func (h *Handler) handleMigrateStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PostgresURL string `json:"postgres_url"`
	}
	if err := readJSON(r, &req); err != nil || req.PostgresURL == "" {
		jsonError(w, "postgres_url is required", http.StatusBadRequest)
		return
	}

	boltStore, ok := h.store.(*store.BoltStore)
	if !ok {
		jsonError(w, "migration only supported from BoltDB backend", http.StatusBadRequest)
		return
	}

	h.migration.mu.RLock()
	if h.migration.status.State == "running" {
		h.migration.mu.RUnlock()
		jsonError(w, "migration already in progress", http.StatusConflict)
		return
	}
	h.migration.mu.RUnlock()

	// Open target Postgres
	target, err := store.OpenPostgres(req.PostgresURL)
	if err != nil {
		jsonError(w, "failed to connect to postgres: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Reset status
	h.migration.mu.Lock()
	h.migration.status = store.MigrationStatus{State: "running", Progress: map[string]string{}}
	h.migration.mu.Unlock()

	statusCh := make(chan store.MigrationStatus, 100)

	// Background migration
	go func() {
		defer target.Close()

		// Consume status updates
		done := make(chan struct{})
		go func() {
			for s := range statusCh {
				h.migration.mu.Lock()
				h.migration.status = s
				h.migration.mu.Unlock()
			}
			close(done)
		}()

		err := store.MigrateToPostgres(boltStore, target, statusCh)
		close(statusCh)
		<-done

		if err != nil {
			h.migration.mu.Lock()
			h.migration.status.State = "failed"
			h.migration.status.Error = err.Error()
			h.migration.mu.Unlock()
		}
	}()

	h.audit("migration_started", "admin", getClientIP(r), map[string]interface{}{
		"target": "postgres",
	})

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
