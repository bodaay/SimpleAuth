package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"simpleauth/internal/migrate"
	"simpleauth/internal/store"
)

// --- Central side: receive a standalone deployment as a named app ---
//
// Importing a directory is a master-level operation, so it is gated by a
// single-use, app-scoped MIGRATION TOKEN that a master admin mints on the target
// app. The standalone authenticates the cross-install preflight/commit calls with
// that token (Authorization: Bearer). Tokens are stored hashed, expire, and are
// consumed on commit.

const migrationTokenTTL = 30 * time.Minute

type migrationTokenRecord struct {
	Hash      string    `json:"hash"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	// AppCreatedAt binds the token to this app INSTANCE: if the app_id is deleted
	// and re-registered, the new app has a different CreatedAt and the old token
	// no longer authenticates (it would otherwise take over an unrelated new app).
	AppCreatedAt time.Time `json:"app_created_at"`
}

func migrationTokenKey(appID string) string { return "migration_token:" + appID }

func hashMigrationToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// handleGenMigrationToken mints a single-use migration token for a target app.
// POST /api/admin/apps/{app_id}/migration-token  (master admin)
func (h *Handler) handleGenMigrationToken(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	if appID == h.defaultAppID() {
		jsonError(w, "the default app cannot be a migration target", http.StatusForbidden)
		return
	}
	app, err := h.store.GetApp(appID)
	if err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		jsonError(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	raw := "sa_mig_" + base64.RawURLEncoding.EncodeToString(b)
	rec := migrationTokenRecord{Hash: hashMigrationToken(raw), ExpiresAt: time.Now().UTC().Add(migrationTokenTTL), AppCreatedAt: app.CreatedAt}
	data, _ := json.Marshal(rec)
	if err := h.store.SetConfigValue(migrationTokenKey(appID), data); err != nil {
		jsonError(w, "failed to store token", http.StatusInternalServerError)
		return
	}
	h.audit("migration_token_issued", "admin", getClientIP(r), map[string]interface{}{"app_id": appID})
	jsonResp(w, map[string]interface{}{
		"migration_token": raw, // shown once
		"app_id":          appID,
		"expires_at":      rec.ExpiresAt,
	}, http.StatusOK)
}

// authMigration validates the bearer migration token against the target app. It
// never reveals which check failed (uniform false), is constant-time on the hash,
// and rejects a token whose app instance (CreatedAt) no longer matches.
func (h *Handler) authMigration(r *http.Request, app *store.App) bool {
	tok := extractBearerToken(r)
	if tok == "" || app == nil {
		return false
	}
	data, err := h.store.GetConfigValue(migrationTokenKey(app.AppID))
	if err != nil || len(data) == 0 {
		return false
	}
	var rec migrationTokenRecord
	if json.Unmarshal(data, &rec) != nil {
		return false
	}
	if rec.Used || time.Now().UTC().After(rec.ExpiresAt) || !rec.AppCreatedAt.Equal(app.CreatedAt) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(rec.Hash), []byte(hashMigrationToken(tok))) == 1
}

// consumeMigrationToken marks the token used. It returns an error if the claim
// could not be persisted, so the caller can fail closed BEFORE applying (a
// silently-failed consume would otherwise leave the token replayable).
func (h *Handler) consumeMigrationToken(appID string) error {
	data, err := h.store.GetConfigValue(migrationTokenKey(appID))
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("token not found")
	}
	var rec migrationTokenRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	rec.Used = true
	out, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return h.store.SetConfigValue(migrationTokenKey(appID), out)
}

type migrationRequest struct {
	AppID       string          `json:"app_id"`
	Bundle      *migrate.Bundle `json:"bundle"`
	CarrySecret bool            `json:"carry_secret"`
}

// guardMigrationCall does the shared validation for preflight/commit: rate-limit,
// parse, token auth, schema compatibility, and target-app sanity. Returns the
// parsed request, or false if it already wrote an error response.
func (h *Handler) guardMigrationCall(w http.ResponseWriter, r *http.Request) (*migrationRequest, bool) {
	if !h.loginLimiter.allow(getClientIP(r)) {
		jsonError(w, "too many requests", http.StatusTooManyRequests)
		return nil, false
	}
	var req migrationRequest
	if err := readJSON(r, &req); err != nil || req.Bundle == nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return nil, false
	}
	if req.Bundle.SchemaRev != migrate.SchemaRev {
		jsonError(w, "incompatible migration bundle — upgrade the older deployment first", http.StatusBadRequest)
		return nil, false
	}
	if req.AppID == h.defaultAppID() {
		jsonError(w, "the default app cannot be a migration target", http.StatusForbidden)
		return nil, false
	}
	// Authenticate BEFORE revealing any app state: a missing app and a bad token
	// both return the same 401, so an unauthenticated caller can't enumerate which
	// app_ids exist. Disabled is only reported once the token is valid.
	app, err := h.store.GetApp(req.AppID)
	if err != nil || !h.authMigration(r, app) {
		jsonError(w, "invalid or expired migration token", http.StatusUnauthorized)
		return nil, false
	}
	if app.Disabled {
		jsonError(w, "target app is disabled", http.StatusForbidden)
		return nil, false
	}
	return &req, true
}

// handleMigrationPreflight runs the dry-run classifier and returns the report,
// mutating nothing. POST /api/migration/preflight  (migration-token auth)
func (h *Handler) handleMigrationPreflight(w http.ResponseWriter, r *http.Request) {
	req, ok := h.guardMigrationCall(w, r)
	if !ok {
		return
	}
	rep, err := migrate.Classify(req.Bundle, h.store, req.AppID, h.defaultAppID())
	if err != nil {
		jsonError(w, "preflight failed", http.StatusInternalServerError)
		return
	}
	jsonResp(w, rep, http.StatusOK)
}

// handleMigrationCommit applies the bundle and consumes the token. It re-runs the
// classifier and refuses if any user is blocked. POST /api/migration/commit
func (h *Handler) handleMigrationCommit(w http.ResponseWriter, r *http.Request) {
	// Serialize commits so the token-claim and Apply are atomic: a second
	// concurrent commit blocks here, then fails auth once the token is consumed —
	// closing the TOCTOU that would otherwise allow a double import.
	h.migrationMu.Lock()
	defer h.migrationMu.Unlock()

	req, ok := h.guardMigrationCall(w, r)
	if !ok {
		return
	}
	rep, err := migrate.Classify(req.Bundle, h.store, req.AppID, h.defaultAppID())
	if err != nil {
		jsonError(w, "preflight failed", http.StatusInternalServerError)
		return
	}
	if !rep.OK() {
		// Nothing is applied, so leave the token usable for a retry after the
		// operator resolves the blocked users.
		jsonResp(w, map[string]interface{}{"error": "migration has blocked users — resolve them first", "report": rep}, http.StatusConflict)
		return
	}
	// Claim the token BEFORE Apply: a partially-applied (non-transactional) commit
	// must not leave a replayable token. Fail closed if the claim can't persist.
	if err := h.consumeMigrationToken(req.AppID); err != nil {
		jsonError(w, "could not claim the migration token — retry", http.StatusInternalServerError)
		return
	}

	// Apply provisions app-local users (check-then-create); take localUserMu so it
	// can't race a concurrent self-service local-user create on the same app. The
	// deferred unlock (in a closure) survives a panic inside Apply.
	res, err := func() (*migrate.ApplyResult, error) {
		h.localUserMu.Lock()
		defer h.localUserMu.Unlock()
		return migrate.Apply(req.Bundle, h.store, req.AppID, h.defaultAppID(), req.CarrySecret)
	}()
	if err != nil {
		jsonError(w, "commit failed (token spent; if the target was partially written, clear it before retrying with a new token): "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.audit("migration_committed", "migration:"+req.AppID, getClientIP(r), map[string]interface{}{
		"app_id": req.AppID, "assignments": res.AssignmentsSet, "local_users": res.LocalUsersCreated,
		"audience": rep.AudienceToApply,
	})
	jsonResp(w, res, http.StatusOK)
}
