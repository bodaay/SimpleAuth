package handler

import (
	"net/http"
	"sync"
	"time"

	"simpleauth/internal/store"
)

// runtimeSettingsCache caches runtime settings in memory for fast access.
type runtimeSettingsCache struct {
	mu sync.RWMutex
	rs *store.RuntimeSettings
}

func (c *runtimeSettingsCache) get() *store.RuntimeSettings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rs
}

func (c *runtimeSettingsCache) set(rs *store.RuntimeSettings) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rs = rs
}

// initRuntimeSettings loads or seeds runtime settings from DB.
// On first run, env/config values seed the DB. After that, DB owns the values.
func (h *Handler) initRuntimeSettings() {
	existing, _ := h.store.GetRuntimeSettings()
	if existing != nil {
		h.runtimeSettings.set(existing)
		return
	}

	// First run — seed from config
	rs := &store.RuntimeSettings{
		DeploymentName:           h.cfg.DeploymentName,
		RedirectURIs:             h.cfg.RedirectURIs,
		CORSOrigins:              h.cfg.CORSOrigins,
		PasswordMinLength:        h.cfg.PasswordMinLength,
		PasswordRequireUppercase: h.cfg.PasswordRequireUppercase,
		PasswordRequireLowercase: h.cfg.PasswordRequireLowercase,
		PasswordRequireDigit:     h.cfg.PasswordRequireDigit,
		PasswordRequireSpecial:   h.cfg.PasswordRequireSpecial,
		PasswordHistoryCount:     h.cfg.PasswordHistoryCount,
		AccountLockoutThreshold:  h.cfg.AccountLockoutThreshold,
		AccountLockoutDurationS:  int(h.cfg.AccountLockoutDuration.Seconds()),
		DefaultRoles:             h.cfg.DefaultRoles,
		RateLimitMax:             h.cfg.RateLimitMax,
		RateLimitWindowS:         int(h.cfg.RateLimitWindow.Seconds()),
		AuditRetentionDays:       int(h.cfg.AuditRetention.Hours() / 24),
	}
	h.store.SaveRuntimeSettings(rs)
	h.runtimeSettings.set(rs)
}

// --- Accessor helpers (read from cache) ---

func (h *Handler) getRedirectURIs() []string {
	if rs := h.runtimeSettings.get(); rs != nil && len(rs.RedirectURIs) > 0 {
		return rs.RedirectURIs
	}
	return h.cfg.RedirectURIs
}

func (h *Handler) getCORSOrigins() string {
	if rs := h.runtimeSettings.get(); rs != nil && rs.CORSOrigins != "" {
		return rs.CORSOrigins
	}
	return h.cfg.CORSOrigins
}

func (h *Handler) getAccountLockoutThreshold() int {
	if rs := h.runtimeSettings.get(); rs != nil {
		return rs.AccountLockoutThreshold
	}
	return h.cfg.AccountLockoutThreshold
}

func (h *Handler) getAccountLockoutDuration() time.Duration {
	if rs := h.runtimeSettings.get(); rs != nil && rs.AccountLockoutDurationS > 0 {
		return time.Duration(rs.AccountLockoutDurationS) * time.Second
	}
	return h.cfg.AccountLockoutDuration
}

func (h *Handler) getPasswordHistoryCount() int {
	if rs := h.runtimeSettings.get(); rs != nil {
		return rs.PasswordHistoryCount
	}
	return h.cfg.PasswordHistoryCount
}

func (h *Handler) getAuditRetention() time.Duration {
	if rs := h.runtimeSettings.get(); rs != nil && rs.AuditRetentionDays > 0 {
		return time.Duration(rs.AuditRetentionDays) * 24 * time.Hour
	}
	return h.cfg.AuditRetention
}

// --- Admin API: Settings ---

// handleGetSettings returns current runtime settings.
// GET /api/admin/settings
func (h *Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	rs := h.runtimeSettings.get()
	if rs == nil {
		rs = &store.RuntimeSettings{}
	}
	jsonResp(w, rs, http.StatusOK)
}

// handleUpdateSettings updates runtime settings.
// PUT /api/admin/settings
func (h *Handler) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var rs store.RuntimeSettings
	if err := readJSON(r, &rs); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.store.SaveRuntimeSettings(&rs); err != nil {
		jsonError(w, "failed to save settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.runtimeSettings.set(&rs)
	h.audit("settings_updated", "admin", getClientIP(r), nil)
	jsonResp(w, rs, http.StatusOK)
}
