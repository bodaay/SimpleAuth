package handler

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// --- Auth Middleware ---

type contextKey string

const (
	ctxAppID   contextKey = "app_id"
	ctxIsAdmin contextKey = "is_admin"
)

func (h *Handler) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			jsonError(w, "missing authorization header", http.StatusUnauthorized)
			return
		}
		key := strings.TrimPrefix(auth, "Bearer ")

		// Check master admin key
		if key == h.cfg.AdminKey {
			r = r.WithContext(setContext(r.Context(), ctxIsAdmin, "true"))
			r = r.WithContext(setContext(r.Context(), ctxAppID, ""))
			next(w, r)
			return
		}

		// Check app API key
		app, err := h.store.GetAppByAPIKey(key)
		if err != nil {
			jsonError(w, "invalid api key", http.StatusUnauthorized)
			return
		}
		r = r.WithContext(setContext(r.Context(), ctxAppID, app.AppID))
		r = r.WithContext(setContext(r.Context(), ctxIsAdmin, "false"))
		next(w, r)
	}
}

func (h *Handler) requireMasterAdmin(next http.HandlerFunc) http.HandlerFunc {
	return h.adminAuth(func(w http.ResponseWriter, r *http.Request) {
		if getContext(r.Context(), ctxIsAdmin) != "true" {
			jsonError(w, "master admin key required", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// --- Rate Limiter ---

type rateLimiter struct {
	mu       sync.Mutex
	counters map[string]*ipCounter
	limit    int
	window   time.Duration
}

type ipCounter struct {
	count    int
	resetAt  time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		counters: make(map[string]*ipCounter),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	c, ok := rl.counters[ip]
	if !ok || now.After(c.resetAt) {
		rl.counters[ip] = &ipCounter{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	c.count++
	return c.count <= rl.limit
}

func (rl *rateLimiter) retryAfter(ip string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	c, ok := rl.counters[ip]
	if !ok {
		return 0
	}
	remaining := time.Until(c.resetAt).Seconds()
	if remaining < 0 {
		return 0
	}
	return int(remaining) + 1
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, c := range rl.counters {
			if now.After(c.resetAt) {
				delete(rl.counters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Strip port
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		return addr[:idx]
	}
	return addr
}
