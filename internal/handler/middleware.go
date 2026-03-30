package handler

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func timingSafeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// --- Auth Middleware ---

type contextKey string

const (
	ctxIsAdmin contextKey = "is_admin"
)

func (h *Handler) requireMasterAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			jsonError(w, "missing authorization header", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		if !timingSafeEqual(token, h.cfg.AdminKey) {
			jsonError(w, "invalid admin key", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(setContext(r.Context(), ctxIsAdmin, "true"))
		next(w, r)
	}
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

// trustedCIDRs is set during handler initialization from config.TrustedProxyCIDRs.
// If empty, forwarded headers are trusted from any source (backwards compatible).
var trustedCIDRs []*net.IPNet

func getClientIP(r *http.Request) string {
	remoteIP := extractIP(r.RemoteAddr)

	// Only trust forwarded headers if the direct connection is from a trusted proxy
	if isTrustedProxy(remoteIP, trustedCIDRs) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			return strings.TrimSpace(parts[0])
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	return remoteIP
}

func extractIP(addr string) string {
	// Handle IPv6 addresses like [::1]:8080
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func isTrustedProxy(ip string, trustedCIDRs []*net.IPNet) bool {
	// If no trusted proxies configured, trust NONE — prevents X-Forwarded-For spoofing
	if len(trustedCIDRs) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range trustedCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}
