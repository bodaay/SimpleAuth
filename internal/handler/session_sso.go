package handler

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	"simpleauth/internal/store"
)

// sessionCookieName is the name of the SSO session cookie.
// Cookie lives on the SimpleAuth host only (Path=h.cfg.BasePath or /),
// never scoped to a parent domain.
const sessionCookieName = "__sa_sso"

// issueSessionCookie creates a new SSO session in the store and sets the cookie.
// No-op when EnableSessionSSO is false.
// The caller should invoke this on successful login (hosted, SSO, OIDC flows).
func (h *Handler) issueSessionCookie(w http.ResponseWriter, r *http.Request, userGUID string) {
	if !h.getSessionSSOEnabled() {
		return
	}

	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		log.Printf("[sso-session] rand failed: %v", err)
		return
	}
	id := hex.EncodeToString(idBytes)

	now := time.Now().UTC()
	s := &store.Session{
		ID:         id,
		UserGUID:   userGUID,
		CreatedAt:  now,
		LastUsedAt: now,
		ExpiresAt:  now.Add(h.getSessionSSOMaxTTL()),
		UserAgent:  r.UserAgent(),
		IP:         getClientIP(r),
	}
	if err := h.store.CreateSession(s); err != nil {
		log.Printf("[sso-session] create failed user=%s err=%v", userGUID, err)
		return
	}

	// Idle TTL drives the cookie's browser-side lifetime; each resolve bumps it.
	idleTTL := h.getSessionSSOIdleTTL()
	secure := !h.cfg.TLSDisabled
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   int(idleTTL.Seconds()),
	})
	log.Printf("[sso-session] issued id=%s... user=%s ip=%s", id[:8], userGUID, s.IP)
}

// resolveSessionCookie looks up the session referenced by the cookie and
// returns the owning user GUID if the session is still valid (not past
// its absolute max, not past idle TTL). On every valid hit it bumps
// LastUsedAt. Returns "" on any failure (no cookie, expired, missing, disabled).
func (h *Handler) resolveSessionCookie(w http.ResponseWriter, r *http.Request) string {
	if !h.getSessionSSOEnabled() {
		return ""
	}

	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return ""
	}

	s, err := h.store.GetSession(c.Value)
	if err != nil || s == nil {
		h.clearSessionCookie(w)
		return ""
	}

	now := time.Now().UTC()

	// Absolute max hit
	if now.After(s.ExpiresAt) {
		h.store.DeleteSession(s.ID)
		h.clearSessionCookie(w)
		return ""
	}

	// Idle TTL hit
	if now.Sub(s.LastUsedAt) > h.getSessionSSOIdleTTL() {
		h.store.DeleteSession(s.ID)
		h.clearSessionCookie(w)
		return ""
	}

	// Verify user still exists and is not disabled
	user, err := h.store.ResolveUser(s.UserGUID)
	if err != nil || user == nil || user.Disabled {
		h.store.DeleteSession(s.ID)
		h.clearSessionCookie(w)
		return ""
	}

	// Verify user-level access isn't revoked (admin kill switch)
	if revoked, _ := h.store.IsUserAccessRevoked(user.GUID); revoked {
		h.store.DeleteSession(s.ID)
		h.clearSessionCookie(w)
		return ""
	}

	// Bump LastUsedAt and extend cookie
	h.store.TouchSession(s.ID, now)

	idleTTL := h.getSessionSSOIdleTTL()
	secure := !h.cfg.TLSDisabled
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
		MaxAge:   int(idleTTL.Seconds()),
	})

	return user.GUID
}

// clearSessionCookie removes the SSO session cookie from the browser.
// Also deletes the session row from the store if cookie is present.
func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   !h.cfg.TLSDisabled,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// deleteCurrentSession deletes the session row pointed at by the cookie,
// then clears the cookie. Used on explicit logout.
func (h *Handler) deleteCurrentSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		h.store.DeleteSession(c.Value)
	}
	h.clearSessionCookie(w)
}
