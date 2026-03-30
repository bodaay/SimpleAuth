package handler

import (
	"simpleauth/internal/store"
)

// getLDAPConfigDecrypted reads LDAP config (no encryption, kept for API compat).
func (h *Handler) getLDAPConfigDecrypted() (*store.LDAPConfig, error) {
	return h.store.GetLDAPConfig()
}

// saveLDAPConfigEncrypted saves LDAP config (no encryption, kept for API compat).
func (h *Handler) saveLDAPConfigEncrypted(cfg *store.LDAPConfig) error {
	return h.store.SaveLDAPConfig(cfg)
}
