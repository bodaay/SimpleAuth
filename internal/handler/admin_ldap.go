package handler

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	ldaplib "github.com/go-ldap/ldap/v3"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

func (h *Handler) handleListLDAP(w http.ResponseWriter, r *http.Request) {
	providers, err := h.store.ListLDAPProviders()
	if err != nil {
		jsonError(w, "failed to list ldap providers", http.StatusInternalServerError)
		return
	}
	if providers == nil {
		providers = []*store.LDAPProvider{}
	}
	jsonResp(w, providers, http.StatusOK)
}

func (h *Handler) handleCreateLDAP(w http.ResponseWriter, r *http.Request) {
	var p store.LDAPProvider
	if err := readJSON(r, &p); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if p.ProviderID == "" {
		jsonError(w, "provider_id required", http.StatusBadRequest)
		return
	}
	if err := h.store.CreateLDAPProvider(&p); err != nil {
		jsonError(w, "failed to create ldap provider", http.StatusInternalServerError)
		return
	}

	h.audit("ldap_provider_added", "admin", getClientIP(r), map[string]interface{}{"provider_id": p.ProviderID})

	jsonResp(w, p, http.StatusCreated)
}

func (h *Handler) handleGetLDAP(w http.ResponseWriter, r *http.Request) {
	providerID := pathParam(r, "provider_id")
	p, err := h.store.GetLDAPProvider(providerID)
	if err != nil {
		jsonError(w, "ldap provider not found", http.StatusNotFound)
		return
	}
	jsonResp(w, p, http.StatusOK)
}

func (h *Handler) handleUpdateLDAP(w http.ResponseWriter, r *http.Request) {
	providerID := pathParam(r, "provider_id")
	existing, err := h.store.GetLDAPProvider(providerID)
	if err != nil {
		jsonError(w, "ldap provider not found", http.StatusNotFound)
		return
	}

	var p store.LDAPProvider
	if err := readJSON(r, &p); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	p.ProviderID = providerID
	p.CreatedAt = existing.CreatedAt

	if err := h.store.UpdateLDAPProvider(&p); err != nil {
		jsonError(w, "failed to update ldap provider", http.StatusInternalServerError)
		return
	}
	jsonResp(w, p, http.StatusOK)
}

func (h *Handler) handleDeleteLDAP(w http.ResponseWriter, r *http.Request) {
	providerID := pathParam(r, "provider_id")
	if err := h.store.DeleteLDAPProvider(providerID); err != nil {
		jsonError(w, "failed to delete ldap provider", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

func (h *Handler) handleTestLDAP(w http.ResponseWriter, r *http.Request) {
	providerID := pathParam(r, "provider_id")
	p, err := h.store.GetLDAPProvider(providerID)
	if err != nil {
		jsonError(w, "ldap provider not found", http.StatusNotFound)
		return
	}

	cfg := ldapConfigFromProvider(p)
	if err := auth.LDAPTestConnection(cfg); err != nil {
		jsonResp(w, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}, http.StatusOK)
		return
	}
	jsonResp(w, map[string]string{"status": "ok"}, http.StatusOK)
}

func (h *Handler) handleExportLDAP(w http.ResponseWriter, r *http.Request) {
	providers, err := h.store.ListLDAPProviders()
	if err != nil {
		jsonError(w, "failed to export", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]interface{}{"ldap_providers": providers}, http.StatusOK)
}

func (h *Handler) handleImportLDAP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LDAPProviders []store.LDAPProvider `json:"ldap_providers"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	imported := 0
	for _, p := range req.LDAPProviders {
		if p.ProviderID == "" {
			continue
		}
		// Upsert
		existing, err := h.store.GetLDAPProvider(p.ProviderID)
		if err != nil {
			h.store.CreateLDAPProvider(&p)
		} else {
			p.CreatedAt = existing.CreatedAt
			h.store.UpdateLDAPProvider(&p)
		}
		imported++
	}

	jsonResp(w, map[string]interface{}{
		"status":   "ok",
		"imported": imported,
	}, http.StatusOK)
}

func (h *Handler) handleAutoDiscoverLDAP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain       string `json:"domain"`
		BindDN       string `json:"bind_dn"`
		BindPassword string `json:"bind_password"`
		ProviderID   string `json:"provider_id"`
		Save         bool   `json:"save"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Domain == "" || req.BindDN == "" || req.BindPassword == "" {
		jsonError(w, "domain, bind_dn, and bind_password required", http.StatusBadRequest)
		return
	}

	if req.ProviderID == "" {
		req.ProviderID = strings.ReplaceAll(req.Domain, ".", "-")
	}

	// Step 1: DNS SRV lookup
	_, addrs, err := net.LookupSRV("ldap", "tcp", req.Domain)
	if err != nil || len(addrs) == 0 {
		jsonError(w, fmt.Sprintf("DNS SRV lookup failed for _ldap._tcp.%s: %v", req.Domain, err), http.StatusBadRequest)
		return
	}

	var discoveredDCs []string
	for _, a := range addrs {
		host := strings.TrimSuffix(a.Target, ".")
		discoveredDCs = append(discoveredDCs, fmt.Sprintf("%s:%d", host, a.Port))
	}

	// Step 2: Connect to the first reachable DC
	var conn *ldaplib.Conn
	var connURL string
	for _, dc := range discoveredDCs {
		url := fmt.Sprintf("ldap://%s", dc)
		c, err := ldaplib.DialURL(url)
		if err == nil {
			conn = c
			connURL = url
			break
		}
	}
	if conn == nil {
		jsonError(w, "could not connect to any discovered DC", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	// Step 3: Query RootDSE
	sr, err := conn.Search(ldaplib.NewSearchRequest(
		"", ldaplib.ScopeBaseObject, ldaplib.NeverDerefAliases, 0, 10, false,
		"(objectClass=*)", []string{"defaultNamingContext", "rootDomainNamingContext"}, nil,
	))
	if err != nil {
		jsonError(w, fmt.Sprintf("RootDSE query failed: %v", err), http.StatusBadGateway)
		return
	}

	baseDN := ""
	if len(sr.Entries) > 0 {
		baseDN = sr.Entries[0].GetAttributeValue("defaultNamingContext")
	}
	if baseDN == "" {
		// Derive from domain
		parts := strings.Split(req.Domain, ".")
		for i, p := range parts {
			if i > 0 {
				baseDN += ","
			}
			baseDN += "DC=" + p
		}
	}

	// Step 4: Test bind
	if err := conn.Bind(req.BindDN, req.BindPassword); err != nil {
		jsonError(w, fmt.Sprintf("bind test failed: %v", err), http.StatusBadRequest)
		return
	}

	provider := &store.LDAPProvider{
		ProviderID:      req.ProviderID,
		Name:            req.Domain + " (auto-discovered)",
		URL:             connURL,
		BaseDN:          baseDN,
		BindDN:          req.BindDN,
		BindPassword:    req.BindPassword,
		UserFilter:      "(sAMAccountName={{username}})",
		UseTLS:          false,
		DisplayNameAttr: "displayName",
		EmailAttr:       "mail",
		GroupsAttr:      "memberOf",
	}

	if req.Save {
		if err := h.store.CreateLDAPProvider(provider); err != nil {
			jsonError(w, "auto-discover succeeded but save failed", http.StatusInternalServerError)
			return
		}
		h.audit("ldap_provider_added", "admin", getClientIP(r), map[string]interface{}{
			"provider_id": provider.ProviderID, "auto_discovered": true,
		})
	}

	type response struct {
		*store.LDAPProvider
		DiscoveredDCs []string `json:"discovered_dcs"`
		Saved         bool     `json:"saved"`
	}
	jsonResp(w, response{
		LDAPProvider:  provider,
		DiscoveredDCs: discoveredDCs,
		Saved:         req.Save,
	}, http.StatusOK)
}
