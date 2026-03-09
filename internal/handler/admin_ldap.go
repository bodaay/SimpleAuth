package handler

import (
	"fmt"
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
		LDAPProviders   []store.LDAPProvider `json:"ldap_providers"`
		ServiceHostname string               `json:"service_hostname"`
		SPN             string               `json:"spn"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	imported := 0
	var lastProviderID string
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
		lastProviderID = p.ProviderID
		imported++
	}

	resp := map[string]interface{}{
		"status":   "ok",
		"imported": imported,
	}

	// Auto-trigger Kerberos setup if the config includes SPN/service_hostname
	if req.ServiceHostname != "" && lastProviderID != "" {
		krbResult, krbErr := h.autoSetupKerberos(lastProviderID, req.ServiceHostname, r)
		if krbErr != nil {
			resp["kerberos_error"] = krbErr.Error()
		} else {
			resp["kerberos"] = krbResult
		}
	}

	jsonResp(w, resp, http.StatusOK)
}

func (h *Handler) handleAutoDiscoverLDAP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server   string `json:"server"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Server == "" || req.Username == "" || req.Password == "" {
		jsonError(w, "server, username, and password required", http.StatusBadRequest)
		return
	}

	// Normalize server URL
	serverURL := req.Server
	if !strings.Contains(serverURL, "://") {
		serverURL = "ldap://" + serverURL
	}
	// Add default port if missing
	afterScheme := serverURL[strings.Index(serverURL, "://")+3:]
	if !strings.Contains(afterScheme, ":") {
		if strings.HasPrefix(serverURL, "ldaps://") {
			serverURL += ":636"
		} else {
			serverURL += ":389"
		}
	}

	// Step 1: Connect
	conn, err := ldaplib.DialURL(serverURL)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to connect to %s: %v", serverURL, err), http.StatusBadGateway)
		return
	}
	defer conn.Close()

	// Step 2: Query RootDSE (anonymous) to get base DN and domain info
	sr, err := conn.Search(ldaplib.NewSearchRequest(
		"", ldaplib.ScopeBaseObject, ldaplib.NeverDerefAliases, 0, 10, false,
		"(objectClass=*)", []string{"defaultNamingContext", "rootDomainNamingContext", "dnsHostName"}, nil,
	))
	if err != nil {
		jsonError(w, fmt.Sprintf("RootDSE query failed: %v", err), http.StatusBadGateway)
		return
	}

	baseDN := ""
	if len(sr.Entries) > 0 {
		baseDN = sr.Entries[0].GetAttributeValue("defaultNamingContext")
	}

	// Derive domain from baseDN (DC=corp,DC=local -> corp.local)
	domain := ""
	if baseDN != "" {
		var domainParts []string
		for _, part := range strings.Split(baseDN, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToUpper(part), "DC=") {
				domainParts = append(domainParts, part[3:])
			}
		}
		domain = strings.Join(domainParts, ".")
	}

	// Build bind DN from username - support multiple formats
	bindDN := req.Username
	if !strings.Contains(bindDN, "=") && !strings.Contains(bindDN, "@") && !strings.Contains(bindDN, "\\") {
		// Plain username like "admin" - try UPN format first if we know the domain
		if domain != "" {
			bindDN = req.Username + "@" + domain
		}
	}

	// Step 3: Bind with credentials
	if err := conn.Bind(bindDN, req.Password); err != nil {
		jsonError(w, fmt.Sprintf("authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// If we still don't have baseDN, try RootDSE again after bind
	if baseDN == "" {
		sr2, err := conn.Search(ldaplib.NewSearchRequest(
			"", ldaplib.ScopeBaseObject, ldaplib.NeverDerefAliases, 0, 10, false,
			"(objectClass=*)", []string{"defaultNamingContext"}, nil,
		))
		if err == nil && len(sr2.Entries) > 0 {
			baseDN = sr2.Entries[0].GetAttributeValue("defaultNamingContext")
		}
	}

	if baseDN == "" {
		jsonError(w, "connected and authenticated, but could not determine base DN — use manual setup", http.StatusUnprocessableEntity)
		return
	}

	// Detect user filter: check if this is Active Directory or standard LDAP
	userFilter := "(uid={{username}})"
	// Try to detect AD by directly searching for any object with sAMAccountName
	adTest, _ := conn.Search(ldaplib.NewSearchRequest(
		baseDN, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases, 1, 5, false,
		"(&(objectClass=person)(sAMAccountName=*))", []string{"sAMAccountName"}, nil,
	))
	if adTest != nil && len(adTest.Entries) > 0 {
		userFilter = "(sAMAccountName={{username}})"
	}

	// Generate provider ID from domain or server
	providerID := "ldap"
	if domain != "" {
		providerID = strings.ReplaceAll(domain, ".", "-")
	} else {
		// Use server hostname
		host := afterScheme
		if idx := strings.Index(host, ":"); idx >= 0 {
			host = host[:idx]
		}
		providerID = strings.ReplaceAll(host, ".", "-")
	}

	providerName := serverURL + " (auto-discovered)"
	if domain != "" {
		providerName = domain + " (auto-discovered)"
	}

	provider := &store.LDAPProvider{
		ProviderID:      providerID,
		Name:            providerName,
		URL:             serverURL,
		BaseDN:          baseDN,
		BindDN:          bindDN,
		BindPassword:    req.Password,
		UserFilter:      userFilter,
		UseTLS:          strings.HasPrefix(serverURL, "ldaps://"),
		DisplayNameAttr: "displayName",
		EmailAttr:       "mail",
		DepartmentAttr:  "department",
		CompanyAttr:     "company",
		JobTitleAttr:    "title",
		GroupsAttr:      "memberOf",
	}

	if err := h.store.CreateLDAPProvider(provider); err != nil {
		jsonError(w, "auto-discover succeeded but save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.audit("ldap_provider_added", "admin", getClientIP(r), map[string]interface{}{
		"provider_id": provider.ProviderID, "auto_discovered": true,
	})

	jsonResp(w, provider, http.StatusOK)
}
