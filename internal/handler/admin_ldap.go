package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	ldaplib "github.com/go-ldap/ldap/v3"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// handleGetLDAPConfig returns the current LDAP configuration (or null if not configured).
// GET /api/admin/ldap
func (h *Handler) handleGetLDAPConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.getLDAPConfigDecrypted()
	if err != nil {
		jsonResp(w, nil, http.StatusOK)
		return
	}
	// Mask password in response
	resp := *cfg
	if resp.BindPassword != "" {
		resp.BindPassword = "••••••••"
	}
	jsonResp(w, resp, http.StatusOK)
}

// ldapTLSRequest carries the TLS settings an import or auto-discover request may
// set. A nil field was omitted from the request: the stored value is kept.
type ldapTLSRequest struct {
	SkipTLSVerify *bool   `json:"skip_tls_verify"`
	AllowInsecure *bool   `json:"allow_insecure"`
	CACert        *string `json:"ca_cert"`
}

// ldapTLSSettings is the TLS part of an LDAP config.
type ldapTLSSettings struct {
	SkipTLSVerify bool
	AllowInsecure bool
	CACert        string
}

// resolveLDAPTLS lays req over the TLS settings of the stored config, so an
// import or a new Connect that does not mention them keeps a pasted CA and the
// switches instead of resetting them. With nothing stored, omitted fields are
// off. A store error other than "not configured" is returned, not ignored.
func (h *Handler) resolveLDAPTLS(req ldapTLSRequest) (ldapTLSSettings, error) {
	var out ldapTLSSettings
	stored, err := h.store.GetLDAPConfig()
	switch {
	case err == nil:
		out = ldapTLSSettings{SkipTLSVerify: stored.SkipTLSVerify, AllowInsecure: stored.AllowInsecure, CACert: stored.CACert}
	case !errors.Is(err, store.ErrLDAPNotConfigured):
		return out, fmt.Errorf("read stored ldap config: %w", err)
	}
	if req.SkipTLSVerify != nil {
		out.SkipTLSVerify = *req.SkipTLSVerify
	}
	if req.AllowInsecure != nil {
		out.AllowInsecure = *req.AllowInsecure
	}
	if req.CACert != nil {
		out.CACert = *req.CACert
	}
	return out, nil
}

// validateLDAPCACert trims a ca_cert value and checks that it holds only
// parseable certificates. Empty means "no extra CA".
func validateLDAPCACert(caCert string) (string, error) {
	caCert = strings.TrimSpace(caCert)
	if caCert == "" {
		return "", nil
	}
	if _, err := auth.ParseLDAPCACert(caCert); err != nil {
		return "", fmt.Errorf("invalid ca_cert: %w", err)
	}
	return caCert, nil
}

// prepareLDAPConfig validates the TLS settings of a config about to be saved and
// sets use_tls from the URL scheme. Connections decide TLS from the scheme
// alone; use_tls is kept in the JSON only so readers see a consistent value.
func prepareLDAPConfig(cfg *store.LDAPConfig) error {
	caCert, err := validateLDAPCACert(cfg.CACert)
	if err != nil {
		return err
	}
	cfg.CACert = caCert
	cfg.UseTLS = auth.IsLDAPS(cfg.URL)
	return nil
}

// ldapAuditDetails adds the TLS switches to an audit entry. The CA certificate
// itself is not logged, only whether one is set.
func ldapAuditDetails(cfg *store.LDAPConfig, details map[string]interface{}) map[string]interface{} {
	details["url"] = cfg.URL
	details["ca_cert_set"] = cfg.CACert != ""
	details["skip_tls_verify"] = cfg.SkipTLSVerify
	details["allow_insecure"] = cfg.AllowInsecure
	return details
}

// handleSaveLDAPConfig saves the LDAP configuration. It is a full replace: a
// field left out of the body is stored as empty/false (the bind password is the
// exception, see below). TLS follows the URL scheme; use_tls is derived from it.
// PUT /api/admin/ldap
func (h *Handler) handleSaveLDAPConfig(w http.ResponseWriter, r *http.Request) {
	var cfg store.LDAPConfig
	if err := readJSON(r, &cfg); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if cfg.URL == "" || cfg.BaseDN == "" {
		jsonError(w, "url and base_dn are required", http.StatusBadRequest)
		return
	}
	if err := prepareLDAPConfig(&cfg); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If password is masked, preserve existing password
	if cfg.BindPassword == "••••••••" {
		existing, err := h.getLDAPConfigDecrypted()
		if err == nil {
			cfg.BindPassword = existing.BindPassword
		}
	}

	// Preserve configured_at if updating
	existing, err := h.getLDAPConfigDecrypted()
	if err == nil {
		cfg.ConfiguredAt = existing.ConfiguredAt
	}

	if err := h.saveLDAPConfigEncrypted(&cfg); err != nil {
		jsonError(w, "failed to save ldap config", http.StatusInternalServerError)
		return
	}

	h.audit("ldap_config_saved", "admin", getClientIP(r), ldapAuditDetails(&cfg, map[string]interface{}{}))

	jsonResp(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// handleDeleteLDAPConfig removes the LDAP configuration.
// DELETE /api/admin/ldap
func (h *Handler) handleDeleteLDAPConfig(w http.ResponseWriter, r *http.Request) {
	if err := h.store.DeleteLDAPConfig(); err != nil {
		jsonError(w, "failed to delete ldap config", http.StatusInternalServerError)
		return
	}
	h.audit("ldap_config_removed", "admin", getClientIP(r), nil)
	jsonResp(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

// handleTestLDAPConfig tests connection to the configured LDAP server.
// POST /api/admin/ldap/test
func (h *Handler) handleTestLDAPConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.getLDAPConfigDecrypted()
	if err != nil {
		jsonError(w, "ldap not configured", http.StatusNotFound)
		return
	}

	authCfg := ldapConfigFromStore(cfg)
	if err := auth.LDAPTestConnection(authCfg); err != nil {
		jsonResp(w, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}, http.StatusOK)
		return
	}
	jsonResp(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// handleTestLDAPUser searches for a user in LDAP and returns the mapped attributes.
// POST /api/admin/ldap/test-user
// Body: {"username": "alice"}
func (h *Handler) handleTestLDAPUser(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.getLDAPConfigDecrypted()
	if err != nil {
		jsonError(w, "ldap not configured", http.StatusNotFound)
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := readJSON(r, &req); err != nil || req.Username == "" {
		jsonError(w, "username required", http.StatusBadRequest)
		return
	}

	authCfg := ldapConfigFromStore(cfg)
	result, err := auth.LDAPSearchUser(authCfg, "sAMAccountName", req.Username)
	if err != nil {
		jsonResp(w, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}, http.StatusOK)
		return
	}

	jsonResp(w, map[string]interface{}{
		"status":       "ok",
		"display_name": result.DisplayName,
		"email":        result.Email,
		"department":   result.Department,
		"company":      result.Company,
		"job_title":    result.JobTitle,
		"groups":       result.Groups,
		"dn":           result.DN,
		"username":     result.Username,
	}, http.StatusOK)
}

// handleImportLDAP imports LDAP config from the PowerShell-generated JSON.
// skip_tls_verify, allow_insecure and ca_cert are optional; omitted ones keep
// their stored values.
// POST /api/admin/ldap/import
func (h *Handler) handleImportLDAP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server          string `json:"server"`
		Username        string `json:"username"`
		Password        string `json:"password"`
		Domain          string `json:"domain"`
		BaseDN          string `json:"base_dn"`
		ServiceHostname string `json:"service_hostname"`
		SPN             string `json:"spn"`
		ldapTLSRequest
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Server == "" || req.Username == "" || req.Password == "" {
		jsonError(w, "server, username, and password required", http.StatusBadRequest)
		return
	}

	tlsSettings, err := h.resolveLDAPTLS(req.ldapTLSRequest)
	if err != nil {
		log.Printf("[admin] LDAP import: %v", err)
		jsonError(w, "failed to read the stored ldap config", http.StatusInternalServerError)
		return
	}

	// Normalize server URL
	serverURL := req.Server
	if !strings.Contains(serverURL, "://") {
		serverURL = "ldap://" + serverURL
	}
	afterScheme := serverURL[strings.Index(serverURL, "://")+3:]
	if !strings.Contains(afterScheme, ":") {
		if strings.HasPrefix(serverURL, "ldaps://") {
			serverURL += ":636"
		} else {
			serverURL += ":389"
		}
	}

	// Build bind DN
	bindDN := req.Username
	if !strings.Contains(bindDN, "=") && !strings.Contains(bindDN, "@") && !strings.Contains(bindDN, "\\") {
		if req.Domain != "" {
			bindDN = req.Username + "@" + req.Domain
		}
	}

	// Derive base DN from domain if not provided
	baseDN := req.BaseDN
	if baseDN == "" && req.Domain != "" {
		var parts []string
		for _, p := range strings.Split(req.Domain, ".") {
			parts = append(parts, "DC="+p)
		}
		baseDN = strings.Join(parts, ",")
	}

	cfg := &store.LDAPConfig{
		URL:             serverURL,
		BaseDN:          baseDN,
		BindDN:          bindDN,
		BindPassword:    req.Password,
		UsernameAttr:    "sAMAccountName",
		SkipTLSVerify:   tlsSettings.SkipTLSVerify,
		AllowInsecure:   tlsSettings.AllowInsecure,
		CACert:          tlsSettings.CACert,
		DisplayNameAttr: "displayName",
		EmailAttr:       "mail",
		DepartmentAttr:  "department",
		CompanyAttr:     "company",
		JobTitleAttr:    "title",
		GroupsAttr:      "memberOf",
		Domain:          req.Domain,
	}
	if err := prepareLDAPConfig(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.saveLDAPConfigEncrypted(cfg); err != nil {
		log.Printf("[admin] Failed to save LDAP config: %v", err)
		jsonError(w, "failed to save ldap config", http.StatusInternalServerError)
		return
	}

	h.audit("ldap_config_imported", "admin", getClientIP(r), ldapAuditDetails(cfg, map[string]interface{}{}))

	resp := map[string]interface{}{
		"status": "ok",
	}

	// Auto-trigger Kerberos setup if service_hostname provided
	if req.ServiceHostname != "" {
		krbResult, krbErr := h.autoSetupKerberos(req.ServiceHostname, r)
		if krbErr != nil {
			resp["kerberos_error"] = krbErr.Error()
		} else {
			resp["kerberos"] = krbResult
		}
	}

	jsonResp(w, resp, http.StatusOK)
}

// handleAutoDiscoverLDAP connects to a server, discovers config, and saves it.
// skip_tls_verify, allow_insecure and ca_cert are optional; omitted ones keep
// their stored values, and the connection already uses them.
// POST /api/admin/ldap/auto-discover
func (h *Handler) handleAutoDiscoverLDAP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server   string `json:"server"`
		Username string `json:"username"`
		Password string `json:"password"`
		ldapTLSRequest
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Server == "" || req.Username == "" || req.Password == "" {
		jsonError(w, "server, username, and password required", http.StatusBadRequest)
		return
	}

	tlsSettings, err := h.resolveLDAPTLS(req.ldapTLSRequest)
	if err != nil {
		log.Printf("[admin] LDAP auto-discover: %v", err)
		jsonError(w, "failed to read the stored ldap config", http.StatusInternalServerError)
		return
	}
	if tlsSettings.CACert, err = validateLDAPCACert(tlsSettings.CACert); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Normalize server URL
	serverURL := req.Server
	if !strings.Contains(serverURL, "://") {
		serverURL = "ldap://" + serverURL
	}
	afterScheme := serverURL[strings.Index(serverURL, "://")+3:]
	if !strings.Contains(afterScheme, ":") {
		if strings.HasPrefix(serverURL, "ldaps://") {
			serverURL += ":636"
		} else {
			serverURL += ":389"
		}
	}

	// Step 1: Connect with the same TLS settings the saved config will have
	// (ldaps://, or ldap:// upgraded with StartTLS; ca_cert, skip_tls_verify,
	// allow_insecure), so the service-account password is never sent in
	// cleartext during discovery unless the config allows it for every login.
	conn, err := auth.LDAPConnect(&auth.LDAPConfig{
		URL:           serverURL,
		SkipTLSVerify: tlsSettings.SkipTLSVerify,
		AllowInsecure: tlsSettings.AllowInsecure,
		CACert:        tlsSettings.CACert,
	})
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to connect to %s: %v", serverURL, err), http.StatusBadGateway)
		return
	}
	defer conn.Close()

	// Step 2: Query RootDSE to get base DN
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

	// Derive domain from baseDN
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

	// Build bind DN
	bindDN := req.Username
	if !strings.Contains(bindDN, "=") && !strings.Contains(bindDN, "@") && !strings.Contains(bindDN, "\\") {
		if domain != "" {
			bindDN = req.Username + "@" + domain
		}
	}

	// Step 3: Bind with credentials
	if err := conn.Bind(bindDN, req.Password); err != nil {
		jsonError(w, fmt.Sprintf("authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// If we still don't have baseDN, try again after bind
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
		jsonError(w, "connected but could not determine base DN — use manual setup", http.StatusUnprocessableEntity)
		return
	}

	// Detect username attribute
	usernameAttr := "uid"
	adTest, _ := conn.Search(ldaplib.NewSearchRequest(
		baseDN, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases, 1, 5, false,
		"(&(objectClass=person)(sAMAccountName=*))", []string{"sAMAccountName"}, nil,
	))
	if adTest != nil && len(adTest.Entries) > 0 {
		usernameAttr = "sAMAccountName"
	}

	cfg := &store.LDAPConfig{
		URL:             serverURL,
		BaseDN:          baseDN,
		BindDN:          bindDN,
		BindPassword:    req.Password,
		UsernameAttr:    usernameAttr,
		SkipTLSVerify:   tlsSettings.SkipTLSVerify,
		AllowInsecure:   tlsSettings.AllowInsecure,
		CACert:          tlsSettings.CACert,
		DisplayNameAttr: "displayName",
		EmailAttr:       "mail",
		DepartmentAttr:  "department",
		CompanyAttr:     "company",
		JobTitleAttr:    "title",
		GroupsAttr:      "memberOf",
		Domain:          domain,
	}
	if err := prepareLDAPConfig(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.saveLDAPConfigEncrypted(cfg); err != nil {
		log.Printf("[admin] Auto-discover save failed: %v", err)
		jsonError(w, "auto-discover succeeded but save failed", http.StatusInternalServerError)
		return
	}

	h.audit("ldap_config_saved", "admin", getClientIP(r), ldapAuditDetails(cfg, map[string]interface{}{
		"auto_discovered": true,
	}))

	// Mask password in response
	resp := *cfg
	resp.BindPassword = "••••••••"
	jsonResp(w, resp, http.StatusOK)
}

// handleSearchLDAPUsers searches the LDAP directory and returns matching users.
// POST /api/admin/ldap/search-users
// Body: {"query": "john", "limit": 50}
func (h *Handler) handleSearchLDAPUsers(w http.ResponseWriter, r *http.Request) {
	p, err := h.getLDAPConfigDecrypted()
	if err != nil {
		jsonError(w, "ldap not configured", http.StatusNotFound)
		return
	}

	var req struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := readJSON(r, &req); err != nil || req.Query == "" {
		jsonError(w, "query required", http.StatusBadRequest)
		return
	}

	cfg := ldapConfigFromStore(p)
	results, err := auth.LDAPSearchUsers(cfg, req.Query, req.Limit)
	if err != nil {
		jsonError(w, fmt.Sprintf("LDAP search failed: %v", err), http.StatusBadGateway)
		return
	}

	// Check which users are already imported
	type searchResult struct {
		Username    string   `json:"username"`
		DisplayName string   `json:"display_name"`
		Email       string   `json:"email"`
		Department  string   `json:"department"`
		Company     string   `json:"company"`
		JobTitle    string   `json:"job_title"`
		Groups      []string `json:"groups"`
		DN          string   `json:"dn"`
		Imported    bool     `json:"imported"`
		UserGUID    string   `json:"user_guid,omitempty"`
	}

	out := make([]searchResult, 0, len(results))
	for _, r := range results {
		sr := searchResult{
			Username:    r.Username,
			DisplayName: r.DisplayName,
			Email:       r.Email,
			Department:  r.Department,
			Company:     r.Company,
			JobTitle:    r.JobTitle,
			Groups:      r.Groups,
			DN:          r.DN,
		}
		// Check if already mapped
		if guid, err := h.store.ResolveMapping("ldap", r.Username); err == nil {
			sr.Imported = true
			sr.UserGUID = guid
		}
		out = append(out, sr)
	}

	jsonResp(w, out, http.StatusOK)
}

// handleImportLDAPUsers imports one or more LDAP users into SimpleAuth.
// POST /api/admin/ldap/import-users
// Body: {"usernames": ["alice", "bob"]}
func (h *Handler) handleImportLDAPUsers(w http.ResponseWriter, r *http.Request) {
	p, err := h.getLDAPConfigDecrypted()
	if err != nil {
		jsonError(w, "ldap not configured", http.StatusNotFound)
		return
	}

	var req struct {
		Usernames []string `json:"usernames"`
	}
	if err := readJSON(r, &req); err != nil || len(req.Usernames) == 0 {
		jsonError(w, "usernames required", http.StatusBadRequest)
		return
	}

	cfg := ldapConfigFromStore(p)
	usernameAttr := cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}

	type importResult struct {
		Username string `json:"username"`
		Status   string `json:"status"`
		UserGUID string `json:"user_guid,omitempty"`
		Error    string `json:"error,omitempty"`
	}

	results := make([]importResult, 0, len(req.Usernames))

	for _, username := range req.Usernames {
		// Check if already imported
		if guid, err := h.store.ResolveMapping("ldap", username); err == nil {
			results = append(results, importResult{Username: username, Status: "exists", UserGUID: guid})
			continue
		}

		// Look up user in LDAP
		ldapUser, err := auth.LDAPSearchUser(cfg, usernameAttr, username)
		if err != nil {
			results = append(results, importResult{Username: username, Status: "error", Error: err.Error()})
			continue
		}

		// Create SimpleAuth user
		user := &store.User{
			DisplayName: ldapUser.DisplayName,
			Email:       ldapUser.Email,
			Department:  ldapUser.Department,
			Company:     ldapUser.Company,
			JobTitle:    ldapUser.JobTitle,
		}
		if err := h.store.CreateUser(user); err != nil {
			results = append(results, importResult{Username: username, Status: "error", Error: "failed to create user"})
			continue
		}

		// Create LDAP identity mapping
		h.store.SetIdentityMapping("ldap", username, user.GUID)

		h.audit("ldap_user_imported", user.GUID, getClientIP(r), map[string]interface{}{
			"username": username, "display_name": ldapUser.DisplayName,
		})

		results = append(results, importResult{Username: username, Status: "imported", UserGUID: user.GUID})
	}

	jsonResp(w, results, http.StatusOK)
}
