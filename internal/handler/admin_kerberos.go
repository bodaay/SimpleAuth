package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	ldaplib "github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

// KerberosConfig is stored in BoltDB config bucket as JSON under key "kerberos:config".
type KerberosConfig struct {
	Realm           string `json:"realm"`
	KeytabPath      string `json:"keytab_path"`
	ProviderID      string `json:"provider_id"`
	ServiceHostname string `json:"service_hostname"`
	SPN             string `json:"spn"`
	BindAccountDN   string `json:"bind_account_dn"`
	SAMAccountName  string `json:"sam_account_name"`
	SetupAt         string `json:"setup_at"`
}

func (h *Handler) getKerberosConfig() (*KerberosConfig, error) {
	data, err := h.store.GetConfigValue("kerberos:config")
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var cfg KerberosConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (h *Handler) saveKerberosConfig(cfg *KerberosConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return h.store.SetConfigValue("kerberos:config", data)
}

// handleKerberosStatus returns the current Kerberos configuration status.
func (h *Handler) handleKerberosStatus(w http.ResponseWriter, r *http.Request) {
	krbCfg, _ := h.getKerberosConfig()

	status := map[string]interface{}{
		"configured": false,
	}

	// Check env-based config
	if h.cfg.KRB5Keytab != "" {
		status["configured"] = true
		status["source"] = "env"
		status["realm"] = h.cfg.KRB5Realm
		status["keytab_path"] = h.cfg.KRB5Keytab
	}

	// Check DB-based config (overrides env display)
	if krbCfg != nil {
		status["configured"] = true
		status["source"] = "auto"
		status["realm"] = krbCfg.Realm
		status["spn"] = krbCfg.SPN
		status["service_hostname"] = krbCfg.ServiceHostname
		status["provider_id"] = krbCfg.ProviderID
		status["setup_at"] = krbCfg.SetupAt
	}

	jsonResp(w, status, http.StatusOK)
}

// handleSetupKerberos configures Kerberos/SPNEGO for an LDAP provider.
// POST /api/admin/ldap/{provider_id}/setup-kerberos
// Body: {"service_hostname": "simpleauth.corp.local"}
func (h *Handler) handleSetupKerberos(w http.ResponseWriter, r *http.Request) {
	providerID := pathParam(r, "provider_id")
	p, err := h.store.GetLDAPProvider(providerID)
	if err != nil {
		jsonError(w, "ldap provider not found", http.StatusNotFound)
		return
	}

	var req struct {
		ServiceHostname string `json:"service_hostname"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ServiceHostname == "" {
		jsonError(w, "service_hostname required", http.StatusBadRequest)
		return
	}

	// Derive realm from base DN
	realm := realmFromBaseDN(p.BaseDN)
	if realm == "" {
		jsonError(w, "cannot derive realm from base DN: "+p.BaseDN, http.StatusBadRequest)
		return
	}

	spn := "HTTP/" + req.ServiceHostname

	// Connect to LDAP
	conn, err := ldaplib.DialURL(p.URL)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to connect to LDAP: %v", err), http.StatusBadGateway)
		return
	}
	defer conn.Close()

	if err := conn.Bind(p.BindDN, p.BindPassword); err != nil {
		jsonError(w, fmt.Sprintf("LDAP bind failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Find the bind account's sAMAccountName
	samAccountName, err := lookupSAMAccountName(conn, p.BindDN, p.BaseDN)
	if err != nil {
		jsonError(w, fmt.Sprintf("could not find sAMAccountName for bind account: %v", err), http.StatusBadRequest)
		return
	}

	// Try to register SPN on the bind account
	spnWarning := ""
	err = registerSPN(conn, p.BindDN, spn)
	if err != nil {
		spnWarning = fmt.Sprintf("could not auto-register SPN (run manually: setspn -A %s %s): %v", spn, samAccountName, err)
	}

	// Generate keytab
	kt := keytab.New()

	// Add entries using sAMAccountName for correct AD salt derivation,
	// then patch the principal to be the SPN.
	for _, encType := range []int32{18, 17, 23} { // AES256, AES128, RC4-HMAC
		if err := kt.AddEntry(samAccountName, realm, p.BindPassword, time.Now(), 0, encType); err != nil {
			continue
		}
		// Patch the last entry's principal to be the SPN
		idx := len(kt.Entries) - 1
		kt.Entries[idx].Principal.Components = []string{"HTTP", req.ServiceHostname}
		kt.Entries[idx].Principal.NumComponents = 2
		kt.Entries[idx].Principal.NameType = 1
	}

	if len(kt.Entries) == 0 {
		jsonError(w, "failed to generate any keytab entries", http.StatusInternalServerError)
		return
	}

	// Marshal and save keytab
	ktBytes, err := kt.Marshal()
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to marshal keytab: %v", err), http.StatusInternalServerError)
		return
	}

	keytabPath := filepath.Join(h.cfg.DataDir, "krb5.keytab")
	if err := os.WriteFile(keytabPath, ktBytes, 0600); err != nil {
		jsonError(w, fmt.Sprintf("failed to write keytab: %v", err), http.StatusInternalServerError)
		return
	}

	// Save config to DB
	krbCfg := &KerberosConfig{
		Realm:           realm,
		KeytabPath:      keytabPath,
		ProviderID:      providerID,
		ServiceHostname: req.ServiceHostname,
		SPN:             spn,
		BindAccountDN:   p.BindDN,
		SAMAccountName:  samAccountName,
		SetupAt:         time.Now().UTC().Format(time.RFC3339),
	}
	if err := h.saveKerberosConfig(krbCfg); err != nil {
		jsonError(w, "keytab generated but failed to save config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.audit("kerberos_setup", "admin", getClientIP(r), map[string]interface{}{
		"provider_id": providerID, "spn": spn, "realm": realm,
	})

	resp := map[string]interface{}{
		"status":       "ok",
		"realm":        realm,
		"spn":          spn,
		"keytab_path":  keytabPath,
		"keytab_types": len(kt.Entries),
	}
	if spnWarning != "" {
		resp["spn_warning"] = spnWarning
	}
	jsonResp(w, resp, http.StatusOK)
}

// handleCleanupKerberos removes Kerberos config and optionally revokes SPN from AD.
// POST /api/admin/ldap/{provider_id}/cleanup-kerberos
// Body: {"username": "admin@corp.local", "password": "..."} (optional, for AD SPN removal)
func (h *Handler) handleCleanupKerberos(w http.ResponseWriter, r *http.Request) {
	providerID := pathParam(r, "provider_id")
	p, err := h.store.GetLDAPProvider(providerID)
	if err != nil {
		jsonError(w, "ldap provider not found", http.StatusNotFound)
		return
	}

	krbCfg, _ := h.getKerberosConfig()
	if krbCfg == nil || krbCfg.ProviderID != providerID {
		jsonError(w, "no kerberos config found for this provider", http.StatusNotFound)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	// Body is optional
	readJSON(r, &req)

	adCleanup := ""

	// Try to remove SPN from AD
	if req.Username != "" && req.Password != "" {
		conn, err := ldaplib.DialURL(p.URL)
		if err == nil {
			defer conn.Close()
			if err := conn.Bind(req.Username, req.Password); err == nil {
				err = unregisterSPN(conn, krbCfg.BindAccountDN, krbCfg.SPN)
				if err != nil {
					adCleanup = fmt.Sprintf("SPN removal failed: %v", err)
				} else {
					adCleanup = "SPN removed from AD"
				}
			} else {
				adCleanup = fmt.Sprintf("AD bind failed: %v", err)
			}
		} else {
			adCleanup = fmt.Sprintf("could not connect to AD: %v", err)
		}
	}

	// Delete keytab file
	if krbCfg.KeytabPath != "" {
		os.Remove(krbCfg.KeytabPath)
	}

	// Clear config from DB
	h.store.DeleteConfigValue("kerberos:config")

	h.audit("kerberos_cleanup", "admin", getClientIP(r), map[string]interface{}{
		"provider_id": providerID, "spn": krbCfg.SPN, "ad_cleanup": adCleanup,
	})

	resp := map[string]interface{}{
		"status": "ok",
	}
	if adCleanup != "" {
		resp["ad_cleanup"] = adCleanup
	}
	jsonResp(w, resp, http.StatusOK)
}

// --- Helpers ---

// realmFromBaseDN extracts a Kerberos realm from a base DN.
// DC=corp,DC=local -> CORP.LOCAL
func realmFromBaseDN(baseDN string) string {
	var parts []string
	for _, seg := range strings.Split(baseDN, ",") {
		seg = strings.TrimSpace(seg)
		if strings.HasPrefix(strings.ToUpper(seg), "DC=") {
			parts = append(parts, seg[3:])
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.ToUpper(strings.Join(parts, "."))
}

// lookupSAMAccountName finds the sAMAccountName for a given DN.
func lookupSAMAccountName(conn *ldaplib.Conn, bindDN, baseDN string) (string, error) {
	// First try a direct read of the bind DN
	sr, err := conn.Search(ldaplib.NewSearchRequest(
		bindDN, ldaplib.ScopeBaseObject, ldaplib.NeverDerefAliases, 1, 5, false,
		"(objectClass=*)", []string{"sAMAccountName"}, nil,
	))
	if err == nil && len(sr.Entries) > 0 {
		sam := sr.Entries[0].GetAttributeValue("sAMAccountName")
		if sam != "" {
			return sam, nil
		}
	}

	// If bind DN is a UPN (user@domain), search by userPrincipalName
	if strings.Contains(bindDN, "@") {
		sr, err = conn.Search(ldaplib.NewSearchRequest(
			baseDN, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases, 1, 5, false,
			fmt.Sprintf("(userPrincipalName=%s)", ldaplib.EscapeFilter(bindDN)),
			[]string{"sAMAccountName"}, nil,
		))
		if err == nil && len(sr.Entries) > 0 {
			sam := sr.Entries[0].GetAttributeValue("sAMAccountName")
			if sam != "" {
				return sam, nil
			}
		}
	}

	// If bind DN is DOMAIN\user format, extract the username part
	if strings.Contains(bindDN, "\\") {
		parts := strings.SplitN(bindDN, "\\", 2)
		return parts[1], nil
	}

	return "", fmt.Errorf("could not determine sAMAccountName from bind DN: %s", bindDN)
}

// registerSPN adds an SPN to the service account in AD.
func registerSPN(conn *ldaplib.Conn, accountDN, spn string) error {
	modify := ldaplib.NewModifyRequest(accountDN, nil)
	modify.Add("servicePrincipalName", []string{spn})
	return conn.Modify(modify)
}

// unregisterSPN removes an SPN from the service account in AD.
func unregisterSPN(conn *ldaplib.Conn, accountDN, spn string) error {
	modify := ldaplib.NewModifyRequest(accountDN, nil)
	modify.Delete("servicePrincipalName", []string{spn})
	return conn.Modify(modify)
}

// autoSetupKerberos generates a keytab for an LDAP provider (called during import).
func (h *Handler) autoSetupKerberos(providerID, serviceHostname string, r *http.Request) (map[string]interface{}, error) {
	p, err := h.store.GetLDAPProvider(providerID)
	if err != nil {
		return nil, fmt.Errorf("provider not found: %v", err)
	}

	realm := realmFromBaseDN(p.BaseDN)
	if realm == "" {
		return nil, fmt.Errorf("cannot derive realm from base DN: %s", p.BaseDN)
	}

	spn := "HTTP/" + serviceHostname

	conn, err := ldaplib.DialURL(p.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %v", err)
	}
	defer conn.Close()

	if err := conn.Bind(p.BindDN, p.BindPassword); err != nil {
		return nil, fmt.Errorf("LDAP bind failed: %v", err)
	}

	samAccountName, err := lookupSAMAccountName(conn, p.BindDN, p.BaseDN)
	if err != nil {
		return nil, fmt.Errorf("could not find sAMAccountName: %v", err)
	}

	kt := keytab.New()
	for _, encType := range []int32{18, 17, 23} {
		if err := kt.AddEntry(samAccountName, realm, p.BindPassword, time.Now(), 0, encType); err != nil {
			continue
		}
		idx := len(kt.Entries) - 1
		kt.Entries[idx].Principal.Components = []string{"HTTP", serviceHostname}
		kt.Entries[idx].Principal.NumComponents = 2
		kt.Entries[idx].Principal.NameType = 1
	}

	if len(kt.Entries) == 0 {
		return nil, fmt.Errorf("failed to generate keytab entries")
	}

	ktBytes, err := kt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal keytab: %v", err)
	}

	keytabPath := filepath.Join(h.cfg.DataDir, "krb5.keytab")
	if err := os.WriteFile(keytabPath, ktBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write keytab: %v", err)
	}

	krbCfg := &KerberosConfig{
		Realm:           realm,
		KeytabPath:      keytabPath,
		ProviderID:      providerID,
		ServiceHostname: serviceHostname,
		SPN:             spn,
		BindAccountDN:   p.BindDN,
		SAMAccountName:  samAccountName,
		SetupAt:         time.Now().UTC().Format(time.RFC3339),
	}
	if err := h.saveKerberosConfig(krbCfg); err != nil {
		return nil, fmt.Errorf("keytab generated but failed to save config: %v", err)
	}

	h.audit("kerberos_setup", "admin", getClientIP(r), map[string]interface{}{
		"provider_id": providerID, "spn": spn, "realm": realm, "auto": true,
	})

	return map[string]interface{}{
		"status": "ok",
		"realm":  realm,
		"spn":    spn,
	}, nil
}

// getKeytabPath returns the effective keytab path (env var or DB config).
func (h *Handler) getKeytabPath() string {
	if h.cfg.KRB5Keytab != "" {
		return h.cfg.KRB5Keytab
	}
	krbCfg, _ := h.getKerberosConfig()
	if krbCfg != nil {
		return krbCfg.KeytabPath
	}
	return ""
}

// getKRB5Realm returns the effective realm (env var or DB config).
func (h *Handler) getKRB5Realm() string {
	if h.cfg.KRB5Realm != "" {
		return h.cfg.KRB5Realm
	}
	krbCfg, _ := h.getKerberosConfig()
	if krbCfg != nil {
		return krbCfg.Realm
	}
	return ""
}
