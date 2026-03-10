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
// Body: optional {"service_hostname": "override"} — defaults to cfg.Hostname
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
	readJSON(r, &req) // optional body
	if req.ServiceHostname == "" {
		req.ServiceHostname = h.cfg.Hostname
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

// handleSetupScript returns a full interactive PowerShell script for AD setup.
// The script auto-discovers the domain, offers to create or reuse an AD account,
// registers the SPN, and exports a config JSON for one-click import into SimpleAuth.
// The SimpleAuth hostname and default account name are pre-injected.
// GET /api/admin/setup-script
func (h *Handler) handleSetupScript(w http.ResponseWriter, r *http.Request) {
	hostname := h.cfg.Hostname
	defaultAccount := "svc-sauth-" + strings.ToLower(h.cfg.DeploymentName)

	lines := setupScriptLines(hostname, defaultAccount, h.cfg.DeploymentName)
	script := strings.Join(lines, "\r\n")

	// UTF-8 BOM so Windows PowerShell reads encoding correctly
	bom := []byte{0xEF, 0xBB, 0xBF}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="Setup-SimpleAuth-%s.ps1"`, strings.ToLower(h.cfg.DeploymentName)))
	w.Write(bom)
	w.Write([]byte(script))
}

// setupScriptLines builds the PowerShell setup script as a slice of lines.
// This mirrors the client-side generateScript but with hostname pre-injected.
func setupScriptLines(hostname, defaultAccount, deploymentName string) []string {
	// psEsc escapes a string for embedding in PowerShell single-quoted strings
	psEsc := func(s string) string { return strings.ReplaceAll(s, "'", "''") }

	return []string{
		"#Requires -Modules ActiveDirectory",
		"<#",
		".SYNOPSIS",
		"    SimpleAuth AD Setup / Cleanup Script",
		".DESCRIPTION",
		"    Interactive script to set up or remove a SimpleAuth service account in AD.",
		"    Run on a Domain Controller or a machine with RSAT AD tools.",
		"    Requires Domain Admin or Account Operator privileges.",
		"",
		"    SimpleAuth Hostname: " + hostname,
		"    Default Account:    " + defaultAccount,
		"#>",
		"",
		"$ErrorActionPreference = \"Stop\"",
		"$SimpleAuthHostname = '" + psEsc(hostname) + "'",
		"",
		"# -- Check admin privileges ----------------------------------------",
		"$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()",
		"$adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator",
		"$isAdmin = (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole($adminRole)",
		"",
		"# -- Header -------------------------------------------------------",
		"Write-Host \"\"",
		"Write-Host \"  ========================================\" -ForegroundColor Cyan",
		"Write-Host \"       SimpleAuth  AD  Manager\" -ForegroundColor Cyan",
		"Write-Host \"  ========================================\" -ForegroundColor Cyan",
		"Write-Host \"  Hostname: $SimpleAuthHostname\" -ForegroundColor White",
		"Write-Host \"\"",
		"if (-not $isAdmin) {",
		"    Write-Host \"  WARNING: Not running as Administrator.\" -ForegroundColor Yellow",
		"    Write-Host \"  You may get Access Denied errors. Right-click PowerShell\" -ForegroundColor Yellow",
		"    Write-Host \"  and select Run as Administrator if this fails.\" -ForegroundColor Yellow",
		"    Write-Host \"\"",
		"}",
		"",
		"# -- Detect domain ------------------------------------------------",
		"$domain = Get-ADDomain",
		"$domainDNS = $domain.DNSRoot",
		"$domainDN = $domain.DistinguishedName",
		"$dc = (Get-ADDomainController -Discover -DomainName $domainDNS).HostName[0]",
		"",
		"Write-Host \"  Domain:    $domainDNS\" -ForegroundColor White",
		"Write-Host \"  Base DN:   $domainDN\" -ForegroundColor White",
		"Write-Host \"  DC:        $dc\" -ForegroundColor White",
		"Write-Host \"\"",
		"",
		"# -- Choose account mode -------------------------------------------",
		"Write-Host \"  How would you like to set up the LDAP bind account?\" -ForegroundColor White",
		"Write-Host \"    1) Create a new service account (recommended)\" -ForegroundColor White",
		"Write-Host \"    2) Use an existing AD account\" -ForegroundColor White",
		"Write-Host \"\"",
		"$accountMode = Read-Host \"Enter choice [1]\"",
		"if ([string]::IsNullOrWhiteSpace($accountMode)) { $accountMode = \"1\" }",
		"Write-Host \"\"",
		"",
		"if ($accountMode -eq \"2\") {",
		"    # --- Use existing account ---",
		"    $AccountName = Read-Host \"Enter sAMAccountName of the existing AD account\"",
		"    if ([string]::IsNullOrWhiteSpace($AccountName)) {",
		"        Write-Host \"  No account specified. Exiting.\" -ForegroundColor Red",
		"        exit 1",
		"    }",
		"    $existingUser = Get-ADUser -Filter \"sAMAccountName -eq '$AccountName'\" -Properties servicePrincipalName -ErrorAction SilentlyContinue",
		"    if (-not $existingUser) {",
		"        Write-Host \"  Account '$AccountName' not found in AD.\" -ForegroundColor Red",
		"        exit 1",
		"    }",
		"    Write-Host \"  Found: $($existingUser.DistinguishedName)\" -ForegroundColor Green",
		"    $AccountPassword = Read-Host \"Enter the password for $AccountName\"",
		"    Write-Host \"\"",
		"} else {",
		"    # --- Create new account ---",
		"    $defaultName = '" + psEsc(defaultAccount) + "'",
		"    $nameInput = Read-Host \"Service account name [$defaultName]\"",
		"    if ([string]::IsNullOrWhiteSpace($nameInput)) { $AccountName = $defaultName } else { $AccountName = $nameInput }",
		"    Write-Host \"\"",
		"",
		"    # Check if account already exists",
		"    $adFilter = \"sAMAccountName -eq '$AccountName'\"",
		"    $existingUser = Get-ADUser -Filter $adFilter -Properties servicePrincipalName -ErrorAction SilentlyContinue",
		"",
		"    if ($existingUser) {",
		"        $existingSPNs = $existingUser.servicePrincipalName",
		"        Write-Host \"  Account '$AccountName' already exists in AD.\" -ForegroundColor Yellow",
		"        if ($existingSPNs) {",
		"            Write-Host \"  SPNs registered: $($existingSPNs -join ', ')\" -ForegroundColor Yellow",
		"        }",
		"        Write-Host \"\"",
		"        Write-Host \"  What would you like to do?\" -ForegroundColor White",
		"        Write-Host \"    1) Re-run setup (update password, re-export config)\" -ForegroundColor White",
		"        Write-Host \"    2) Remove everything (delete SPNs, disable/delete account)\" -ForegroundColor White",
		"        Write-Host \"    3) Exit\" -ForegroundColor White",
		"        Write-Host \"\"",
		"        $choice = Read-Host \"Enter choice [1]\"",
		"        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = \"1\" }",
		"        Write-Host \"\"",
		"",
		"        if ($choice -eq \"3\") {",
		"            Write-Host \"  Exiting.\" -ForegroundColor White",
		"            exit 0",
		"        }",
		"",
		"        if ($choice -eq \"2\") {",
		"            # ---- CLEANUP MODE ----",
		"            Write-Host \"  ---- Cleanup Mode ----\" -ForegroundColor Red",
		"            Write-Host \"\"",
		"            if ($existingSPNs) {",
		"                foreach ($s in $existingSPNs) {",
		"                    Write-Host \"  Removing SPN: $s\" -ForegroundColor White",
		"                    try { $null = & setspn -D $s $AccountName 2>&1; Write-Host \"    Removed.\" -ForegroundColor Green } catch { Write-Host \"    Failed: $_\" -ForegroundColor Yellow }",
		"                }",
		"            } else {",
		"                Write-Host \"  No SPNs to remove.\" -ForegroundColor White",
		"            }",
		"            Write-Host \"\"",
		"            Write-Host \"  Delete the account entirely, or just disable it?\" -ForegroundColor White",
		"            Write-Host \"    1) Delete account\" -ForegroundColor White",
		"            Write-Host \"    2) Disable account (keep for reference)\" -ForegroundColor White",
		"            Write-Host \"\"",
		"            $delChoice = Read-Host \"Enter choice [1]\"",
		"            if ([string]::IsNullOrWhiteSpace($delChoice)) { $delChoice = \"1\" }",
		"            if ($delChoice -eq \"2\") {",
		"                Disable-ADAccount -Identity $existingUser",
		"                Write-Host \"  Account '$AccountName' disabled.\" -ForegroundColor Green",
		"            } else {",
		"                $confirm = Read-Host \"  Type YES to permanently delete '$AccountName'\"",
		"                if ($confirm -eq \"YES\") {",
		"                    Remove-ADUser -Identity $existingUser -Confirm:$false",
		"                    Write-Host \"  Account '$AccountName' deleted.\" -ForegroundColor Green",
		"                } else {",
		"                    Write-Host \"  Aborted. Account not deleted.\" -ForegroundColor Yellow",
		"                }",
		"            }",
		"            $outFile = Join-Path (Get-Location) \"simpleauth-config.json\"",
		"            if (Test-Path $outFile) {",
		"                $delCfg = Read-Host \"  Delete simpleauth-config.json too? [y/N]\"",
		"                if ($delCfg -eq \"y\" -or $delCfg -eq \"Y\") { Remove-Item $outFile; Write-Host \"  Config file deleted.\" -ForegroundColor Green }",
		"            }",
		"            Write-Host \"\"",
		"            Write-Host \"  ========================================\" -ForegroundColor Green",
		"            Write-Host \"           Cleanup Complete\" -ForegroundColor Green",
		"            Write-Host \"  ========================================\" -ForegroundColor Green",
		"            Write-Host \"\"",
		"            Write-Host \"  Remember to also remove the LDAP provider\" -ForegroundColor Yellow",
		"            Write-Host \"  and Kerberos config in the SimpleAuth admin UI.\" -ForegroundColor Yellow",
		"            Write-Host \"\"",
		"            Read-Host \"Press Enter to exit\"",
		"            exit 0",
		"        }",
		"        # choice \"1\" falls through to setup below",
		"    }",
		"",
		"    # -- Prompt for password ---",
		"    Write-Host \"  Enter a password for the service account.\" -ForegroundColor White",
		"    Write-Host \"  (This will be stored in the exported config file for SimpleAuth to use.)\" -ForegroundColor White",
		"    Write-Host \"\"",
		"    $AccountPassword = Read-Host \"Password for $AccountName\"",
		"    if ([string]::IsNullOrWhiteSpace($AccountPassword)) {",
		"        Write-Host \"  Password is required. Exiting.\" -ForegroundColor Red",
		"        exit 1",
		"    }",
		"    Write-Host \"\"",
		"}",
		"",
		"# ==================================================================",
		"# SETUP MODE",
		"# ==================================================================",
		"",
		"# -- Select OU (only for new accounts) ---",
		"if ($accountMode -ne \"2\" -and -not $existingUser) {",
		"    Write-Host \"[1/4] Select where to create the service account\" -ForegroundColor Yellow",
		"    Write-Host \"\"",
		"    $ous = @()",
		"    $ous += [PSCustomObject]@{ Index = 0; Name = \"(Default Users container)\"; DN = $domain.UsersContainer }",
		"    $ouList = Get-ADOrganizationalUnit -Filter * -Properties CanonicalName | Sort-Object CanonicalName",
		"    $i = 1",
		"    foreach ($ou in $ouList) {",
		"        $ous += [PSCustomObject]@{ Index = $i; Name = $ou.CanonicalName; DN = $ou.DistinguishedName }",
		"        $i++",
		"    }",
		"    foreach ($entry in $ous) {",
		"        $idx = $entry.Index.ToString().PadLeft(3)",
		"        if ($entry.Index -eq 0) {",
		"            Write-Host \"  $idx) $($entry.Name)\" -ForegroundColor Green",
		"        } else {",
		"            Write-Host \"  $idx) $($entry.Name)\" -ForegroundColor White",
		"        }",
		"    }",
		"    Write-Host \"\"",
		"    $selection = Read-Host \"Enter number [0]\"",
		"    if ([string]::IsNullOrWhiteSpace($selection)) { $selection = \"0\" }",
		"    $selectedIdx = [int]$selection",
		"    if ($selectedIdx -lt 0 -or $selectedIdx -ge $ous.Count) {",
		"        Write-Host \"  Invalid selection, using default\" -ForegroundColor Yellow",
		"        $selectedIdx = 0",
		"    }",
		"    $targetOU = $ous[$selectedIdx].DN",
		"    Write-Host \"  Selected: $($ous[$selectedIdx].Name)\" -ForegroundColor Cyan",
		"    Write-Host \"\"",
		"} elseif ($existingUser) {",
		"    Write-Host \"[1/4] OU selection skipped (account already exists)\" -ForegroundColor Yellow",
		"    $targetOU = ($existingUser.DistinguishedName -replace \"^CN=[^,]+,\", \"\")",
		"    Write-Host \"\"",
		"} else {",
		"    Write-Host \"[1/4] OU selection skipped (using existing account)\" -ForegroundColor Yellow",
		"    Write-Host \"\"",
		"}",
		"",
		"# -- Create or update account --------------------------------------",
		"Write-Host \"[2/4] Setting up service account...\" -ForegroundColor Yellow",
		"$securePw = ConvertTo-SecureString $AccountPassword -AsPlainText -Force",
		"",
		"if ($accountMode -eq \"2\") {",
		"    Write-Host \"  Using existing account: $AccountName\" -ForegroundColor Green",
		"} elseif ($existingUser) {",
		"    try {",
		"        Set-ADAccountPassword -Identity $existingUser -NewPassword $securePw -Reset",
		"        Enable-ADAccount -Identity $existingUser",
		"        Write-Host \"  Password updated, account enabled.\" -ForegroundColor Green",
		"    } catch {",
		"        Write-Host \"  ERROR: Failed to update account: $_\" -ForegroundColor Red",
		"        Read-Host \"Press Enter to exit\"",
		"        exit 1",
		"    }",
		"} else {",
		"    $newUserParams = @{",
		"        Name                 = $AccountName",
		"        SamAccountName       = $AccountName",
		"        UserPrincipalName    = \"$AccountName@$domainDNS\"",
		"        Path                 = $targetOU",
		"        AccountPassword      = $securePw",
		"        Enabled              = $true",
		"        PasswordNeverExpires = $true",
		"        CannotChangePassword = $true",
		"        Description          = \"SimpleAuth LDAP bind account (do not delete)\"",
		"    }",
		"    try {",
		"        New-ADUser @newUserParams",
		"        Write-Host \"  Account created in: $targetOU\" -ForegroundColor Green",
		"    } catch {",
		"        Write-Host \"  ERROR: Failed to create account: $_\" -ForegroundColor Red",
		"        Write-Host \"\"",
		"        Write-Host \"  Possible causes:\" -ForegroundColor Yellow",
		"        Write-Host \"    - Access denied: run as Domain Admin or Account Operator\" -ForegroundColor White",
		"        Write-Host \"    - No permission on OU: try the default Users container\" -ForegroundColor White",
		"        Write-Host \"    - Password does not meet complexity requirements\" -ForegroundColor White",
		"        Write-Host \"\"",
		"        Read-Host \"Press Enter to exit\"",
		"        exit 1",
		"    }",
		"}",
		"Write-Host \"\"",
		"",
		"# -- Kerberos SPN --------------------------------------------------",
		"Write-Host \"[3/4] Kerberos / SPNEGO setup\" -ForegroundColor Yellow",
		"",
		"# Reload account to get current SPNs",
		"$adFilter = \"sAMAccountName -eq '$AccountName'\"",
		"$currentSPNs = (Get-ADUser -Filter $adFilter -Properties servicePrincipalName).servicePrincipalName",
		"$spn = \"HTTP/$SimpleAuthHostname\"",
		"$spnResult = $null",
		"",
		"# Check if the required SPN is already registered",
		"$spnAlreadyRegistered = $false",
		"if ($currentSPNs) {",
		"    foreach ($s in $currentSPNs) {",
		"        if ($s -eq $spn) { $spnAlreadyRegistered = $true; break }",
		"    }",
		"}",
		"",
		"if ($spnAlreadyRegistered) {",
		"    Write-Host \"  SPN already registered: $spn\" -ForegroundColor Green",
		"    $spnResult = @{ spn = $spn; service_hostname = $SimpleAuthHostname }",
		"} else {",
		"    Write-Host \"  Registering SPN: $spn on $AccountName\" -ForegroundColor White",
		"    try {",
		"        $null = & setspn -A $spn $AccountName 2>&1",
		"        Write-Host \"  SPN registered successfully\" -ForegroundColor Green",
		"        $spnResult = @{ spn = $spn; service_hostname = $SimpleAuthHostname }",
		"    } catch {",
		"        Write-Host \"  Warning: SPN registration failed: $_\" -ForegroundColor Yellow",
		"        Write-Host \"  Run manually: setspn -A $spn $AccountName\" -ForegroundColor Yellow",
		"        $spnResult = @{ service_hostname = $SimpleAuthHostname }",
		"    }",
		"}",
		"Write-Host \"\"",
		"",
		"# -- Export config -------------------------------------------------",
		"Write-Host \"[4/4] Exporting config...\" -ForegroundColor Yellow",
		"",
		"$config = [ordered]@{",
		"    server   = $dc",
		"    username = \"$AccountName@$domainDNS\"",
		"    password = $AccountPassword",
		"    domain   = $domainDNS",
		"    base_dn  = $domainDN",
		"}",
		"if ($spnResult) {",
		"    foreach ($key in $spnResult.Keys) { $config[$key] = $spnResult[$key] }",
		"}",
		"",
		"$outFile = Join-Path (Get-Location) \"simpleauth-config.json\"",
		"$config | ConvertTo-Json | Set-Content -Path $outFile -Encoding UTF8",
		"",
		"Write-Host \"\"",
		"Write-Host \"  ========================================\" -ForegroundColor Green",
		"Write-Host \"           Setup Complete!\" -ForegroundColor Green",
		"Write-Host \"  ========================================\" -ForegroundColor Green",
		"Write-Host \"\"",
		"Write-Host \"  Config file: $outFile\" -ForegroundColor White",
		"Write-Host \"\"",
		"Write-Host \"  Next steps:\" -ForegroundColor Yellow",
		"Write-Host \"    1. Copy simpleauth-config.json to your workstation\" -ForegroundColor White",
		"Write-Host \"    2. Open SimpleAuth admin UI -> LDAP Providers\" -ForegroundColor White",
		"Write-Host \"    3. Click Import Config and upload the file\" -ForegroundColor White",
		"Write-Host \"\"",
		"Read-Host \"Press Enter to exit\"",
	}
}
