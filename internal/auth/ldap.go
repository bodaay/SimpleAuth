package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ErrLDAPUserNotFound is returned (wrapped) when a directory search matches no
// entry, so callers can tell "the account is gone" apart from "LDAP is down".
var ErrLDAPUserNotFound = errors.New("ldap user not found")

// ErrLDAPAccountDisabled is returned when the directory marks the account as
// disabled or expired (AD userAccountControl / accountExpires).
var ErrLDAPAccountDisabled = errors.New("directory account disabled")

type LDAPConfig struct {
	URL             string
	BaseDN          string
	BindDN          string
	BindPassword    string
	UsernameAttr    string
	CustomFilter    string
	UseTLS          bool
	SkipTLSVerify   bool
	AllowInsecure   bool
	DisplayNameAttr string
	EmailAttr       string
	DepartmentAttr  string
	CompanyAttr     string
	JobTitleAttr    string
	GroupsAttr      string
}

type LDAPResult struct {
	DN          string
	Username    string
	DisplayName string
	Email       string
	Department  string
	Company     string
	JobTitle    string
	Groups      []string
	// Disabled is true when AD reports the account as disabled
	// (userAccountControl ACCOUNTDISABLE) or past its accountExpires date.
	// Always false for directories that expose neither attribute.
	Disabled bool
}

// ldapRootCAs is the trust pool for directory certificates; nil means the system
// pool (which honours SSL_CERT_FILE). Tests point it at their own CA.
var ldapRootCAs *x509.CertPool

// ldapTLSConfig returns the TLS settings for a connection to the server in rawURL.
// ServerName must be set explicitly: StartTLS wraps an already-open socket with
// tls.Client, which (unlike tls.Dial for ldaps://) does not derive it from the
// address, and without it every verified handshake fails with "either ServerName
// or InsecureSkipVerify must be specified in the tls.Config".
func ldapTLSConfig(rawURL string, skipVerify bool) *tls.Config {
	cfg := &tls.Config{InsecureSkipVerify: skipVerify, RootCAs: ldapRootCAs}
	if u, err := url.Parse(rawURL); err == nil {
		cfg.ServerName = u.Hostname()
	}
	return cfg
}

func LDAPConnect(cfg *LDAPConfig) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	if cfg.UseTLS {
		// ldaps:// — implicit TLS from the first byte.
		conn, err = ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(ldapTLSConfig(cfg.URL, cfg.SkipTLSVerify)))
		if err != nil {
			return nil, fmt.Errorf("ldap connect: %w", err)
		}
		return conn, nil
	}

	// Plain ldap:// — dial, then upgrade to TLS with StartTLS *before any bind*
	// so the service-account and end-user passwords are never transmitted in
	// cleartext. Fail closed if the upgrade fails, unless the operator has
	// explicitly opted into insecure cleartext binds (allow_insecure).
	conn, err = ldap.DialURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}
	if cfg.AllowInsecure {
		return conn, nil
	}
	if err := conn.StartTLS(ldapTLSConfig(cfg.URL, cfg.SkipTLSVerify)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap StartTLS upgrade failed; refusing cleartext bind (use ldaps:// or set allow_insecure): %w", err)
	}
	return conn, nil
}

// LDAPSearchUser searches for a user by a specific field value using service account credentials.
func LDAPSearchUser(cfg *LDAPConfig, field, value string) (*LDAPResult, error) {
	conn, err := LDAPConnect(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind with service account
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service account bind failed: %w", err)
	}

	filter := fmt.Sprintf("(%s=%s)", ldap.EscapeFilter(field), ldap.EscapeFilter(value))

	attrs := ldapAttrs(cfg)

	sr, err := conn.Search(ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 30, false,
		filter, attrs, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("%w: %s=%s", ErrLDAPUserNotFound, field, value)
	}

	entry := sr.Entries[0]
	return entryToResult(entry, cfg), nil
}

// LDAPSearchUsers searches the directory for users matching a query string.
// Searches across common attributes: username, display name, email.
func LDAPSearchUsers(cfg *LDAPConfig, query string, limit int) ([]*LDAPResult, error) {
	conn, err := LDAPConnect(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service account bind failed: %w", err)
	}

	if limit <= 0 || limit > 100 {
		limit = 50
	}

	escapedQuery := ldap.EscapeFilter(query)
	usernameAttr := cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}

	// Build a filter that searches across multiple fields
	filter := fmt.Sprintf("(&(objectClass=person)(|(%s=%s*)(%s=*%s*)",
		usernameAttr, escapedQuery,
		usernameAttr, escapedQuery,
	)
	if cfg.DisplayNameAttr != "" {
		filter += fmt.Sprintf("(%s=*%s*)", cfg.DisplayNameAttr, escapedQuery)
	}
	if cfg.EmailAttr != "" {
		filter += fmt.Sprintf("(%s=*%s*)", cfg.EmailAttr, escapedQuery)
	}
	filter += "))"

	attrs := ldapAttrs(cfg)

	sr, err := conn.Search(ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, 30, false,
		filter, attrs, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}

	var results []*LDAPResult
	for _, entry := range sr.Entries {
		r := entryToResult(entry, cfg)
		if r.Username != "" {
			results = append(results, r)
		}
	}
	return results, nil
}

// LDAPAuthenticate performs user search and bind authentication.
func LDAPAuthenticate(cfg *LDAPConfig, username, password string) (*LDAPResult, error) {
	conn, err := LDAPConnect(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind with service account first
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service account bind failed: %w", err)
	}

	// Search for user — use custom filter if set, otherwise build from username_attr
	escapedUser := ldap.EscapeFilter(username)
	var filter string
	if cfg.CustomFilter != "" {
		filter = strings.Replace(cfg.CustomFilter, "{{username}}", escapedUser, -1)
	} else {
		attr := cfg.UsernameAttr
		if attr == "" {
			attr = "sAMAccountName"
		}
		filter = fmt.Sprintf("(%s=%s)", attr, escapedUser)
	}
	attrs := ldapAttrs(cfg)

	sr, err := conn.Search(ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 30, false,
		filter, attrs, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrLDAPUserNotFound, username)
	}

	entry := sr.Entries[0]

	// Bind as user to verify password
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, fmt.Errorf("authentication failed")
	}

	// AD normally refuses the bind for a disabled/expired account, but don't rely
	// on it: check the account state explicitly.
	result := entryToResult(entry, cfg)
	if result.Disabled {
		return nil, ErrLDAPAccountDisabled
	}
	return result, nil
}

// LDAPTestConnection tests connectivity and bind with a service account.
func LDAPTestConnection(cfg *LDAPConfig) error {
	conn, err := LDAPConnect(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return fmt.Errorf("bind failed: %w", err)
	}
	return nil
}

func ldapAttrs(cfg *LDAPConfig) []string {
	usernameAttr := cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}
	attrs := []string{"dn", usernameAttr, "userAccountControl", "accountExpires"}
	for _, a := range []string{cfg.DisplayNameAttr, cfg.EmailAttr, cfg.DepartmentAttr, cfg.CompanyAttr, cfg.JobTitleAttr, cfg.GroupsAttr} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	return attrs
}

func entryToResult(entry *ldap.Entry, cfg *LDAPConfig) *LDAPResult {
	usernameAttr := cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}
	result := &LDAPResult{
		DN:       entry.DN,
		Username: entry.GetAttributeValue(usernameAttr),
		Disabled: adAccountDisabled(entry.GetAttributeValue("userAccountControl"), entry.GetAttributeValue("accountExpires"), time.Now()),
	}
	if cfg.DisplayNameAttr != "" {
		result.DisplayName = entry.GetAttributeValue(cfg.DisplayNameAttr)
	}
	if cfg.EmailAttr != "" {
		result.Email = entry.GetAttributeValue(cfg.EmailAttr)
	}
	if cfg.DepartmentAttr != "" {
		result.Department = entry.GetAttributeValue(cfg.DepartmentAttr)
	}
	if cfg.CompanyAttr != "" {
		result.Company = entry.GetAttributeValue(cfg.CompanyAttr)
	}
	if cfg.JobTitleAttr != "" {
		result.JobTitle = entry.GetAttributeValue(cfg.JobTitleAttr)
	}
	if cfg.GroupsAttr != "" {
		result.Groups = entry.GetAttributeValues(cfg.GroupsAttr)
		// Extract the CN from full DN group names, case-insensitively. AD returns
		// "CN=Admins,OU=...", but some directories emit lowercase "cn="; the old
		// code matched case-insensitively yet stripped only the uppercase "CN="
		// prefix, leaving "cn=Admins" intact and breaking group→role mapping.
		for i, g := range result.Groups {
			if idx := strings.Index(g, "="); idx > 0 && strings.EqualFold(g[:idx], "cn") {
				cn := g[idx+1:]
				if comma := strings.Index(cn, ","); comma >= 0 {
					cn = cn[:comma]
				}
				result.Groups[i] = cn
			}
		}
	}
	return result
}

// adAccountDisabled interprets AD's account-state attributes. Empty values
// (non-AD directories) mean "not disabled".
//
//   - userAccountControl: bit 0x2 is ACCOUNTDISABLE.
//   - accountExpires: Windows FILETIME (100ns ticks since 1601-01-01 UTC);
//     0 and 0x7FFFFFFFFFFFFFFF both mean "never expires".
func adAccountDisabled(userAccountControl, accountExpires string, now time.Time) bool {
	if userAccountControl != "" {
		if uac, err := strconv.ParseInt(userAccountControl, 10, 64); err == nil && uac&0x2 != 0 {
			return true
		}
	}
	if accountExpires != "" {
		ft, err := strconv.ParseInt(accountExpires, 10, 64)
		if err == nil && ft != 0 && ft != 0x7FFFFFFFFFFFFFFF {
			const epochDiff = 11644473600 // seconds between 1601-01-01 and 1970-01-01
			expires := time.Unix(ft/1e7-epochDiff, (ft%1e7)*100)
			if !now.Before(expires) {
				return true
			}
		}
	}
	return false
}
