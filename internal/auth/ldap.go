package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
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

// ErrLDAPAmbiguous is returned (wrapped) by LDAPUserFinder.Find when a name
// matches more than one directory entry.
var ErrLDAPAmbiguous = errors.New("ldap name matches more than one entry")

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

func LDAPConnect(cfg *LDAPConfig) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	if cfg.UseTLS {
		// ldaps:// — implicit TLS from the first byte.
		conn, err = ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		}))
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
	if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}); err != nil {
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

	filter := signInFilter(cfg, username)
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

// signInFilter is the search a password sign-in runs for username: the custom
// filter if set ({{username}} replaced), otherwise (username_attr=username).
func signInFilter(cfg *LDAPConfig, username string) string {
	escapedUser := ldap.EscapeFilter(username)
	if cfg.CustomFilter != "" {
		return strings.Replace(cfg.CustomFilter, "{{username}}", escapedUser, -1)
	}
	attr := cfg.UsernameAttr
	if attr == "" {
		attr = "sAMAccountName"
	}
	return fmt.Sprintf("(%s=%s)", attr, escapedUser)
}

// linkFilter is signInFilter limited to person entries (AD users and
// inetOrgPerson both are), so a group or other object named like a user is
// never taken for one.
func linkFilter(cfg *LDAPConfig, username string) string {
	return "(&(objectClass=person)" + signInFilter(cfg, username) + ")"
}

// LDAPUserFinder looks directory users up by the name they sign in with, over
// one connection bound as the service account: for runs over many users
// (POST /api/admin/ldap/link-users) that would otherwise connect and bind once
// per user.
type LDAPUserFinder struct {
	cfg  *LDAPConfig
	conn *ldap.Conn
}

// NewLDAPUserFinder connects and binds as the service account.
func NewLDAPUserFinder(cfg *LDAPConfig) (*LDAPUserFinder, error) {
	conn, err := LDAPConnect(cfg)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("service account bind failed: %w", err)
	}
	return &LDAPUserFinder{cfg: cfg, conn: conn}, nil
}

// Find returns the one person entry the sign-in filter matches for username:
// ErrLDAPUserNotFound when none does, ErrLDAPAmbiguous when more than one does
// (both wrapped); any other error is the directory failing.
func (f *LDAPUserFinder) Find(username string) (*LDAPResult, error) {
	sr, err := f.conn.Search(ldap.NewSearchRequest(
		f.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 30, false,
		linkFilter(f.cfg, username), ldapAttrs(f.cfg), nil,
	))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if sr == nil || len(sr.Entries) == 0 {
		if err != nil {
			return nil, fmt.Errorf("ldap search: %w", err)
		}
		return nil, fmt.Errorf("%w: %s", ErrLDAPUserNotFound, username)
	}
	if len(sr.Entries) > 1 || err != nil {
		return nil, fmt.Errorf("%w: %s", ErrLDAPAmbiguous, username)
	}
	return entryToResult(sr.Entries[0], f.cfg), nil
}

// Close ends the connection.
func (f *LDAPUserFinder) Close() { f.conn.Close() }

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
