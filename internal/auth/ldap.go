package auth

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConfig struct {
	URL             string
	BaseDN          string
	BindDN          string
	BindPassword    string
	UserFilter      string
	UseTLS          bool
	SkipTLSVerify   bool
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
}

func LDAPConnect(cfg *LDAPConfig) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	if cfg.UseTLS {
		conn, err = ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: cfg.SkipTLSVerify,
		}))
	} else {
		conn, err = ldap.DialURL(cfg.URL)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
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
		return nil, fmt.Errorf("user not found: %s=%s", field, value)
	}

	entry := sr.Entries[0]
	return entryToResult(entry, cfg), nil
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

	// Search for user
	filter := strings.Replace(cfg.UserFilter, "{{username}}", ldap.EscapeFilter(username), -1)
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
		return nil, fmt.Errorf("user not found: %s", username)
	}

	entry := sr.Entries[0]

	// Bind as user to verify password
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, fmt.Errorf("authentication failed")
	}

	return entryToResult(entry, cfg), nil
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
	attrs := []string{"dn", "sAMAccountName"}
	for _, a := range []string{cfg.DisplayNameAttr, cfg.EmailAttr, cfg.DepartmentAttr, cfg.CompanyAttr, cfg.JobTitleAttr, cfg.GroupsAttr} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	return attrs
}

func entryToResult(entry *ldap.Entry, cfg *LDAPConfig) *LDAPResult {
	result := &LDAPResult{
		DN:       entry.DN,
		Username: entry.GetAttributeValue("sAMAccountName"),
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
		// Extract CN from full DN group names
		for i, g := range result.Groups {
			if strings.HasPrefix(strings.ToLower(g), "cn=") {
				parts := strings.SplitN(g, ",", 2)
				result.Groups[i] = strings.TrimPrefix(parts[0], "CN=")
			}
		}
	}
	return result
}
