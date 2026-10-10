package auth

import (
	"net"
	"strings"
	"testing"

	"simpleauth/internal/ldaptest"
)

func TestLDAPTLSConfigServerName(t *testing.T) {
	cases := []struct{ url, want string }{
		{"ldap://dc01.corp.local:389", "dc01.corp.local"},
		{"ldap://dc01.corp.local", "dc01.corp.local"},
		{"ldaps://dc01.corp.local:636", "dc01.corp.local"},
		{"ldap://10.0.0.5:389", "10.0.0.5"},
		{"ldap://[2001:db8::1]:389", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := ldapTLSConfig(c.url, false).ServerName; got != c.want {
			t.Errorf("ldapTLSConfig(%q).ServerName = %q, want %q", c.url, got, c.want)
		}
	}
	if !ldapTLSConfig("ldap://dc01", true).InsecureSkipVerify {
		t.Error("skip_tls_verify not carried into the TLS config")
	}
}

// trustCA makes LDAPConnect verify directory certificates against ca for this test.
func trustCA(t *testing.T, ca *ldaptest.CA) {
	t.Helper()
	ldapRootCAs = ca.Pool
	t.Cleanup(func() { ldapRootCAs = nil })
}

// Regression: StartTLS used a tls.Config without ServerName, so with certificate
// verification on (the default) every upgrade failed with "either ServerName or
// InsecureSkipVerify must be specified" and ldap:// could never be used securely.
func TestLDAPConnectStartTLSVerifiesCertificate(t *testing.T) {
	ca := ldaptest.NewCA(t)
	trustCA(t, ca)
	cert := ca.Issue(t, nil, []net.IP{net.ParseIP("127.0.0.1")})
	srv := ldaptest.StartTLSServer(t, &cert)

	conn, err := LDAPConnect(&LDAPConfig{URL: "ldap://" + srv.Addr})
	if err != nil {
		t.Fatalf("StartTLS with a trusted certificate failed: %v", err)
	}
	defer conn.Close()
	state, ok := conn.TLSConnectionState()
	if !ok || !state.HandshakeComplete {
		t.Fatal("connection was not upgraded to TLS")
	}
	if ops := srv.CleartextOps(); len(ops) != 1 || ops[0] != ldaptest.TagExtendedRequest {
		t.Errorf("operations sent in cleartext = %x, want only the StartTLS request", ops)
	}
}

func TestLDAPConnectStartTLSRejectsWrongHost(t *testing.T) {
	ca := ldaptest.NewCA(t)
	trustCA(t, ca)
	cert := ca.Issue(t, []string{"dc01.other.test"}, nil)
	srv := ldaptest.StartTLSServer(t, &cert)

	conn, err := LDAPConnect(&LDAPConfig{URL: "ldap://" + srv.Addr})
	if err == nil {
		conn.Close()
		t.Fatal("StartTLS accepted a certificate issued for another host")
	}
	if !strings.Contains(err.Error(), "refusing cleartext bind") || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLDAPConnectStartTLSSkipVerify(t *testing.T) {
	cert := ldaptest.NewCA(t).Issue(t, []string{"dc01.other.test"}, nil)
	srv := ldaptest.StartTLSServer(t, &cert)

	conn, err := LDAPConnect(&LDAPConfig{URL: "ldap://" + srv.Addr, SkipTLSVerify: true})
	if err != nil {
		t.Fatalf("StartTLS with skip_tls_verify failed: %v", err)
	}
	conn.Close()
}

func TestLDAPConnectLDAPSVerifiesCertificate(t *testing.T) {
	ca := ldaptest.NewCA(t)
	trustCA(t, ca)
	srv := ldaptest.StartLDAPSServer(t, ca.Issue(t, nil, []net.IP{net.ParseIP("127.0.0.1")}))

	conn, err := LDAPConnect(&LDAPConfig{URL: "ldaps://" + srv.Addr, UseTLS: true})
	if err != nil {
		t.Fatalf("ldaps:// with a trusted certificate failed: %v", err)
	}
	conn.Close()
}
