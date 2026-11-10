package auth

import (
	"crypto/x509"
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
		tc, err := ldapTLSConfig(&LDAPConfig{URL: c.url})
		if err != nil {
			t.Fatalf("ldapTLSConfig(%q): %v", c.url, err)
		}
		if tc.ServerName != c.want {
			t.Errorf("ldapTLSConfig(%q).ServerName = %q, want %q", c.url, tc.ServerName, c.want)
		}
	}
	tc, err := ldapTLSConfig(&LDAPConfig{URL: "ldap://dc01", SkipTLSVerify: true})
	if err != nil || !tc.InsecureSkipVerify {
		t.Errorf("skip_tls_verify not carried into the TLS config (err %v)", err)
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

	conn, err := LDAPConnect(&LDAPConfig{URL: "ldaps://" + srv.Addr})
	if err != nil {
		t.Fatalf("ldaps:// with a trusted certificate failed: %v", err)
	}
	conn.Close()
}

// withSystemPool makes pool stand in for the system trust store for this test.
// An empty pool is a system store that lacks the AD root CA, and keeps the
// failure deterministic: with a real system pool, macOS reports an untrusted
// certificate in its own words.
func withSystemPool(t *testing.T, pool *x509.CertPool) {
	t.Helper()
	ldapRootCAs = pool
	t.Cleanup(func() { ldapRootCAs = nil })
}

// requireVerified fails unless conn completed a TLS handshake that verified the
// server's certificate chain (as opposed to skipping verification).
func requireVerified(t *testing.T, cfg *LDAPConfig) {
	t.Helper()
	conn, err := LDAPConnect(cfg)
	if err != nil {
		t.Fatalf("LDAPConnect(%s): %v", cfg.URL, err)
	}
	defer conn.Close()
	state, ok := conn.TLSConnectionState()
	if !ok || !state.HandshakeComplete {
		t.Fatal("connection is not TLS")
	}
	if len(state.VerifiedChains) == 0 {
		t.Fatal("certificate chain was not verified")
	}
}

// requireUnknownAuthority fails unless LDAPConnect refuses the directory because
// its certificate chains to an untrusted CA, and points the operator at ca_cert.
func requireUnknownAuthority(t *testing.T, cfg *LDAPConfig) {
	t.Helper()
	conn, err := LDAPConnect(cfg)
	if err == nil {
		conn.Close()
		t.Fatalf("LDAPConnect(%s) accepted a certificate from an untrusted CA", cfg.URL)
	}
	if !strings.Contains(err.Error(), "certificate signed by unknown authority") || !strings.Contains(err.Error(), "set ca_cert") {
		t.Errorf("unexpected error: %v", err)
	}
}

// The AD certificate comes from an internal root CA that is not in the system
// store: StartTLS and ldaps:// verify it once that CA is pasted into ca_cert,
// and fail closed without it.
func TestLDAPConnectCACert(t *testing.T) {
	ca := ldaptest.NewCA(t) // the AD root CA, separate from anything trusted
	cert := ca.Issue(t, nil, []net.IP{net.ParseIP("127.0.0.1")})
	startTLS := "ldap://" + ldaptest.StartTLSServer(t, &cert).Addr
	ldaps := "ldaps://" + ldaptest.StartLDAPSServer(t, cert).Addr

	for _, url := range []string{startTLS, ldaps} {
		t.Run(url[:strings.Index(url, ":")], func(t *testing.T) {
			// Real system pool plus the pasted CA.
			requireVerified(t, &LDAPConfig{URL: url, CACert: ca.PEM})

			withSystemPool(t, x509.NewCertPool())
			requireUnknownAuthority(t, &LDAPConfig{URL: url})
			requireVerified(t, &LDAPConfig{URL: url, CACert: ca.PEM})
			// A CA bundle: an unrelated CA first, then the AD root CA.
			requireVerified(t, &LDAPConfig{URL: url, CACert: ldaptest.NewCA(t).PEM + ca.PEM})
			// The wrong CA is not enough.
			requireUnknownAuthority(t, &LDAPConfig{URL: url, CACert: ldaptest.NewCA(t).PEM})
		})
	}
}

// ca_cert adds trust; it does not switch off the host name check.
func TestLDAPConnectCACertStillChecksHost(t *testing.T) {
	ca := ldaptest.NewCA(t)
	withSystemPool(t, x509.NewCertPool())
	cert := ca.Issue(t, []string{"dc01.other.test"}, nil)
	srv := ldaptest.StartTLSServer(t, &cert)

	conn, err := LDAPConnect(&LDAPConfig{URL: "ldap://" + srv.Addr, CACert: ca.PEM})
	if err == nil {
		conn.Close()
		t.Fatal("StartTLS accepted a certificate issued for another host")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("unexpected error: %v", err)
	}
}

// skip_tls_verify still works with an untrusted CA, on both schemes.
func TestLDAPConnectSkipVerifyUntrustedCA(t *testing.T) {
	withSystemPool(t, x509.NewCertPool())
	cert := ldaptest.NewCA(t).Issue(t, []string{"dc01.other.test"}, nil)
	for _, url := range []string{
		"ldap://" + ldaptest.StartTLSServer(t, &cert).Addr,
		"ldaps://" + ldaptest.StartLDAPSServer(t, cert).Addr,
	} {
		conn, err := LDAPConnect(&LDAPConfig{URL: url, SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("%s with skip_tls_verify failed: %v", url, err)
		}
		conn.Close()
	}
}

// A stored ca_cert that does not parse is an error before anything is dialled,
// never a silent fall back to the system pool.
func TestLDAPConnectInvalidCACert(t *testing.T) {
	cert := ldaptest.NewCA(t).Issue(t, nil, []net.IP{net.ParseIP("127.0.0.1")})
	srv := ldaptest.StartTLSServer(t, &cert)

	conn, err := LDAPConnect(&LDAPConfig{URL: "ldap://" + srv.Addr, CACert: "not a certificate"})
	if err == nil {
		conn.Close()
		t.Fatal("LDAPConnect accepted an unparseable ca_cert")
	}
	if !strings.Contains(err.Error(), "ldap ca_cert") {
		t.Errorf("unexpected error: %v", err)
	}
	if ops := srv.CleartextOps(); len(ops) != 0 {
		t.Errorf("dialled the directory despite the bad ca_cert (ops %x)", ops)
	}
}

func TestParseLDAPCACert(t *testing.T) {
	a, b := ldaptest.NewCA(t).PEM, ldaptest.NewCA(t).PEM
	good := map[string]struct {
		pem  string
		want int
	}{
		"single":           {a, 1},
		"bundle":           {a + b, 2},
		"crlf":             {strings.ReplaceAll(a, "\n", "\r\n"), 1},
		"surrounding text": {"Bag Attributes\n    friendlyName: corp-root\nsubject=CN=corp-root\n" + a + "\n\n", 1},
		"indented lines":   {"  " + strings.ReplaceAll(a, "\n", "\n\t  "), 1},
	}
	for name, c := range good {
		certs, err := ParseLDAPCACert(c.pem)
		if err != nil || len(certs) != c.want {
			t.Errorf("%s: got %d certificates, err %v; want %d", name, len(certs), err, c.want)
		}
	}

	damaged := a[:len(a)/2] + a[len(a)/2+7:] // a few base64 characters lost: the block no longer decodes
	bad := map[string]string{
		"empty":          "",
		"not PEM":        "MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRlc3Rj",
		"private key":    a + "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
		"garbage block":  "-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----\n",
		"damaged":        b + damaged,
		"truncated":      b + a[:len(a)-30],
		"truncated only": a[:len(a)-30],
	}
	for name, text := range bad {
		certs, err := ParseLDAPCACert(text)
		if err == nil {
			t.Errorf("%s: accepted (%d certificates)", name, len(certs))
		}
		t.Logf("%s: %v", name, err)
	}
}

func TestIsLDAPS(t *testing.T) {
	cases := map[string]bool{
		"ldaps://dc01.corp.local:636": true,
		"LDAPS://dc01.corp.local":     true,
		"ldap://dc01.corp.local:389":  false,
		"ldap://dc01.corp.local:636":  false,
		"dc01.corp.local":             false,
	}
	for url, want := range cases {
		if got := IsLDAPS(url); got != want {
			t.Errorf("IsLDAPS(%q) = %v, want %v", url, got, want)
		}
	}
}
