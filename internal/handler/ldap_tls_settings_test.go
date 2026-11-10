package handler

import (
	"net"
	"net/http"
	"strings"
	"testing"

	"simpleauth/internal/ldaptest"
	"simpleauth/internal/store"
)

// getLDAP returns the stored LDAP config as the console reads it.
func getLDAP(t *testing.T, h *Handler) map[string]interface{} {
	t.Helper()
	w := doJSON(h, "GET", "/api/admin/ldap", nil, adminHeaders())
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/admin/ldap: %d %s", w.Code, w.Body.String())
	}
	var cfg map[string]interface{}
	parseJSON(t, w, &cfg)
	if cfg == nil {
		t.Fatal("no LDAP config stored")
	}
	return cfg
}

// putLDAP saves a config through PUT /api/admin/ldap and fails the test unless it is accepted.
func putLDAP(t *testing.T, h *Handler, body map[string]interface{}) {
	t.Helper()
	if w := doJSON(h, "PUT", "/api/admin/ldap", body, adminHeaders()); w.Code != http.StatusOK {
		t.Fatalf("PUT /api/admin/ldap: %d %s", w.Code, w.Body.String())
	}
}

// testLDAP runs POST /api/admin/ldap/test and returns its error ("" when ok).
func testLDAP(t *testing.T, h *Handler) string {
	t.Helper()
	w := doJSON(h, "POST", "/api/admin/ldap/test", nil, adminHeaders())
	var r struct{ Status, Error string }
	parseJSON(t, w, &r)
	if r.Status == "ok" {
		return ""
	}
	if r.Error == "" {
		return "status " + r.Status
	}
	return r.Error
}

// wantTLS checks the TLS settings of the stored config.
func wantTLS(t *testing.T, h *Handler, skip, insecure bool, caCert string) {
	t.Helper()
	cfg := getLDAP(t, h)
	got := func(k string) bool { b, _ := cfg[k].(bool); return b }
	gotCA, _ := cfg["ca_cert"].(string)
	if got("skip_tls_verify") != skip || got("allow_insecure") != insecure || gotCA != strings.TrimSpace(caCert) {
		t.Errorf("stored skip_tls_verify=%v allow_insecure=%v ca_cert set=%v; want %v %v %v (ca_cert matches: %v)",
			got("skip_tls_verify"), got("allow_insecure"), gotCA != "", skip, insecure, caCert != "",
			gotCA == strings.TrimSpace(caCert))
	}
}

func ldapBody(url string, extra map[string]interface{}) map[string]interface{} {
	b := map[string]interface{}{
		"url": url, "base_dn": "DC=corp,DC=test",
		"bind_dn": "CN=svc,DC=corp,DC=test", "bind_password": "secret",
	}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

var localhostIP = []net.IP{net.ParseIP("127.0.0.1")}

func TestSaveLDAPConfigRejectsInvalidCACert(t *testing.T) {
	h, _ := testSetup(t)
	ca := ldaptest.NewCA(t)

	for name, caCert := range map[string]string{
		"not PEM":     "paste the CA here",
		"private key": "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
		"truncated":   ca.PEM[:len(ca.PEM)-40],
	} {
		w := doJSON(h, "PUT", "/api/admin/ldap", ldapBody("ldap://dc01.corp.test", map[string]interface{}{"ca_cert": caCert}), adminHeaders())
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid ca_cert") {
			t.Errorf("%s: PUT = %d %s, want 400 invalid ca_cert", name, w.Code, w.Body.String())
		}
	}
	if w := doJSON(h, "GET", "/api/admin/ldap", nil, adminHeaders()); strings.TrimSpace(w.Body.String()) != "null" {
		t.Errorf("a refused config was stored: %s", w.Body.String())
	}

	putLDAP(t, h, ldapBody("ldap://dc01.corp.test", map[string]interface{}{"ca_cert": "\n" + ca.PEM + "\n"}))
	wantTLS(t, h, false, false, ca.PEM)
}

// The scheme decides TLS; use_tls is derived from it so GET never shows a value
// that contradicts what the connection does.
func TestSaveLDAPConfigUseTLSFollowsScheme(t *testing.T) {
	h, _ := testSetup(t)
	for url, want := range map[string]bool{"ldaps://dc01.corp.test:636": true, "ldap://dc01.corp.test:389": false} {
		putLDAP(t, h, ldapBody(url, map[string]interface{}{"use_tls": !want}))
		if got, _ := getLDAP(t, h)["use_tls"].(bool); got != want {
			t.Errorf("%s saved with use_tls=%v: stored use_tls=%v, want %v", url, !want, got, want)
		}
	}
}

// The production case: AD's certificate comes from a root CA that the system
// pool does not hold. Pasting that CA into ca_cert makes /test succeed on both
// StartTLS and ldaps://; without it the connection fails closed.
func TestLDAPTestTrustsCACert(t *testing.T) {
	h, _ := testSetup(t)
	ca := ldaptest.NewCA(t)
	cert := ca.Issue(t, nil, localhostIP)

	for _, url := range []string{
		"ldap://" + ldaptest.StartTLSServer(t, &cert).Addr,
		"ldaps://" + ldaptest.StartLDAPSServer(t, cert).Addr,
	} {
		putLDAP(t, h, ldapBody(url, map[string]interface{}{"ca_cert": ca.PEM}))
		if err := testLDAP(t, h); err != "" {
			t.Errorf("%s with ca_cert: %s", url, err)
		}

		putLDAP(t, h, ldapBody(url, nil))
		if err := testLDAP(t, h); !strings.Contains(err, "certificate") || !strings.Contains(err, "set ca_cert") {
			t.Errorf("%s without ca_cert: got %q, want a certificate error pointing at ca_cert", url, err)
		}
	}
}

// The console's manual form never sends use_tls, so an ldaps:// URL saved from
// the UI used to be dialled with go-ldap's default TLS settings: ca_cert and
// skip_tls_verify were ignored. The scheme now decides.
func TestLDAPSWithoutUseTLSUsesTLSSettings(t *testing.T) {
	h, _ := testSetup(t)
	ca := ldaptest.NewCA(t)

	trusted := ldaptest.StartLDAPSServer(t, ca.Issue(t, nil, localhostIP))
	putLDAP(t, h, ldapBody("ldaps://"+trusted.Addr, map[string]interface{}{"ca_cert": ca.PEM}))
	if err := testLDAP(t, h); err != "" {
		t.Errorf("ldaps:// with ca_cert and no use_tls: %s", err)
	}

	wrongHost := ldaptest.StartLDAPSServer(t, ldaptest.NewCA(t).Issue(t, []string{"dc01.other.test"}, nil))
	putLDAP(t, h, ldapBody("ldaps://"+wrongHost.Addr, map[string]interface{}{"skip_tls_verify": true}))
	if err := testLDAP(t, h); err != "" {
		t.Errorf("ldaps:// with skip_tls_verify and no use_tls: %s", err)
	}
}

// A config stored by an older version with use_tls=true on an ldap:// URL used
// to be dialled in cleartext with no StartTLS at all (go-ldap ignores the TLS
// config for ldap://), sending the bind password in the clear.
func TestStoredUseTLSOnLDAPURLStillUsesStartTLS(t *testing.T) {
	h, _ := testSetup(t)
	cert := ldaptest.NewCA(t).Issue(t, nil, localhostIP)
	srv := ldaptest.StartTLSServer(t, &cert)
	if err := h.saveLDAPConfigEncrypted(&store.LDAPConfig{
		URL: "ldap://" + srv.Addr, BaseDN: "DC=corp,DC=test", BindDN: "CN=svc,DC=corp,DC=test", BindPassword: "secret",
		UseTLS: true, SkipTLSVerify: true,
	}); err != nil {
		t.Fatal(err)
	}

	if err := testLDAP(t, h); err != "" {
		t.Errorf("/test: %s", err)
	}
	if !srv.TLSUpgraded() {
		t.Error("connection was not upgraded with StartTLS")
	}
	assertNoCleartextOps(t, srv)
}
