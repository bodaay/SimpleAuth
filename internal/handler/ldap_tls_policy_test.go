package handler

import (
	"net/http"
	"strings"
	"testing"

	"simpleauth/internal/ldaptest"
)

// assertNoCleartextOps fails when anything but the StartTLS request reached the
// directory before TLS — a search or, worse, a bind carrying a password.
func assertNoCleartextOps(t *testing.T, srv *ldaptest.Server) {
	t.Helper()
	for _, op := range srv.CleartextOps() {
		if op != ldaptest.TagExtendedRequest {
			t.Errorf("LDAP operation 0x%x was sent in cleartext", op)
		}
	}
}

// The console's "Connect" (auto-discover) used to dial ldap:// and bind without
// StartTLS, sending the service-account password in cleartext and reporting
// success for a config that then failed every login.
func TestAutoDiscoverDoesNotBindInCleartext(t *testing.T) {
	h, _ := testSetup(t)
	srv := ldaptest.StartTLSServer(t, nil) // directory that refuses StartTLS

	w := doJSON(h, "POST", "/api/admin/ldap/auto-discover", map[string]string{
		"server": "ldap://" + srv.Addr, "username": "svc@corp.local", "password": "secret",
	}, adminHeaders())

	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "StartTLS") {
		t.Errorf("auto-discover = %d %s, want 502 with the StartTLS error", w.Code, w.Body.String())
	}
	assertNoCleartextOps(t, srv)
}

func TestSetupKerberosDoesNotBindInCleartext(t *testing.T) {
	h, _ := testSetup(t)
	srv := ldaptest.StartTLSServer(t, nil)

	w := doJSON(h, "PUT", "/api/admin/ldap", map[string]interface{}{
		"url": "ldap://" + srv.Addr, "base_dn": "DC=corp,DC=local",
		"bind_dn": "CN=svc,DC=corp,DC=local", "bind_password": "secret",
	}, adminHeaders())
	if w.Code != http.StatusOK {
		t.Fatalf("save ldap config: %d %s", w.Code, w.Body.String())
	}

	w = doJSON(h, "POST", "/api/admin/ldap/setup-kerberos", map[string]string{"service_hostname": "auth.corp.local"}, adminHeaders())
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "StartTLS") {
		t.Errorf("setup-kerberos = %d %s, want 502 with the StartTLS error", w.Code, w.Body.String())
	}
	assertNoCleartextOps(t, srv)
}
