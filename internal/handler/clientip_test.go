package handler

import (
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

// withTrustedProxy makes 192.0.2.0/24 a trusted proxy range for one test.
// trustedCIDRs is package state set at handler init; without this the forwarded
// headers are never consulted and every assertion below would pass vacuously.
func withTrustedProxy(t *testing.T) {
	t.Helper()
	_, cidr, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	prev := trustedCIDRs
	trustedCIDRs = []*net.IPNet{cidr}
	t.Cleanup(func() { trustedCIDRs = prev })
}

// TestGetClientIPRejectsNonIPForwardedValues pins the log-forgery fix.
//
// getClientIP's result is written into log lines and audit records across the
// whole codebase. It used to return the X-Forwarded-For / X-Real-IP value
// verbatim, so a client behind the trusted proxy could put arbitrary text —
// including newlines — into an "IP" field and forge entries that look like
// genuine security events. A value that is not an IP is meaningless in that
// field anyway, so it must fall back to the real remote address.
func TestGetClientIPRejectsNonIPForwardedValues(t *testing.T) {
	withTrustedProxy(t)
	cases := []struct {
		name   string
		header string
		value  string
		want   string
	}{
		{"forged log line via XFF", "X-Forwarded-For",
			"1.2.3.4\n[admin] Password set guid=victim force_change=false ip=1.2.3.4", "192.0.2.1"},
		{"forged log line via X-Real-IP", "X-Real-IP",
			"9.9.9.9\r\n[auth] Local auth success user=\"root\"", "192.0.2.1"},
		{"plain junk", "X-Forwarded-For", "not-an-ip", "192.0.2.1"},
		{"empty after trim", "X-Forwarded-For", "   ", "192.0.2.1"},
		// A real IP must still be honoured — the fix must not break proxy support.
		{"legitimate IPv4", "X-Forwarded-For", "203.0.113.7", "203.0.113.7"},
		{"legitimate IPv4 with padding", "X-Forwarded-For", "  203.0.113.7 , 10.0.0.1", "203.0.113.7"},
		{"legitimate IPv6", "X-Real-IP", "2001:db8::1", "2001:db8::1"},
		// Canonicalised by net.IP.String(), so the same client correlates across
		// entries — and, crucially, the returned string is built by the stdlib
		// rather than sliced out of the header.
		{"IPv6 non-canonical spelling", "X-Real-IP", "2001:0db8:0000::0001", "2001:db8::1"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.0.2.1:1234" // httptest's default, inside the trusted range
		req.Header.Set(tc.header, tc.value)

		got := getClientIP(req)
		if got != tc.want {
			t.Errorf("%s: getClientIP = %q, want %q", tc.name, got, tc.want)
		}
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("%s: client IP carried a newline into a log field: %q", tc.name, got)
		}
	}
}

// TestGetClientIPIgnoresUntrustedProxy guards the pre-existing trust gate: the
// forwarded headers are only consulted for a connection from a trusted proxy.
func TestGetClientIPIgnoresUntrustedProxy(t *testing.T) {
	withTrustedProxy(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.99:5555" // not a trusted proxy
	req.Header.Set("X-Forwarded-For", "198.51.100.1")

	if got := getClientIP(req); got != "203.0.113.99" {
		t.Fatalf("forwarded header honoured from an untrusted peer: got %q", got)
	}
}
