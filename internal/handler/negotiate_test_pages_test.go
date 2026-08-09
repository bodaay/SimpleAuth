package handler

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNegotiateDiagnosticPagesEscapeErrors is the M39 regression.
//
// Three call sites passed err.Error() with NO escaping at all (the SPNEGO
// unmarshal, raw-AP-REQ and ticket-parse failures), and err derives from the
// attacker-supplied `Authorization: Negotiate` header.
func TestNegotiateDiagnosticPagesEscapeErrors(t *testing.T) {
	h, _ := testSetup(t)
	const payload = `</td></tr><script>alert(1)</script>`

	for name, tmpl := range map[string]*template.Template{
		"krbFailed":   negotiateTestKrbFailedTmpl,
		"loginFailed": negotiateTestLoginFailedTmpl,
	} {
		rec := httptest.NewRecorder()
		h.renderNegotiateTest(rec, tmpl, http.StatusOK, negotiateTestData{Error: payload})
		body := rec.Body.String()

		if strings.Contains(body, "<script>alert(1)</script>") {
			t.Errorf("%s: reflected an unescaped script tag (M39)", name)
		}
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Errorf("%s: payload should appear HTML-escaped", name)
		}
		// Single-encoded, not double: a surviving manual html.EscapeString would
		// produce &amp;lt; and ship visibly mangled text to the operator.
		if strings.Contains(body, "&amp;lt;") {
			t.Errorf("%s: payload double-escaped — a manual EscapeString survived the conversion", name)
		}
	}
}

// TestNegotiateSuccessPageEscapesDirectoryAttributes covers the AD-controlled
// fields. displayName / department / memberOf are attacker-influenced for anyone
// who can edit their own directory record, and were reflected raw.
func TestNegotiateSuccessPageEscapesDirectoryAttributes(t *testing.T) {
	h, _ := testSetup(t)
	const imgPayload = `<img src=x onerror=alert(1)>`

	rec := httptest.NewRecorder()
	h.renderNegotiateSuccess(rec, map[string]string{
		"auth_method":  "Kerberos",
		"display_name": imgPayload,
		"department":   imgPayload,
		"groups":       imgPayload,
		"email":        `"><script>alert(2)</script>`,
	})
	body := rec.Body.String()

	for _, bad := range []string{"<img src=x onerror=", "<script>alert(2)</script>"} {
		if strings.Contains(body, bad) {
			t.Errorf("success page reflected an unescaped AD attribute: %q (M39)", bad)
		}
	}
	if !strings.Contains(body, "&lt;img") {
		t.Error("AD attribute should appear escaped")
	}
}

// TestNegotiateDiagnosticPagesRenderBasePath pins the {{BASE_PATH}} → {{.BasePath}}
// migration. A missed occurrence leaves a literal placeholder in the form action,
// silently breaking the diagnostic form's POST target — and a stray {{ would have
// panicked template.Must at package init instead, taking every test with it.
func TestNegotiateDiagnosticPagesRenderBasePath(t *testing.T) {
	h, _ := testSetup(t)
	h.cfg.BasePath = "/sauth"

	// The five pages that carry a form.
	pages := map[string]struct {
		tmpl   *template.Template
		status int
	}{
		"wait":        {negotiateTestWaitTmpl, http.StatusUnauthorized},
		"ntlm":        {negotiateTestNTLMFallbackTmpl, http.StatusOK},
		"formError":   {negotiateTestFormErrorTmpl, http.StatusOK},
		"krbFailed":   {negotiateTestKrbFailedTmpl, http.StatusOK},
		"loginFailed": {negotiateTestLoginFailedTmpl, http.StatusOK},
	}
	for name, p := range pages {
		rec := httptest.NewRecorder()
		h.renderNegotiateTest(rec, p.tmpl, p.status, negotiateTestData{Error: "x"})
		body := rec.Body.String()

		if strings.Contains(body, "{{BASE_PATH}}") || strings.Contains(body, "{{.BasePath}}") {
			t.Errorf("%s: an unrendered base-path placeholder survived", name)
		}
		// negotiateTestCSS used to carry fmt-escaped "%%" for the Fprintf paths.
		// html/template is not a format string, so those would ship literally and
		// break every rule containing them (border-radius:50%%, width:100%%).
		if strings.Contains(body, "%%") {
			t.Errorf("%s: fmt-escaped %%%% survived into the rendered CSS", name)
		}
		if !strings.Contains(body, `action="/sauth/test-negotiate"`) {
			t.Errorf("%s: form action should carry the configured base path", name)
		}
	}
}

// TestNegotiateWaitPageKeeps401 guards the status code the SPNEGO handshake
// depends on: the wait page MUST be a 401 or the browser never retries with a
// Negotiate token. The conversion moved WriteHeader into the shared helper, so
// this is exactly the kind of thing a refactor can silently drop.
func TestNegotiateWaitPageKeeps401(t *testing.T) {
	h, _ := testSetup(t)
	rec := httptest.NewRecorder()
	h.renderNegotiateTest(rec, negotiateTestWaitTmpl, http.StatusUnauthorized, negotiateTestData{})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wait page must render 401 (the SPNEGO challenge), got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
}
