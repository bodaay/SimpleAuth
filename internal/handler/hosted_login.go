package handler

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func generateCSRFToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func setCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "__csrf",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})
}

func validateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("__csrf")
	if err != nil {
		return false
	}
	return timingSafeEqual(cookie.Value, r.FormValue("_csrf"))
}

// handleHostedLoginPage serves the hosted login form.
// Apps redirect users here: GET /login?redirect_uri=Y
func (h *Handler) handleHostedLoginPage(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	errorMsg := r.URL.Query().Get("error")

	// Validate redirect_uri
	if redirectURI != "" && !isAllowedRedirect(h.getRedirectURIs(), redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	errorHTML := ""
	if errorMsg != "" {
		errorHTML = `<div class="error">` + errorMsg + `</div>`
	}

	ssoEnabled := h.getKeytabPath() != ""
	ssoLink := ""
	if ssoEnabled {
		ssoLink = h.url("/login/sso")
		if redirectURI != "" {
			ssoLink += "?redirect_uri=" + url.QueryEscape(redirectURI)
		}
	}

	// Check auto_sso setting — only auto-redirect if SSO is enabled, no error, and not already tried
	autoSSO := false
	ssoAttempted := false
	if c, err := r.Cookie("__sso_attempted"); err == nil && c.Value == "1" {
		ssoAttempted = true
	}
	if ssoEnabled && errorMsg == "" && r.URL.Query().Get("manual") != "1" && !ssoAttempted {
		if rs := h.runtimeSettings.get(); rs != nil && rs.AutoSSO {
			autoSSO = true
		}
	}

	csrfToken := generateCSRFToken()
	setCSRFCookie(w, csrfToken)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// %[1]s = redirectURI, %[2]s = errorHTML, %[3]s = ssoLink, %[4]s = csrfToken,
	// %[5]s = ssoEnabled ("1"/""), %[6]s = autoSSO ("1"/"")
	ssoEnabledStr := ""
	if ssoEnabled {
		ssoEnabledStr = "1"
	}
	autoSSOStr := ""
	if autoSSO {
		autoSSOStr = "1"
	}
	fmt.Fprintf(w, h.bp(hostedLoginHTML), redirectURI, errorHTML, ssoLink, csrfToken, ssoEnabledStr, autoSSOStr)
}

// handleHostedLoginSubmit processes the hosted login form submission.
func (h *Handler) handleHostedLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		h.redirectToLoginError(w, r, redirectURI, "Username and password are required")
		return
	}

	// Validate redirect_uri
	if redirectURI != "" && !isAllowedRedirect(h.getRedirectURIs(), redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	ip := getClientIP(r)

	if !h.loginLimiter.allow(ip) {
		h.redirectToLoginError(w, r, redirectURI, "Too many login attempts. Please try again later.")
		return
	}

	log.Printf("[hosted-login] Attempt user=%q ip=%s redirect_uri=%q", username, ip, redirectURI)
	userGUID, ldapGroups, err := h.authenticateUser(username, password)
	if err != nil {
		log.Printf("[hosted-login] Failed user=%q ip=%s reason=%q", username, ip, err.Error())
		h.audit("login_failed", "", ip, map[string]interface{}{
			"username": username, "reason": err.Error(), "flow": "hosted",
		})
		h.redirectToLoginError(w, r, redirectURI, "Invalid credentials")
		return
	}

	user, err := h.store.ResolveUser(userGUID)
	if err != nil {
		h.redirectToLoginError(w, r, redirectURI, "User not found")
		return
	}
	if user.Disabled {
		h.redirectToLoginError(w, r, redirectURI, "Account disabled")
		return
	}

	// Assign default roles if needed
	h.assignDefaultRoles(user.GUID)

	// Issue tokens
	roles, _ := h.store.GetUserRoles(user.GUID)
	perms := h.resolveUserPermissions(user.GUID, roles)
	accessToken, refreshToken, expiresIn, err := h.issueTokenPair(user, roles, perms, ldapGroups)
	if err != nil {
		h.redirectToLoginError(w, r, redirectURI, "Token generation failed")
		return
	}

	log.Printf("[hosted-login] Success user=%q guid=%s name=%q ip=%s", username, user.GUID, user.DisplayName, ip)
	h.auditLogin(user, ip, map[string]interface{}{"flow": "hosted"})

	if redirectURI != "" {
		// Redirect with tokens in fragment
		fragment := fmt.Sprintf("access_token=%s&refresh_token=%s&expires_in=%d&token_type=Bearer",
			url.QueryEscape(accessToken),
			url.QueryEscape(refreshToken),
			expiresIn,
		)
		http.Redirect(w, r, redirectURI+"#"+fragment, http.StatusFound)
		return
	}

	// No redirect URI — send user to account page with token in fragment
	fragment := fmt.Sprintf("access_token=%s&refresh_token=%s&expires_in=%d&token_type=Bearer",
		url.QueryEscape(accessToken),
		url.QueryEscape(refreshToken),
		expiresIn,
	)
	http.Redirect(w, r, h.url("/account")+"#"+fragment, http.StatusFound)
}

func isAllowedRedirect(allowedList []string, uri string) bool {
	if len(allowedList) == 0 {
		return false // No redirect URIs configured — reject all redirects
	}

	// Only allow http/https schemes
	if !strings.HasPrefix(uri, "https://") && !strings.HasPrefix(uri, "http://") {
		return false
	}

	for _, allowed := range allowedList {
		if strings.HasSuffix(allowed, "*") {
			prefix := allowed[:len(allowed)-1]
			// Ensure wildcard prefix ends with / to prevent subdomain bypass
			// e.g. "https://app.corp.local/*" matches "https://app.corp.local/callback"
			// but NOT "https://app.corp.local.evil.com/"
			if !strings.HasSuffix(prefix, "/") && !strings.HasSuffix(prefix, ".") {
				prefix += "/"
				if strings.HasPrefix(uri, prefix) || uri == allowed[:len(allowed)-1] {
					return true
				}
				continue
			}
			if strings.HasPrefix(uri, prefix) {
				return true
			}
		} else if allowed == uri {
			return true
		}
	}
	return false
}

func (h *Handler) redirectToLoginError(w http.ResponseWriter, r *http.Request, redirectURI, msg string) {
	// If redirect_uri is set and allowed, send the error back to the app
	// so it can handle it (e.g. show password fallback modal).
	// redirect_uri is already validated by the caller before reaching here.
	if redirectURI != "" {
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		http.Redirect(w, r, redirectURI+sep+"error="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	// No redirect_uri — show SimpleAuth's own login page with error
	// manual=1 prevents auto-SSO from looping
	u := h.url("/login") + "?error=" + url.QueryEscape(msg) + "&manual=1"
	http.Redirect(w, r, u, http.StatusFound)
}

const hostedLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In — SimpleAuth</title>
<style>
:root {
  --bg: #F7F5F3; --card: #FFFFFF; --text: #1A1F24; --muted: #A59F8A;
  --border: #D6D1CA; --burgundy: #8B153D; --burgundy-hover: #6E1030;
  --error-bg: #F8E4E4; --error-text: #8B153D;
  --gold-light: #F8E08E; --gold: #8F6A2A;
  --input-bg: #FFFFFF; --input-border: #C1A18D;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#222A31;--card:#2E3840;--text:#F2EFEC;--muted:#8A857D;
  --border:#475560;--burgundy:#8B153D;--burgundy-hover:#A42D55;
  --error-bg:rgba(139,21,61,0.2);--error-text:#D4A0A0;
  --gold:#8F6A2A;--input-bg:#2A333B;--input-border:#475560;
}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{width:420px;padding:40px;background:var(--card);border:1px solid var(--border);border-radius:16px;box-shadow:0 4px 16px rgba(51,63,72,0.1)}
.brand{text-align:center;margin-bottom:32px}
.brand h1{font-size:1.5rem;font-weight:700;margin-bottom:4px}
.brand p{color:var(--muted);font-size:0.875rem}
.gold-bar{height:3px;background:linear-gradient(90deg,var(--gold-light),var(--gold-dark));border-radius:999px;margin-bottom:24px}
.error{background:var(--error-bg);color:var(--error-text);padding:12px 16px;border-radius:8px;font-size:0.875rem;margin-bottom:16px}
label{display:block;font-size:0.875rem;font-weight:600;margin-bottom:8px}
input[type=text],input[type=password]{width:100%%;padding:12px 16px;background:var(--input-bg);border:1px solid var(--input-border);border-radius:12px;font-size:0.875rem;font-family:inherit;color:var(--text);margin-bottom:16px}
input:focus{outline:none;border-color:var(--gold);box-shadow:0 0 0 3px rgba(143,106,42,0.2)}
.btn-primary{width:100%%;padding:14px;background:var(--burgundy);color:#fff;border:none;border-radius:8px;font-size:0.95rem;font-weight:600;cursor:pointer;font-family:inherit;text-align:center;text-decoration:none;display:block}
.btn-primary:hover{background:var(--burgundy-hover)}
.btn-submit{width:100%%;padding:12px;background:var(--burgundy);color:#fff;border:none;border-radius:8px;font-size:0.875rem;font-weight:600;cursor:pointer;font-family:inherit}
.btn-submit:hover{background:var(--burgundy-hover)}
.manual-toggle{display:block;width:100%%;text-align:center;padding:10px;color:var(--muted);font-size:0.8rem;cursor:pointer;border:none;background:none;margin-top:16px;font-family:inherit}
.manual-toggle:hover{color:var(--text)}
.manual-form{display:none;margin-top:16px;padding-top:16px;border-top:1px solid var(--border)}
.manual-form.show{display:block}
.sso-status{text-align:center;padding:24px 0;color:var(--muted);font-size:0.9rem}
.sso-status .spinner{display:inline-block;width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--burgundy);border-radius:50%%;animation:spin 0.8s linear infinite;margin-right:8px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
  <div class="brand"><h1>SimpleAuth</h1><p>Sign in to continue</p></div>
  <div class="gold-bar"></div>
  %[2]s
  <div id="sso-section" style="display:none">
    <a href="%[3]s" class="btn-primary" id="sso-btn">Sign in with Single Sign-On</a>
    <button class="manual-toggle" onclick="document.getElementById('manual-form').classList.add('show');this.style.display='none'">
      Or sign in with username and password
    </button>
  </div>
  <div id="auto-sso-status" style="display:none">
    <div class="sso-status"><span class="spinner"></span> Attempting Single Sign-On...</div>
  </div>
  <div id="manual-form" class="manual-form">
    <form method="POST" action="{{BASE_PATH}}/login">
      <input type="hidden" name="redirect_uri" value="%[1]s">
      <input type="hidden" name="_csrf" value="%[4]s">
      <label>Username</label>
      <input type="text" name="username" placeholder="Enter your username" autofocus required>
      <label>Password</label>
      <input type="password" name="password" placeholder="Enter your password" required>
      <button type="submit" class="btn-submit">Sign In</button>
    </form>
  </div>
</div>
<script>
(function(){
  var ssoEnabled = "%[5]s" === "1";
  var autoSSO = "%[6]s" === "1";
  var ssoLink = "%[3]s";
  var hasError = document.querySelector('.error') !== null;
  var manualForm = document.getElementById('manual-form');

  function showManualOnly() {
    manualForm.classList.add('show');
    manualForm.style.borderTop = 'none';
    manualForm.style.marginTop = '0';
    manualForm.style.paddingTop = '0';
  }

  if (ssoEnabled && !hasError) {
    if (autoSSO && ssoLink) {
      // Auto-SSO: show spinner, wait 3s, then redirect
      document.getElementById('auto-sso-status').style.display = 'block';
      setTimeout(function(){ window.location.href = ssoLink; }, 3000);
    } else {
      // Manual SSO: show button + collapsed form
      document.getElementById('sso-section').style.display = 'block';
    }
  } else if (ssoEnabled && hasError) {
    // SSO failed — show SSO button (retry) + manual form expanded
    document.getElementById('sso-section').style.display = 'block';
    manualForm.classList.add('show');
  } else if (hasError) {
    // Error but no SSO — just manual form
    showManualOnly();
  } else {
    // No SSO configured — show manual form directly
    showManualOnly();
  }
})();
</script>
</body>
</html>`
