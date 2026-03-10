package handler

import (
	"fmt"
	"net/http"
	"net/url"
)

// handleHostedLoginPage serves the hosted login form.
// Apps redirect users here: GET /login?redirect_uri=Y
func (h *Handler) handleHostedLoginPage(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	errorMsg := r.URL.Query().Get("error")

	// Validate redirect_uri
	if redirectURI != "" && !isAllowedRedirect(h.cfg.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	errorHTML := ""
	if errorMsg != "" {
		errorHTML = `<div class="error">` + errorMsg + `</div>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, hostedLoginHTML, redirectURI, errorHTML)
}

// handleHostedLoginSubmit processes the hosted login form submission.
func (h *Handler) handleHostedLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == "" || password == "" {
		redirectToLoginError(w, r, redirectURI, "Username and password are required")
		return
	}

	// Validate redirect_uri
	if redirectURI != "" && !isAllowedRedirect(h.cfg.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	ip := getClientIP(r)

	if !h.loginLimiter.allow(ip) {
		redirectToLoginError(w, r, redirectURI, "Too many login attempts. Please try again later.")
		return
	}

	userGUID, ldapGroups, err := h.authenticateUser(username, password)
	if err != nil {
		h.audit("login_failed", "", ip, map[string]interface{}{
			"username": username, "reason": err.Error(), "flow": "hosted",
		})
		redirectToLoginError(w, r, redirectURI, "Invalid credentials")
		return
	}

	user, err := h.store.ResolveUser(userGUID)
	if err != nil {
		redirectToLoginError(w, r, redirectURI, "User not found")
		return
	}
	if user.Disabled {
		redirectToLoginError(w, r, redirectURI, "Account disabled")
		return
	}

	// Assign default roles if needed
	h.assignDefaultRoles(user.GUID)

	// Issue tokens
	roles, _ := h.store.GetUserRoles(user.GUID)
	perms := h.resolveUserPermissions(user.GUID, roles)
	accessToken, refreshToken, expiresIn, err := h.issueTokenPair(user, roles, perms, ldapGroups)
	if err != nil {
		redirectToLoginError(w, r, redirectURI, "Token generation failed")
		return
	}

	h.audit("login_success", user.GUID, ip, map[string]interface{}{"flow": "hosted"})

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
	http.Redirect(w, r, "/account#"+fragment, http.StatusFound)
}

func isAllowedRedirect(allowed []string, uri string) bool {
	if len(allowed) == 0 {
		return true // No restrictions configured
	}
	for _, a := range allowed {
		if a == uri {
			return true
		}
	}
	return false
}

func redirectToLoginError(w http.ResponseWriter, r *http.Request, redirectURI, msg string) {
	u := "/login?error=" + url.QueryEscape(msg)
	if redirectURI != "" {
		u += "&redirect_uri=" + url.QueryEscape(redirectURI)
	}
	http.Redirect(w, r, u, http.StatusFound)
}

const hostedLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In — SimpleAuth</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #FAFAF8; --card: #FFFFFF; --text: #333F48; --muted: #A59F8A;
  --border: #D6D1CA; --burgundy: #8B153D; --burgundy-hover: #6E1030;
  --error-bg: #F8E4E4; --error-text: #8B153D;
  --gold-light: #F8E08E; --gold-dark: #8F6A2A;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#1A1E22;--card:#242A30;--text:#E8E4DE;--muted:#6B6760;
  --border:#3A424A;--burgundy:#A02050;--burgundy-hover:#B82D60;
  --error-bg:rgba(139,21,61,0.2);--error-text:#D4A0A0;
}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{width:400px;padding:40px;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:0 4px 16px rgba(51,63,72,0.1)}
.brand{text-align:center;margin-bottom:32px}
.brand h1{font-size:1.5rem;font-weight:700;margin-bottom:4px}
.brand p{color:var(--muted);font-size:0.875rem}
.gold-bar{height:3px;background:linear-gradient(90deg,var(--gold-light),var(--gold-dark));border-radius:999px;margin-bottom:24px}
.error{background:var(--error-bg);color:var(--error-text);padding:12px 16px;border-radius:8px;font-size:0.875rem;margin-bottom:16px}
label{display:block;font-size:0.875rem;font-weight:600;margin-bottom:8px}
input{width:100%%;padding:12px 16px;background:var(--card);border:1px solid var(--border);border-radius:8px;font-size:0.875rem;font-family:inherit;color:var(--text);margin-bottom:16px}
input:focus{outline:none;border-color:var(--burgundy);box-shadow:0 0 0 3px rgba(139,21,61,0.15)}
button{width:100%%;padding:12px;background:var(--burgundy);color:#fff;border:none;border-radius:8px;font-size:0.875rem;font-weight:600;cursor:pointer;font-family:inherit}
button:hover{background:var(--burgundy-hover)}
</style>
</head>
<body>
<div class="card">
  <div class="brand"><h1>SimpleAuth</h1><p>Sign in to continue</p></div>
  <div class="gold-bar"></div>
  %[2]s
  <form method="POST" action="/login">
    <input type="hidden" name="redirect_uri" value="%[1]s">
    <label>Username</label>
    <input type="text" name="username" placeholder="Enter your username" autofocus required>
    <label>Password</label>
    <input type="password" name="password" placeholder="Enter your password" required>
    <button type="submit">Sign In</button>
  </form>
</div>
<script>
// If already logged in, show account link
try{if(sessionStorage.getItem('sa_access_token')){
  document.querySelector('.brand p').innerHTML='Sign in to continue or <a href="/account" style="color:var(--burgundy);font-weight:600">go to your account</a>';
}}catch(e){}
</script>
</body>
</html>`
