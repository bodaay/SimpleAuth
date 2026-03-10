package handler

import (
	"fmt"
	"net/http"
)

// handleAccountPage serves the user self-service page.
// Users can view their profile info and change their password.
// GET /account — requires access_token in query or stored in sessionStorage via /login flow.
func (h *Handler) handleAccountPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, h.bp(accountPageHTML))
}

const accountPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>My Account — SimpleAuth</title>
<style>
:root {
  --bg: #FAFAF8; --card: #FFFFFF; --text: #333F48; --muted: #A59F8A;
  --border: #D6D1CA; --burgundy: #8B153D; --burgundy-hover: #6E1030;
  --success-bg: #E8F5E9; --success-text: #2E7D32;
  --error-bg: #F8E4E4; --error-text: #8B153D;
  --gold-light: #F8E08E; --gold-dark: #8F6A2A;
  --tag-bg: #F0EDE8; --tag-text: #6B6760;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#1A1E22;--card:#242A30;--text:#E8E4DE;--muted:#6B6760;
  --border:#3A424A;--burgundy:#A02050;--burgundy-hover:#B82D60;
  --success-bg:rgba(46,125,50,0.2);--success-text:#81C784;
  --error-bg:rgba(139,21,61,0.2);--error-text:#D4A0A0;
  --tag-bg:#2A3038;--tag-text:#A59F8A;
}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:40px 16px}
.container{width:100%;max-width:520px}
.card{padding:32px;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:0 4px 16px rgba(51,63,72,0.1);margin-bottom:24px}
.brand{text-align:center;margin-bottom:24px}
.brand h1{font-size:1.5rem;font-weight:700;margin-bottom:4px}
.brand p{color:var(--muted);font-size:0.875rem}
.gold-bar{height:3px;background:linear-gradient(90deg,var(--gold-light),var(--gold-dark));border-radius:999px;margin-bottom:24px}
h2{font-size:1.125rem;font-weight:600;margin-bottom:16px}
.field{margin-bottom:12px}
.field-label{font-size:0.75rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px}
.field-value{font-size:0.9375rem;word-break:break-word}
.tags{display:flex;flex-wrap:wrap;gap:6px}
.tag{display:inline-block;padding:3px 10px;background:var(--tag-bg);color:var(--tag-text);border-radius:999px;font-size:0.75rem;font-weight:500}
.divider{height:1px;background:var(--border);margin:20px 0}
label{display:block;font-size:0.875rem;font-weight:600;margin-bottom:8px}
input[type="password"]{width:100%;padding:12px 16px;background:var(--card);border:1px solid var(--border);border-radius:8px;font-size:0.875rem;font-family:inherit;color:var(--text);margin-bottom:16px}
input[type="password"]:focus{outline:none;border-color:var(--burgundy);box-shadow:0 0 0 3px rgba(139,21,61,0.15)}
button{width:100%;padding:12px;background:var(--burgundy);color:#fff;border:none;border-radius:8px;font-size:0.875rem;font-weight:600;cursor:pointer;font-family:inherit}
button:hover{background:var(--burgundy-hover)}
button:disabled{opacity:0.6;cursor:not-allowed}
.msg{padding:12px 16px;border-radius:8px;font-size:0.875rem;margin-bottom:16px;display:none}
.msg.success{background:var(--success-bg);color:var(--success-text);display:block}
.msg.error{background:var(--error-bg);color:var(--error-text);display:block}
.login-prompt{text-align:center;padding:60px 32px}
.login-prompt p{color:var(--muted);margin-bottom:16px}
.login-prompt a{color:var(--burgundy);font-weight:600;text-decoration:none}
.login-prompt a:hover{text-decoration:underline}
.logout-link{display:block;text-align:center;margin-top:8px;color:var(--muted);font-size:0.8125rem;text-decoration:none}
.logout-link:hover{color:var(--burgundy)}
.ldap-note{color:var(--muted);font-size:0.8125rem;font-style:italic}
#loading{text-align:center;color:var(--muted);padding:40px}
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <div class="brand"><h1>SimpleAuth</h1><p>My Account</p></div>
    <div class="gold-bar"></div>

    <div id="loading">Loading...</div>

    <div id="login-prompt" style="display:none" class="login-prompt">
      <p>You need to sign in to view your account.</p>
      <a href="{{BASE_PATH}}/login">Sign In</a>
    </div>

    <div id="profile" style="display:none">
      <h2>Profile</h2>
      <div class="field"><div class="field-label">Display Name</div><div class="field-value" id="p-name">—</div></div>
      <div class="field"><div class="field-label">Email</div><div class="field-value" id="p-email">—</div></div>
      <div class="field"><div class="field-label">Username</div><div class="field-value" id="p-username">—</div></div>
      <div class="field" id="p-dept-row"><div class="field-label">Department</div><div class="field-value" id="p-dept">—</div></div>
      <div class="field" id="p-company-row"><div class="field-label">Company</div><div class="field-value" id="p-company">—</div></div>
      <div class="field" id="p-title-row"><div class="field-label">Job Title</div><div class="field-value" id="p-title">—</div></div>
      <div class="field" id="p-roles-row"><div class="field-label">Roles</div><div class="tags" id="p-roles"></div></div>
    </div>
  </div>

  <div id="password-card" class="card" style="display:none">
    <h2>Change Password</h2>
    <div id="pw-msg" class="msg"></div>
    <div id="pw-ldap" style="display:none" class="ldap-note">
      Your password is managed by your organization's directory (LDAP/Active Directory). Contact your IT administrator to change it.
    </div>
    <form id="pw-form" style="display:none">
      <label for="current_password">Current Password</label>
      <input type="password" id="current_password" placeholder="Enter current password" autocomplete="current-password">
      <label for="new_password">New Password</label>
      <input type="password" id="new_password" placeholder="Enter new password (min 6 characters)" autocomplete="new-password" required>
      <label for="confirm_password">Confirm New Password</label>
      <input type="password" id="confirm_password" placeholder="Confirm new password" autocomplete="new-password" required>
      <button type="submit" id="pw-btn">Update Password</button>
    </form>
  </div>

  <a href="#" id="logout-link" class="logout-link" style="display:none">Sign Out</a>
</div>

<script>
(function() {
  var token = null;
  var userInfo = null;

  // Try to get token from fragment (redirected from /login), query, or sessionStorage
  if (location.hash) {
    var params = new URLSearchParams(location.hash.substring(1));
    if (params.get('access_token')) {
      token = params.get('access_token');
      var rt = params.get('refresh_token');
      try {
        sessionStorage.setItem('sa_access_token', token);
        if (rt) sessionStorage.setItem('sa_refresh_token', rt);
      } catch(e) {}
      // Clean up URL
      history.replaceState(null, '', '{{BASE_PATH}}/account');
    }
  }
  if (!token) {
    var qp = new URLSearchParams(location.search);
    if (qp.get('access_token')) token = qp.get('access_token');
  }
  if (!token) {
    try { token = sessionStorage.getItem('sa_access_token'); } catch(e) {}
  }

  if (!token) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('login-prompt').style.display = 'block';
    return;
  }

  // Fetch user info
  fetch('{{BASE_PATH}}/api/auth/userinfo', {
    headers: { 'Authorization': 'Bearer ' + token }
  })
  .then(function(res) {
    if (!res.ok) throw new Error('unauthorized');
    return res.json();
  })
  .then(function(data) {
    userInfo = data;
    document.getElementById('loading').style.display = 'none';
    document.getElementById('profile').style.display = 'block';
    document.getElementById('password-card').style.display = 'block';
    document.getElementById('logout-link').style.display = 'block';

    // Populate profile
    setText('p-name', data.display_name);
    setText('p-email', data.email);
    setText('p-username', data.preferred_username || data.email || '—');

    showIfPresent('p-dept-row', 'p-dept', data.department);
    showIfPresent('p-company-row', 'p-company', data.company);
    showIfPresent('p-title-row', 'p-title', data.job_title);

    var rolesEl = document.getElementById('p-roles');
    var roles = data.roles || [];
    if (roles.length > 0) {
      rolesEl.innerHTML = roles.map(function(r) { return '<span class="tag">' + esc(r) + '</span>'; }).join('');
    } else {
      document.getElementById('p-roles-row').style.display = 'none';
    }

    // Check if user is LDAP-only (no local password)
    var isLDAP = data.auth_source === 'ldap';
    if (isLDAP) {
      document.getElementById('pw-ldap').style.display = 'block';
      document.getElementById('pw-form').style.display = 'none';
    } else {
      document.getElementById('pw-form').style.display = 'block';
    }
  })
  .catch(function() {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('login-prompt').style.display = 'block';
    try { sessionStorage.removeItem('sa_access_token'); } catch(e) {}
  });

  // Password change form
  document.getElementById('pw-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var msg = document.getElementById('pw-msg');
    msg.className = 'msg';
    msg.style.display = 'none';

    var newPw = document.getElementById('new_password').value;
    var confirmPw = document.getElementById('confirm_password').value;
    var currentPw = document.getElementById('current_password').value;

    if (newPw.length < 6) {
      showMsg('error', 'New password must be at least 6 characters.');
      return;
    }
    if (newPw !== confirmPw) {
      showMsg('error', 'Passwords do not match.');
      return;
    }

    var btn = document.getElementById('pw-btn');
    btn.disabled = true;
    btn.textContent = 'Updating...';

    fetch('{{BASE_PATH}}/api/auth/reset-password', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        current_password: currentPw,
        new_password: newPw
      })
    })
    .then(function(res) { return res.json().then(function(d) { return { ok: res.ok, data: d }; }); })
    .then(function(result) {
      btn.disabled = false;
      btn.textContent = 'Update Password';
      if (result.ok) {
        showMsg('success', 'Password updated successfully.');
        document.getElementById('current_password').value = '';
        document.getElementById('new_password').value = '';
        document.getElementById('confirm_password').value = '';
      } else {
        showMsg('error', result.data.error || 'Failed to update password.');
      }
    })
    .catch(function() {
      btn.disabled = false;
      btn.textContent = 'Update Password';
      showMsg('error', 'Network error. Please try again.');
    });
  });

  // Logout
  document.getElementById('logout-link').addEventListener('click', function(e) {
    e.preventDefault();
    try {
      sessionStorage.removeItem('sa_access_token');
      sessionStorage.removeItem('sa_refresh_token');
    } catch(ex) {}
    location.href = '{{BASE_PATH}}/login';
  });

  function setText(id, val) {
    document.getElementById(id).textContent = val || '—';
  }
  function showIfPresent(rowId, valId, val) {
    if (!val) { document.getElementById(rowId).style.display = 'none'; return; }
    document.getElementById(valId).textContent = val;
  }
  function showMsg(type, text) {
    var msg = document.getElementById('pw-msg');
    msg.className = 'msg ' + type;
    msg.textContent = text;
    msg.style.display = 'block';
  }
  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
})();
</script>
</body>
</html>`
