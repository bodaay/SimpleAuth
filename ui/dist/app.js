import { h, render, Component } from 'https://esm.sh/preact@10.19.3';
import { useState, useEffect, useCallback } from 'https://esm.sh/preact@10.19.3/hooks';
import htm from 'https://esm.sh/htm@3.1.1';

const html = htm.bind(h);

// === API Helper ===
const API_KEY_STORAGE = 'simpleauth_admin_key';

function getApiKey() { return localStorage.getItem(API_KEY_STORAGE) || ''; }
function setApiKey(key) { localStorage.setItem(API_KEY_STORAGE, key); }

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Authorization': `Bearer ${getApiKey()}`, 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// === Icons (inline SVG) ===
const icons = {
  dashboard: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>`,
  users: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  apps: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="9" height="9" rx="2"/><rect x="13" y="2" width="9" height="9" rx="2"/><rect x="2" y="13" width="9" height="9" rx="2"/><rect x="13" y="13" width="9" height="9" rx="2"/></svg>`,
  ldap: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>`,
  mappings: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
  impersonate: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/><line x1="2" y1="2" x2="22" y2="22" opacity="0.3"/></svg>`,
  audit: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`,
  sun: html`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
  moon: html`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  close: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  plus: html`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  copy: html`<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
};

// === Toast ===
let toastTimeout;
function Toast({ message, type }) {
  if (!message) return null;
  return html`<div class="toast toast-${type}">${message}</div>`;
}

// === Modal ===
function Modal({ title, onClose, children }) {
  return html`
    <div class="modal-overlay" onClick=${(e) => e.target === e.currentTarget && onClose()}>
      <div class="modal">
        <div class="modal-header">
          <h3>${title}</h3>
          <button class="btn-icon" onClick=${onClose}>${icons.close}</button>
        </div>
        ${children}
      </div>
    </div>
  `;
}

// === Dashboard ===
function Dashboard() {
  const [stats, setStats] = useState({ users: 0, apps: 0, events: [] });
  useEffect(() => {
    Promise.all([
      api('GET', '/api/admin/users'),
      api('GET', '/api/admin/apps'),
      api('GET', '/api/admin/audit?limit=10'),
    ]).then(([users, apps, events]) => {
      setStats({ users: users.length, apps: apps.length, events });
    }).catch(() => {});
  }, []);

  return html`
    <div class="page-header"><h2>Dashboard</h2></div>
    <div class="gold-bar" style="margin-bottom: var(--sp-8)"></div>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Users</div>
        <div class="stat-value">${stats.users}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Registered Apps</div>
        <div class="stat-value">${stats.apps}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Recent Events</div>
        <div class="stat-value">${stats.events.length}</div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><h3>Recent Activity</h3></div>
      ${stats.events.length === 0
        ? html`<div class="empty-state"><p>No recent activity</p></div>`
        : html`
          <div class="table-wrap">
            <table>
              <thead><tr><th>Event</th><th>Actor</th><th>Time</th><th>Details</th></tr></thead>
              <tbody>
                ${stats.events.map(e => html`
                  <tr>
                    <td><span class="badge ${e.event.includes('fail') ? 'badge-error' : e.event.includes('success') ? 'badge-success' : ''}">${e.event}</span></td>
                    <td><span class="guid">${(e.actor || '').substring(0, 8)}...</span></td>
                    <td style="font-size:0.75rem;color:var(--text-muted)">${new Date(e.timestamp).toLocaleString()}</td>
                    <td style="font-size:0.75rem;color:var(--text-secondary)">${JSON.stringify(e.data || {})}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          </div>
        `
      }
    </div>
  `;
}

// === Users Page ===
function UsersPage() {
  const [users, setUsers] = useState([]);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [toast, setToast] = useState(null);

  const load = () => api('GET', '/api/admin/users').then(setUsers).catch(() => {});
  useEffect(load, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => setToast(null), 3000);
  };

  const createUser = async () => {
    try {
      await api('POST', '/api/admin/users', form);
      setModal(null);
      setForm({});
      load();
      showToast('User created');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const deleteUser = async (guid) => {
    if (!confirm('Delete this user?')) return;
    try {
      await api('DELETE', `/api/admin/users/${guid}`);
      load();
      showToast('User deleted');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const toggleDisabled = async (user) => {
    try {
      await api('PUT', `/api/admin/users/${user.guid}/disabled`, { disabled: !user.disabled });
      load();
      showToast(user.disabled ? 'User enabled' : 'User disabled');
    } catch (e) { showToast(e.message, 'error'); }
  };

  return html`
    <div class="page-header">
      <h2>Users</h2>
      <div class="page-header-actions">
        <button class="btn btn-primary" onClick=${() => { setForm({}); setModal('create'); }}>${icons.plus} New User</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>GUID</th><th>Display Name</th><th>Email</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
        <tbody>
          ${users.length === 0
            ? html`<tr><td colspan="6"><div class="empty-state"><p>No users yet</p></div></td></tr>`
            : users.map(u => html`
              <tr>
                <td><span class="guid">${u.guid.substring(0, 8)}...</span></td>
                <td>${u.display_name || '—'}</td>
                <td style="color:var(--text-secondary)">${u.email || '—'}</td>
                <td>
                  ${u.merged_into
                    ? html`<span class="badge badge-warning">Merged</span>`
                    : u.disabled
                      ? html`<span class="badge badge-error">Disabled</span>`
                      : html`<span class="badge badge-success">Active</span>`
                  }
                </td>
                <td style="font-size:0.75rem;color:var(--text-muted)">${new Date(u.created_at).toLocaleDateString()}</td>
                <td>
                  <button class="btn btn-sm btn-secondary" onClick=${() => toggleDisabled(u)}>${u.disabled ? 'Enable' : 'Disable'}</button>
                  <button class="btn btn-sm btn-danger" style="margin-left:var(--sp-1)" onClick=${() => deleteUser(u.guid)}>Delete</button>
                </td>
              </tr>
            `)
          }
        </tbody>
      </table>
    </div>

    ${modal === 'create' && html`
      <${Modal} title="Create User" onClose=${() => setModal(null)}>
        <div class="form-group">
          <label class="form-label">Username</label>
          <input class="form-input" value=${form.username || ''} onInput=${e => setForm({ ...form, username: e.target.value })} placeholder="admin" />
        </div>
        <div class="form-group">
          <label class="form-label">Password</label>
          <input class="form-input" type="password" value=${form.password || ''} onInput=${e => setForm({ ...form, password: e.target.value })} />
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Display Name</label>
            <input class="form-input" value=${form.display_name || ''} onInput=${e => setForm({ ...form, display_name: e.target.value })} />
          </div>
          <div class="form-group">
            <label class="form-label">Email</label>
            <input class="form-input" type="email" value=${form.email || ''} onInput=${e => setForm({ ...form, email: e.target.value })} />
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${createUser}>Create User</button>
        </div>
      <//>
    `}
    ${toast && html`<${Toast} ...${toast} />`}
  `;
}

// === Apps Page ===
function AppsPage() {
  const [apps, setApps] = useState([]);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [toast, setToast] = useState(null);

  const load = () => api('GET', '/api/admin/apps').then(setApps).catch(() => {});
  useEffect(load, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => setToast(null), 3000);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    showToast('Copied to clipboard');
  };

  const createApp = async () => {
    try {
      const result = await api('POST', '/api/admin/apps', {
        name: form.name,
        description: form.description,
        redirect_uris: form.redirect_uris ? form.redirect_uris.split('\n').filter(Boolean) : [],
      });
      setModal(null);
      setForm({});
      load();
      showToast(`App created! API Key: ${result.api_key}`);
    } catch (e) { showToast(e.message, 'error'); }
  };

  const rotateKey = async (appId) => {
    if (!confirm('Rotate API key? The old key will stop working immediately.')) return;
    try {
      const result = await api('POST', `/api/admin/apps/${appId}/rotate-key`);
      load();
      showToast(`New key: ${result.new_api_key}`);
    } catch (e) { showToast(e.message, 'error'); }
  };

  const deleteApp = async (appId) => {
    if (!confirm('Delete this app?')) return;
    try {
      await api('DELETE', `/api/admin/apps/${appId}`);
      load();
      showToast('App deleted');
    } catch (e) { showToast(e.message, 'error'); }
  };

  return html`
    <div class="page-header">
      <h2>Apps</h2>
      <div class="page-header-actions">
        <button class="btn btn-primary" onClick=${() => { setForm({}); setModal('create'); }}>${icons.plus} Register App</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>App ID</th><th>Name</th><th>Description</th><th>API Key</th><th>Created</th><th>Actions</th></tr></thead>
        <tbody>
          ${apps.length === 0
            ? html`<tr><td colspan="6"><div class="empty-state"><p>No apps registered</p></div></td></tr>`
            : apps.map(a => html`
              <tr>
                <td><span class="guid">${a.app_id}</span></td>
                <td style="font-weight:600">${a.name}</td>
                <td style="color:var(--text-secondary);font-size:0.875rem">${a.description || '—'}</td>
                <td>
                  <span class="guid">${a.api_key.substring(0, 12)}...</span>
                  <button class="btn-icon" onClick=${() => copyToClipboard(a.api_key)} title="Copy">${icons.copy}</button>
                </td>
                <td style="font-size:0.75rem;color:var(--text-muted)">${new Date(a.created_at).toLocaleDateString()}</td>
                <td>
                  <button class="btn btn-sm btn-secondary" onClick=${() => rotateKey(a.app_id)}>Rotate Key</button>
                  <button class="btn btn-sm btn-danger" style="margin-left:var(--sp-1)" onClick=${() => deleteApp(a.app_id)}>Delete</button>
                </td>
              </tr>
            `)
          }
        </tbody>
      </table>
    </div>

    ${modal === 'create' && html`
      <${Modal} title="Register App" onClose=${() => setModal(null)}>
        <div class="form-group">
          <label class="form-label">App Name</label>
          <input class="form-input" value=${form.name || ''} onInput=${e => setForm({ ...form, name: e.target.value })} placeholder="chat-app" />
        </div>
        <div class="form-group">
          <label class="form-label">Description</label>
          <input class="form-input" value=${form.description || ''} onInput=${e => setForm({ ...form, description: e.target.value })} placeholder="Internal chat application" />
        </div>
        <div class="form-group">
          <label class="form-label">Redirect URIs</label>
          <textarea class="form-textarea" value=${form.redirect_uris || ''} onInput=${e => setForm({ ...form, redirect_uris: e.target.value })} placeholder="https://chat.corp.local/callback\nhttp://localhost:3000/callback"></textarea>
          <div class="form-help">One per line</div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${createApp}>Register App</button>
        </div>
      <//>
    `}
    ${toast && html`<${Toast} ...${toast} />`}
  `;
}

// === LDAP Providers Page ===
function LDAPPage() {
  const [providers, setProviders] = useState([]);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [testResult, setTestResult] = useState(null);
  const [toast, setToast] = useState(null);

  const load = () => api('GET', '/api/admin/ldap').then(setProviders).catch(() => {});
  useEffect(load, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => setToast(null), 3000);
  };

  const createProvider = async () => {
    try {
      await api('POST', '/api/admin/ldap', {
        ...form,
        use_tls: form.use_tls === 'true',
        skip_tls_verify: form.skip_tls_verify === 'true',
        priority: parseInt(form.priority) || 0,
      });
      setModal(null);
      setForm({});
      load();
      showToast('LDAP provider added');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const testConnection = async (providerId) => {
    try {
      const result = await api('POST', `/api/admin/ldap/${providerId}/test`);
      showToast(result.status === 'ok' ? 'Connection successful' : `Error: ${result.error}`, result.status === 'ok' ? 'success' : 'error');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const autoDiscover = async () => {
    try {
      const result = await api('POST', '/api/admin/ldap/auto-discover', {
        domain: form.domain,
        bind_dn: form.bind_dn,
        bind_password: form.bind_password,
        provider_id: form.provider_id,
        save: true,
      });
      setModal(null);
      setForm({});
      load();
      showToast(`Discovered ${result.discovered_dcs?.length || 0} DCs, provider saved`);
    } catch (e) { showToast(e.message, 'error'); }
  };

  const deleteProvider = async (id) => {
    if (!confirm('Delete this LDAP provider?')) return;
    try {
      await api('DELETE', `/api/admin/ldap/${id}`);
      load();
      showToast('Provider deleted');
    } catch (e) { showToast(e.message, 'error'); }
  };

  return html`
    <div class="page-header">
      <h2>LDAP Providers</h2>
      <div class="page-header-actions">
        <button class="btn btn-secondary" onClick=${() => { setForm({}); setModal('discover'); }}>Auto-Discover</button>
        <button class="btn btn-primary" onClick=${() => { setForm({ user_filter: '(sAMAccountName={{username}})', display_name_attr: 'displayName', email_attr: 'mail', groups_attr: 'memberOf' }); setModal('create'); }}>${icons.plus} Add Provider</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>ID</th><th>Name</th><th>URL</th><th>Base DN</th><th>Priority</th><th>Actions</th></tr></thead>
        <tbody>
          ${providers.length === 0
            ? html`<tr><td colspan="6"><div class="empty-state"><p>No LDAP providers configured</p></div></td></tr>`
            : providers.map(p => html`
              <tr>
                <td><span class="guid">${p.provider_id}</span></td>
                <td style="font-weight:600">${p.name}</td>
                <td style="color:var(--text-secondary);font-size:0.875rem">${p.url}</td>
                <td style="font-size:0.75rem;color:var(--text-muted)">${p.base_dn}</td>
                <td>${p.priority}</td>
                <td>
                  <button class="btn btn-sm btn-secondary" onClick=${() => testConnection(p.provider_id)}>Test</button>
                  <button class="btn btn-sm btn-danger" style="margin-left:var(--sp-1)" onClick=${() => deleteProvider(p.provider_id)}>Delete</button>
                </td>
              </tr>
            `)
          }
        </tbody>
      </table>
    </div>

    ${modal === 'create' && html`
      <${Modal} title="Add LDAP Provider" onClose=${() => setModal(null)}>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Provider ID</label>
            <input class="form-input" value=${form.provider_id || ''} onInput=${e => setForm({ ...form, provider_id: e.target.value })} placeholder="corp" />
          </div>
          <div class="form-group">
            <label class="form-label">Name</label>
            <input class="form-input" value=${form.name || ''} onInput=${e => setForm({ ...form, name: e.target.value })} placeholder="Corporate AD" />
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">URL</label>
          <input class="form-input" value=${form.url || ''} onInput=${e => setForm({ ...form, url: e.target.value })} placeholder="ldap://dc1.corp.local:389" />
        </div>
        <div class="form-group">
          <label class="form-label">Base DN</label>
          <input class="form-input" value=${form.base_dn || ''} onInput=${e => setForm({ ...form, base_dn: e.target.value })} placeholder="DC=corp,DC=local" />
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Bind DN</label>
            <input class="form-input" value=${form.bind_dn || ''} onInput=${e => setForm({ ...form, bind_dn: e.target.value })} />
          </div>
          <div class="form-group">
            <label class="form-label">Bind Password</label>
            <input class="form-input" type="password" value=${form.bind_password || ''} onInput=${e => setForm({ ...form, bind_password: e.target.value })} />
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">User Filter</label>
          <input class="form-input" value=${form.user_filter || ''} onInput=${e => setForm({ ...form, user_filter: e.target.value })} />
        </div>
        <div class="form-group">
          <label class="form-label">Priority</label>
          <input class="form-input" type="number" value=${form.priority || '0'} onInput=${e => setForm({ ...form, priority: e.target.value })} />
          <div class="form-help">Lower = tried first</div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${createProvider}>Add Provider</button>
        </div>
      <//>
    `}

    ${modal === 'discover' && html`
      <${Modal} title="Auto-Discover LDAP" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">Enter a domain name and service account credentials. SimpleAuth will auto-configure via DNS SRV and RootDSE.</p>
        <div class="form-group">
          <label class="form-label">Domain</label>
          <input class="form-input" value=${form.domain || ''} onInput=${e => setForm({ ...form, domain: e.target.value })} placeholder="corp.local" />
        </div>
        <div class="form-group">
          <label class="form-label">Provider ID (optional)</label>
          <input class="form-input" value=${form.provider_id || ''} onInput=${e => setForm({ ...form, provider_id: e.target.value })} placeholder="corp" />
        </div>
        <div class="form-group">
          <label class="form-label">Bind DN</label>
          <input class="form-input" value=${form.bind_dn || ''} onInput=${e => setForm({ ...form, bind_dn: e.target.value })} placeholder="CN=svc-auth,OU=Service Accounts,DC=corp,DC=local" />
        </div>
        <div class="form-group">
          <label class="form-label">Bind Password</label>
          <input class="form-input" type="password" value=${form.bind_password || ''} onInput=${e => setForm({ ...form, bind_password: e.target.value })} />
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${autoDiscover}>Discover & Save</button>
        </div>
      <//>
    `}
    ${toast && html`<${Toast} ...${toast} />`}
  `;
}

// === Impersonate Page ===
function ImpersonatePage() {
  const [users, setUsers] = useState([]);
  const [apps, setApps] = useState([]);
  const [selectedUser, setSelectedUser] = useState('');
  const [selectedApp, setSelectedApp] = useState('');
  const [result, setResult] = useState(null);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    api('GET', '/api/admin/users').then(setUsers).catch(() => {});
    api('GET', '/api/admin/apps').then(setApps).catch(() => {});
  }, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => setToast(null), 3000);
  };

  const impersonate = async () => {
    if (!selectedUser) { showToast('Select a user', 'error'); return; }
    try {
      const res = await api('POST', '/api/auth/impersonate', {
        target_guid: selectedUser,
        app_id: selectedApp,
      });
      setResult(res);
    } catch (e) { showToast(e.message, 'error'); }
  };

  return html`
    <div class="page-header"><h2>Impersonate User</h2></div>
    <div class="card" style="max-width:600px">
      <div class="form-group">
        <label class="form-label">User</label>
        <select class="form-select" value=${selectedUser} onChange=${e => setSelectedUser(e.target.value)}>
          <option value="">Select a user...</option>
          ${users.map(u => html`<option value=${u.guid}>${u.display_name || u.guid} (${u.email || 'no email'})</option>`)}
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">App (optional)</label>
        <select class="form-select" value=${selectedApp} onChange=${e => setSelectedApp(e.target.value)}>
          <option value="">No app scope</option>
          ${apps.map(a => html`<option value=${a.app_id}>${a.name} (${a.app_id})</option>`)}
        </select>
      </div>
      <button class="btn btn-primary" onClick=${impersonate}>Generate Impersonated Token</button>

      ${result && html`
        <div style="margin-top:var(--sp-6)">
          <div class="gold-bar" style="margin-bottom:var(--sp-4)"></div>
          <label class="form-label">Access Token</label>
          <div style="position:relative">
            <textarea class="form-textarea" style="font-family:var(--font-mono);font-size:0.75rem;height:120px" readonly value=${result.access_token}></textarea>
            <button class="btn-icon" style="position:absolute;top:var(--sp-2);right:var(--sp-2)" onClick=${() => { navigator.clipboard.writeText(result.access_token); showToast('Copied'); }}>${icons.copy}</button>
          </div>
          <div style="display:flex;gap:var(--sp-4);margin-top:var(--sp-2)">
            <span class="badge badge-warning">Impersonated</span>
            <span class="badge">Expires in ${result.expires_in}s</span>
          </div>
        </div>
      `}
    </div>
    ${toast && html`<${Toast} ...${toast} />`}
  `;
}

// === Identity Mappings Page ===
function MappingsPage() {
  const [mappings, setMappings] = useState([]);
  const [users, setUsers] = useState({});
  const [search, setSearch] = useState('');
  const [providerFilter, setProviderFilter] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [newMapping, setNewMapping] = useState({ provider: '', external_id: '', user_guid: '' });
  const [toast, setToast] = useState({ message: '', type: '' });

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => setToast({ message: '', type: '' }), 3000);
  };

  const load = () => {
    Promise.all([
      api('GET', '/api/admin/mappings'),
      api('GET', '/api/admin/users'),
    ]).then(([m, u]) => {
      setMappings(m);
      const userMap = {};
      u.forEach(user => { userMap[user.guid] = user; });
      setUsers(userMap);
    }).catch(() => {});
  };
  useEffect(() => load(), []);

  const providers = [...new Set(mappings.map(m => m.provider))].sort();

  const filtered = mappings.filter(m => {
    if (providerFilter && m.provider !== providerFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const user = users[m.user_guid];
      const userName = user ? (user.display_name || user.email || '').toLowerCase() : '';
      return m.provider.toLowerCase().includes(q) ||
             m.external_id.toLowerCase().includes(q) ||
             m.user_guid.toLowerCase().includes(q) ||
             userName.includes(q);
    }
    return true;
  });

  const addMapping = async () => {
    if (!newMapping.provider || !newMapping.external_id || !newMapping.user_guid) return;
    try {
      await api('PUT', `/api/admin/users/${newMapping.user_guid}/mappings`, {
        provider: newMapping.provider, external_id: newMapping.external_id,
      });
      showToast('Mapping created');
      setShowAdd(false);
      setNewMapping({ provider: '', external_id: '', user_guid: '' });
      load();
    } catch (e) { showToast(e.message, 'error'); }
  };

  const deleteMapping = async (m) => {
    if (!confirm(`Delete mapping ${m.provider}:${m.external_id}?`)) return;
    try {
      await api('DELETE', `/api/admin/users/${m.user_guid}/mappings/${encodeURIComponent(m.provider)}/${encodeURIComponent(m.external_id)}`);
      showToast('Mapping deleted');
      load();
    } catch (e) { showToast(e.message, 'error'); }
  };

  const allUsers = Object.values(users);

  return html`
    <${Toast} message=${toast.message} type=${toast.type} />
    <div class="page-header">
      <h2>Identity Mappings</h2>
      <button class="btn btn-primary btn-sm" onClick=${() => setShowAdd(true)}>${icons.plus} Add Mapping</button>
    </div>
    <div style="display:flex;gap:var(--sp-2);margin-bottom:var(--sp-4);flex-wrap:wrap;align-items:center">
      <input class="form-input" style="max-width:300px" placeholder="Search mappings..." value=${search} onInput=${e => setSearch(e.target.value)} />
      <button class="btn btn-sm ${!providerFilter ? 'btn-primary' : 'btn-secondary'}" onClick=${() => setProviderFilter('')}>All</button>
      ${providers.map(p => html`
        <button class="btn btn-sm ${providerFilter === p ? 'btn-primary' : 'btn-secondary'}" onClick=${() => setProviderFilter(p)}>${p}</button>
      `)}
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Provider</th><th>External ID</th><th>User</th><th>GUID</th><th></th></tr></thead>
        <tbody>
          ${filtered.length === 0
            ? html`<tr><td colspan="5"><div class="empty-state"><p>No identity mappings found</p></div></td></tr>`
            : filtered.map(m => {
                const user = users[m.user_guid];
                return html`
                  <tr>
                    <td><span class="badge">${m.provider}</span></td>
                    <td style="font-family:var(--font-mono);font-size:0.8rem">${m.external_id}</td>
                    <td>${user ? (user.display_name || user.email || '—') : '—'}</td>
                    <td><span class="guid">${m.user_guid.substring(0, 12)}...</span></td>
                    <td><button class="btn btn-sm btn-danger" onClick=${() => deleteMapping(m)}>Delete</button></td>
                  </tr>
                `;
              })
          }
        </tbody>
      </table>
    </div>
    <div style="margin-top:var(--sp-2);color:var(--text-muted);font-size:0.8rem">${filtered.length} mapping${filtered.length !== 1 ? 's' : ''}</div>

    ${showAdd && html`
      <${Modal} title="Add Identity Mapping" onClose=${() => setShowAdd(false)}>
        <div class="form-group">
          <label class="form-label">Provider</label>
          <input class="form-input" value=${newMapping.provider} onInput=${e => setNewMapping({ ...newMapping, provider: e.target.value })} placeholder="e.g. ldap, kerberos, saml" />
        </div>
        <div class="form-group">
          <label class="form-label">External ID</label>
          <input class="form-input" value=${newMapping.external_id} onInput=${e => setNewMapping({ ...newMapping, external_id: e.target.value })} placeholder="e.g. user@domain.com" />
        </div>
        <div class="form-group">
          <label class="form-label">User</label>
          <select class="form-input" value=${newMapping.user_guid} onChange=${e => setNewMapping({ ...newMapping, user_guid: e.target.value })}>
            <option value="">Select user...</option>
            ${allUsers.map(u => html`<option value=${u.guid}>${u.display_name || u.email || u.guid}</option>`)}
          </select>
        </div>
        <div style="display:flex;gap:var(--sp-2);justify-content:flex-end;margin-top:var(--sp-4)">
          <button class="btn btn-secondary" onClick=${() => setShowAdd(false)}>Cancel</button>
          <button class="btn btn-primary" onClick=${addMapping}>Create</button>
        </div>
      <//>
    `}
  `;
}

// === Audit Log Page ===
function AuditPage() {
  const [entries, setEntries] = useState([]);
  const [filter, setFilter] = useState('');
  const load = (event) => {
    const params = event ? `?event=${event}&limit=50` : '?limit=50';
    api('GET', `/api/admin/audit${params}`).then(setEntries).catch(() => {});
  };
  useEffect(() => load(), []);

  const eventTypes = ['login_success', 'login_failed', 'impersonation', 'user_created', 'user_merged', 'role_changed', 'app_registered', 'app_key_rotated'];

  return html`
    <div class="page-header"><h2>Audit Log</h2></div>
    <div style="display:flex;gap:var(--sp-2);margin-bottom:var(--sp-4);flex-wrap:wrap">
      <button class="btn btn-sm ${!filter ? 'btn-primary' : 'btn-secondary'}" onClick=${() => { setFilter(''); load(); }}>All</button>
      ${eventTypes.map(t => html`
        <button class="btn btn-sm ${filter === t ? 'btn-primary' : 'btn-secondary'}" onClick=${() => { setFilter(t); load(t); }}>${t}</button>
      `)}
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>IP</th><th>Data</th></tr></thead>
        <tbody>
          ${entries.length === 0
            ? html`<tr><td colspan="5"><div class="empty-state"><p>No audit entries</p></div></td></tr>`
            : entries.map(e => html`
              <tr>
                <td style="font-size:0.75rem;color:var(--text-muted);white-space:nowrap">${new Date(e.timestamp).toLocaleString()}</td>
                <td><span class="badge ${e.event.includes('fail') ? 'badge-error' : e.event.includes('success') ? 'badge-success' : e.event === 'impersonation' ? 'badge-warning' : ''}">${e.event}</span></td>
                <td><span class="guid">${(e.actor || '—').substring(0, 12)}</span></td>
                <td style="font-size:0.75rem;color:var(--text-secondary)">${e.ip || '—'}</td>
                <td style="font-size:0.75rem;font-family:var(--font-mono);color:var(--text-muted);max-width:300px;overflow:hidden;text-overflow:ellipsis">${JSON.stringify(e.data || {})}</td>
              </tr>
            `)
          }
        </tbody>
      </table>
    </div>
  `;
}

// === Login Setup (Admin Key) ===
function LoginSetup({ onLogin }) {
  const [key, setKey] = useState('');
  const [error, setError] = useState('');

  const login = async () => {
    setApiKey(key);
    try {
      await api('GET', '/api/admin/users');
      onLogin();
    } catch (e) {
      setError('Invalid admin key');
      setApiKey('');
    }
  };

  return html`
    <div class="login-page">
      <div class="login-card">
        <div class="login-brand">
          <h1>SimpleAuth</h1>
          <p>Admin Console</p>
        </div>
        <div class="gold-bar" style="margin-bottom:var(--sp-6)"></div>
        ${error && html`<div class="login-error">${error}</div>`}
        <div class="form-group">
          <label class="form-label">Admin API Key</label>
          <input class="form-input" type="password" value=${key} onInput=${e => setKey(e.target.value)} onKeyDown=${e => e.key === 'Enter' && login()} placeholder="Enter your AUTH_ADMIN_KEY" autofocus />
        </div>
        <button class="btn btn-primary" style="width:100%" onClick=${login}>Sign In</button>
      </div>
    </div>
  `;
}

// === App Shell ===
function App() {
  const [page, setPage] = useState('dashboard');
  const [authed, setAuthed] = useState(!!getApiKey());
  const [theme, setTheme] = useState(localStorage.getItem('simpleauth_theme') || 'auto');

  useEffect(() => {
    if (theme === 'auto') {
      document.documentElement.removeAttribute('data-theme');
    } else {
      document.documentElement.setAttribute('data-theme', theme);
    }
    localStorage.setItem('simpleauth_theme', theme);
  }, [theme]);

  // Verify key on mount
  useEffect(() => {
    if (authed) {
      api('GET', '/api/admin/users').catch(() => {
        setApiKey('');
        setAuthed(false);
      });
    }
  }, []);

  const toggleTheme = () => {
    const next = theme === 'light' ? 'dark' : theme === 'dark' ? 'auto' : 'light';
    setTheme(next);
  };

  if (!authed) return html`<${LoginSetup} onLogin=${() => setAuthed(true)} />`;

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: icons.dashboard },
    { id: 'users', label: 'Users', icon: icons.users },
    { id: 'apps', label: 'Apps', icon: icons.apps },
    { id: 'ldap', label: 'LDAP Providers', icon: icons.ldap },
    { id: 'mappings', label: 'Mappings', icon: icons.mappings },
    { id: 'impersonate', label: 'Impersonate', icon: icons.impersonate },
    { id: 'audit', label: 'Audit Log', icon: icons.audit },
  ];

  const pages = {
    dashboard: Dashboard,
    users: UsersPage,
    apps: AppsPage,
    ldap: LDAPPage,
    mappings: MappingsPage,
    impersonate: ImpersonatePage,
    audit: AuditPage,
  };

  const PageComponent = pages[page] || Dashboard;

  return html`
    <div class="app-layout">
      <nav class="sidebar">
        <div class="sidebar-brand">
          <h1>SimpleAuth</h1>
          <span>Admin Console</span>
        </div>
        <div class="sidebar-nav">
          ${navItems.map(item => html`
            <button class="nav-item ${page === item.id ? 'active' : ''}" onClick=${() => setPage(item.id)}>
              ${item.icon}
              <span>${item.label}</span>
            </button>
          `)}
        </div>
        <div class="sidebar-footer">
          <button class="theme-toggle" onClick=${toggleTheme} title="Toggle theme">
            ${theme === 'dark' ? icons.sun : icons.moon}
            <span style="margin-left:var(--sp-2);font-size:0.75rem">${theme === 'auto' ? 'Auto' : theme === 'dark' ? 'Light' : 'Dark'}</span>
          </button>
          <button class="btn btn-sm btn-secondary" style="width:100%;margin-top:var(--sp-2)" onClick=${() => { setApiKey(''); setAuthed(false); }}>Sign Out</button>
        </div>
      </nav>
      <main class="main-content">
        <${PageComponent} />
      </main>
    </div>
  `;
}

render(html`<${App} />`, document.getElementById('app'));
