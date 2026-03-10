import { h, render, Component } from 'preact';
import { useState, useEffect, useCallback } from 'preact/hooks';
import htm from 'htm';

const html = htm.bind(h);

// === API Helper ===
const API_KEY_STORAGE = 'simpleauth_admin_key';
const BASE_PATH = (window.__BASE_PATH__ || '');

function getApiKey() { return localStorage.getItem(API_KEY_STORAGE) || ''; }
function setApiKey(key) { localStorage.setItem(API_KEY_STORAGE, key); }

async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Authorization': `Bearer ${getApiKey()}`, 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(BASE_PATH + path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// === Icons (inline SVG) ===
const icons = {
  dashboard: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>`,
  users: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  ldap: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg>`,
  mappings: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
  impersonate: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/><line x1="2" y1="2" x2="22" y2="22" opacity="0.3"/></svg>`,
  audit: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`,
  sun: html`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
  moon: html`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  close: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  plus: html`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
  copy: html`<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  roles: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
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
  const [stats, setStats] = useState({ users: 0, events: [] });

  useEffect(() => {
    Promise.all([
      api('GET', '/api/admin/users'),
      api('GET', '/api/admin/audit?limit=10'),
    ]).then(([users, events]) => {
      setStats({ users: users.length, events });
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

// === Roles & Permissions ===
function RolesPage() {
  const [defaultRoles, setDefaultRoles] = useState([]);
  const [newDefaultRole, setNewDefaultRole] = useState('');
  const [rolePerms, setRolePerms] = useState({});
  const [newRoleName, setNewRoleName] = useState('');
  const [newPermForRole, setNewPermForRole] = useState({});
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => setToast(null), 3000);
  };

  useEffect(() => {
    Promise.all([
      api('GET', '/api/admin/defaults/roles'),
      api('GET', '/api/admin/role-permissions'),
    ]).then(([dRoles, rp]) => {
      setDefaultRoles(dRoles || []);
      setRolePerms(rp || {});
    }).catch(() => {});
  }, []);

  const saveDefaultRoles = async (roles) => {
    try {
      await api('PUT', '/api/admin/defaults/roles', roles);
      setDefaultRoles(roles);
      showToast('Default roles saved');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const addDefaultRole = () => {
    const r = newDefaultRole.trim();
    if (!r || defaultRoles.includes(r)) return;
    setNewDefaultRole('');
    saveDefaultRoles([...defaultRoles, r]);
  };

  const saveRolePerms = async (mapping) => {
    try {
      await api('PUT', '/api/admin/role-permissions', mapping);
      setRolePerms(mapping);
      showToast('Role permissions saved');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const addRole = () => {
    const r = newRoleName.trim();
    if (!r || rolePerms[r]) return;
    const updated = { ...rolePerms, [r]: [] };
    setNewRoleName('');
    saveRolePerms(updated);
  };

  const deleteRole = (role) => {
    const updated = { ...rolePerms };
    delete updated[role];
    saveRolePerms(updated);
  };

  const addPermToRole = (role) => {
    const p = (newPermForRole[role] || '').trim();
    if (!p || (rolePerms[role] || []).includes(p)) return;
    const updated = { ...rolePerms, [role]: [...(rolePerms[role] || []), p] };
    setNewPermForRole({ ...newPermForRole, [role]: '' });
    saveRolePerms(updated);
  };

  const removePermFromRole = (role, perm) => {
    const updated = { ...rolePerms, [role]: (rolePerms[role] || []).filter(p => p !== perm) };
    saveRolePerms(updated);
  };

  return html`
    <div class="page-header"><h2>Roles & Permissions</h2></div>
    <div class="gold-bar" style="margin-bottom: var(--sp-8)"></div>

    <div class="card" style="margin-bottom:var(--sp-6)">
      <div class="card-header"><h3>Default Roles</h3></div>
      <div style="padding:var(--sp-4)">
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-3)">Automatically assigned to every new user on first login.</p>
        <div style="display:flex;gap:var(--sp-2);flex-wrap:wrap;margin-bottom:var(--sp-3)">
          ${defaultRoles.map(r => html`
            <span class="badge" style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px">
              ${r}
              <button class="btn-icon" style="padding:0;min-width:auto" onClick=${() => saveDefaultRoles(defaultRoles.filter(x => x !== r))} title="Remove">×</button>
            </span>
          `)}
          ${defaultRoles.length === 0 && html`<span style="color:var(--text-muted);font-size:0.875rem">None configured</span>`}
        </div>
        <div style="display:flex;gap:var(--sp-2)">
          <input class="form-input" style="flex:1;max-width:300px" value=${newDefaultRole} onInput=${e => setNewDefaultRole(e.target.value)} placeholder="e.g. user, member" onKeyDown=${e => e.key === 'Enter' && addDefaultRole()} />
          <button class="btn btn-sm btn-primary" onClick=${addDefaultRole}>Add</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h3>Role → Permissions</h3>
      </div>
      <div style="padding:var(--sp-4)">
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-3)">Define what permissions each role grants. These are expanded into the JWT automatically.</p>

        ${Object.keys(rolePerms).length === 0
          ? html`<div style="color:var(--text-muted);font-size:0.875rem;margin-bottom:var(--sp-3)">No roles defined yet.</div>`
          : Object.entries(rolePerms).map(([role, perms]) => html`
            <div class="card" style="padding:var(--sp-3);margin-bottom:var(--sp-3)">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--sp-2)">
                <strong style="font-size:0.875rem">${role}</strong>
                <button class="btn btn-sm btn-danger" onClick=${() => deleteRole(role)}>Remove</button>
              </div>
              <div style="display:flex;gap:var(--sp-1);flex-wrap:wrap;margin-bottom:var(--sp-2)">
                ${(perms || []).map(p => html`
                  <span class="badge badge-success" style="display:inline-flex;align-items:center;gap:4px;padding:3px 8px;font-size:0.75rem">
                    ${p}
                    <button class="btn-icon" style="padding:0;min-width:auto;font-size:0.75rem" onClick=${() => removePermFromRole(role, p)} title="Remove">×</button>
                  </span>
                `)}
                ${(perms || []).length === 0 && html`<span style="color:var(--text-muted);font-size:0.75rem">No permissions</span>`}
              </div>
              <div style="display:flex;gap:var(--sp-1)">
                <input class="form-input" style="flex:1;padding:6px 10px;font-size:0.8rem" value=${newPermForRole[role] || ''} onInput=${e => setNewPermForRole({ ...newPermForRole, [role]: e.target.value })} placeholder="e.g. posts:write" onKeyDown=${e => e.key === 'Enter' && addPermToRole(role)} />
                <button class="btn btn-sm btn-secondary" onClick=${() => addPermToRole(role)}>Add</button>
              </div>
            </div>
          `)
        }

        <div style="display:flex;gap:var(--sp-2);margin-top:var(--sp-2)">
          <input class="form-input" style="flex:1" value=${newRoleName} onInput=${e => setNewRoleName(e.target.value)} placeholder="New role name, e.g. editor" onKeyDown=${e => e.key === 'Enter' && addRole()} />
          <button class="btn btn-sm btn-primary" onClick=${addRole}>${icons.plus} Add Role</button>
        </div>
      </div>
    </div>
    ${toast && html`<${Toast} ...${toast} />`}
  `;
}

// === Users Page ===
function UsersPage() {
  const [users, setUsers] = useState([]);
  const [modal, setModal] = useState(null);
  const [form, setForm] = useState({});
  const [toast, setToast] = useState(null);
  const [detail, setDetail] = useState(null);
  const [roles, setRoles] = useState([]);
  const [perms, setPerms] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [roleInput, setRoleInput] = useState('');
  const [permInput, setPermInput] = useState('');
  const [search, setSearch] = useState('');
  const [roleDefs, setRoleDefs] = useState({});

  const load = () => {
    api('GET', '/api/admin/users').then(setUsers).catch(() => {});
  };
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
      if (detail && detail.guid === guid) setDetail(null);
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

  const setPassword = async () => {
    try {
      await api('PUT', `/api/admin/users/${detail.guid}/password`, { password: form.new_password });
      setModal(null);
      setForm({});
      showToast('Password updated');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const openDetail = async (user) => {
    setDetail(user);
    setSessions([]);
    setRoles([]);
    setPerms([]);
    setRoleDefs({});
    api('GET', `/api/admin/users/${user.guid}/sessions`).then(setSessions).catch(() => {});
    loadRolesPerms(user.guid);
  };

  const loadRolesPerms = async (guid) => {
    try {
      const r = await api('GET', `/api/admin/users/${guid}/roles`);
      setRoles(r || []);
    } catch { setRoles([]); }
    try {
      const p = await api('GET', `/api/admin/users/${guid}/permissions`);
      setPerms(p || []);
    } catch { setPerms([]); }
    try {
      const rp = await api('GET', '/api/admin/role-permissions');
      setRoleDefs(rp || {});
    } catch { setRoleDefs({}); }
  };

  const addRole = async () => {
    if (!roleInput.trim()) return;
    const updated = [...roles, roleInput.trim()];
    try {
      await api('PUT', `/api/admin/users/${detail.guid}/roles`, updated);
      setRoles(updated);
      setRoleInput('');
      showToast('Role added');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const removeRole = async (role) => {
    const updated = roles.filter(r => r !== role);
    try {
      await api('PUT', `/api/admin/users/${detail.guid}/roles`, updated);
      setRoles(updated);
      showToast('Role removed');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const addPerm = async () => {
    if (!permInput.trim()) return;
    const updated = [...perms, permInput.trim()];
    try {
      await api('PUT', `/api/admin/users/${detail.guid}/permissions`, updated);
      setPerms(updated);
      setPermInput('');
      showToast('Permission added');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const removePerm = async (perm) => {
    const updated = perms.filter(p => p !== perm);
    try {
      await api('PUT', `/api/admin/users/${detail.guid}/permissions`, updated);
      setPerms(updated);
      showToast('Permission removed');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const revokeSessions = async () => {
    if (!confirm('Revoke all sessions for this user? They will be logged out everywhere.')) return;
    try {
      await api('DELETE', `/api/admin/users/${detail.guid}/sessions`);
      setSessions([]);
      showToast('All sessions revoked');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const filtered = users.filter(u => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (u.display_name || '').toLowerCase().includes(q) ||
           (u.email || '').toLowerCase().includes(q) ||
           u.guid.toLowerCase().includes(q);
  });

  return html`
    <div class="page-header">
      <h2>Users</h2>
      <div class="page-header-actions">
        <input class="form-input" style="max-width:250px" placeholder="Search users..." value=${search} onInput=${e => setSearch(e.target.value)} />
        <button class="btn btn-primary" onClick=${() => { setForm({}); setModal('create'); }}>${icons.plus} New User</button>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>GUID</th><th>Display Name</th><th>Email</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
        <tbody>
          ${filtered.length === 0
            ? html`<tr><td colspan="6"><div class="empty-state"><p>No users found</p></div></td></tr>`
            : filtered.map(u => html`
              <tr style="cursor:pointer" onClick=${() => openDetail(u)}>
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
                <td onClick=${e => e.stopPropagation()}>
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
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Department</label>
            <input class="form-input" value=${form.department || ''} onInput=${e => setForm({ ...form, department: e.target.value })} />
          </div>
          <div class="form-group">
            <label class="form-label">Job Title</label>
            <input class="form-input" value=${form.job_title || ''} onInput=${e => setForm({ ...form, job_title: e.target.value })} />
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Company</label>
          <input class="form-input" value=${form.company || ''} onInput=${e => setForm({ ...form, company: e.target.value })} />
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${createUser}>Create User</button>
        </div>
      <//>
    `}

    ${modal === 'password' && html`
      <${Modal} title="Set Password" onClose=${() => setModal(null)}>
        <div class="form-group">
          <label class="form-label">New Password</label>
          <input class="form-input" type="password" value=${form.new_password || ''} onInput=${e => setForm({ ...form, new_password: e.target.value })} placeholder="Minimum 6 characters" />
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${setPassword}>Set Password</button>
        </div>
      <//>
    `}

    ${detail && html`
      <${Modal} title="User Detail" onClose=${() => setDetail(null)}>
        <div style="display:grid;grid-template-columns:auto 1fr;gap:var(--sp-2) var(--sp-4);font-size:0.875rem;margin-bottom:var(--sp-4)">
          <span style="color:var(--text-muted)">GUID</span><span class="guid" style="font-size:0.8rem">${detail.guid}</span>
          <span style="color:var(--text-muted)">Name</span><span>${detail.display_name || '—'}</span>
          <span style="color:var(--text-muted)">Email</span><span>${detail.email || '—'}</span>
          <span style="color:var(--text-muted)">Department</span><span>${detail.department || '—'}</span>
          <span style="color:var(--text-muted)">Company</span><span>${detail.company || '—'}</span>
          <span style="color:var(--text-muted)">Job Title</span><span>${detail.job_title || '—'}</span>
          <span style="color:var(--text-muted)">Status</span><span>${detail.disabled ? 'Disabled' : detail.merged_into ? 'Merged into ' + detail.merged_into.substring(0,8) + '...' : 'Active'}</span>
        </div>

        <div style="display:flex;gap:var(--sp-2);margin-bottom:var(--sp-4)">
          <button class="btn btn-sm btn-secondary" onClick=${() => { setForm({}); setModal('password'); }}>Set Password</button>
          <button class="btn btn-sm btn-danger" onClick=${revokeSessions}>Revoke All Sessions</button>
        </div>

        <div style="margin-bottom:var(--sp-4)">
          <div style="display:flex;align-items:center;gap:var(--sp-2);margin-bottom:var(--sp-2)">
            <strong style="font-size:0.875rem">Sessions</strong>
            <span style="color:var(--text-muted);font-size:0.75rem">(${sessions.length} active)</span>
          </div>
          ${sessions.length === 0
            ? html`<p style="color:var(--text-muted);font-size:0.8rem">No active sessions</p>`
            : html`<div style="max-height:120px;overflow-y:auto">
                ${sessions.map(s => html`
                  <div style="display:flex;justify-content:space-between;padding:var(--sp-1) 0;font-size:0.8rem;border-bottom:1px solid var(--border)">
                    <span>session</span>
                    <span style="color:var(--text-muted)">expires ${new Date(s.expires_at).toLocaleDateString()}</span>
                  </div>
                `)}
              </div>`
          }
        </div>

        <div>
          <div style="display:flex;align-items:center;gap:var(--sp-2);margin-bottom:var(--sp-2)">
            <strong style="font-size:0.875rem">Roles & Permissions</strong>
          </div>

          <div style="margin-bottom:var(--sp-3)">
            <label style="font-size:0.75rem;color:var(--text-muted);display:block;margin-bottom:var(--sp-1)">Roles</label>
            <div style="display:flex;flex-wrap:wrap;gap:var(--sp-1);margin-bottom:var(--sp-1)">
              ${roles.map(r => html`
                <span class="badge" style="cursor:pointer" onClick=${() => removeRole(r)}>${r} ×</span>
              `)}
              ${roles.length === 0 && html`<span style="color:var(--text-muted);font-size:0.8rem">None</span>`}
            </div>
            ${Object.keys(roleDefs).length > 0 && html`
              <div style="margin-bottom:var(--sp-1)">
                <span style="font-size:0.7rem;color:var(--text-muted)">Available: </span>
                ${Object.keys(roleDefs).filter(r => !roles.includes(r)).map(r => html`
                  <button class="btn btn-sm btn-secondary" style="padding:1px 6px;font-size:0.7rem;margin:1px" onClick=${() => {
                    const updated = [...roles, r];
                    api('PUT', '/api/admin/users/' + detail.guid + '/roles', updated).then(() => { setRoles(updated); showToast('Role added'); }).catch(e => showToast(e.message, 'error'));
                  }}>+ ${r}</button>
                `)}
                ${Object.keys(roleDefs).filter(r => !roles.includes(r)).length === 0 && html`<span style="font-size:0.7rem;color:var(--text-muted)">all assigned</span>`}
              </div>
            `}
            <div style="display:flex;gap:var(--sp-1)">
              <input class="form-input" style="flex:1;padding:4px 8px;font-size:0.8rem" placeholder="Add custom role..." value=${roleInput} onInput=${e => setRoleInput(e.target.value)} onKeyDown=${e => e.key === 'Enter' && addRole()} />
              <button class="btn btn-sm btn-primary" onClick=${addRole}>Add</button>
            </div>
          </div>

          <div>
            <label style="font-size:0.75rem;color:var(--text-muted);display:block;margin-bottom:var(--sp-1)">Direct Permissions</label>
            <div class="form-help" style="font-size:0.7rem;margin-bottom:var(--sp-1)">Extra permissions for this user, on top of what their roles grant.</div>
            <div style="display:flex;flex-wrap:wrap;gap:var(--sp-1);margin-bottom:var(--sp-1)">
              ${perms.map(p => html`
                <span class="badge" style="cursor:pointer" onClick=${() => removePerm(p)}>${p} ×</span>
              `)}
              ${perms.length === 0 && html`<span style="color:var(--text-muted);font-size:0.8rem">None</span>`}
            </div>
            ${(() => {
              const allDefinedPerms = [...new Set(Object.values(roleDefs).flat())];
              const available = allDefinedPerms.filter(p => !perms.includes(p));
              return available.length > 0 && html`
                <div style="margin-bottom:var(--sp-1)">
                  <span style="font-size:0.7rem;color:var(--text-muted)">Known: </span>
                  ${available.map(p => html`
                    <button class="btn btn-sm btn-secondary" style="padding:1px 6px;font-size:0.7rem;margin:1px" onClick=${() => {
                      const updated = [...perms, p];
                      api('PUT', '/api/admin/users/' + detail.guid + '/permissions', updated).then(() => { setPerms(updated); showToast('Permission added'); }).catch(e => showToast(e.message, 'error'));
                    }}>+ ${p}</button>
                  `)}
                </div>
              `;
            })()}
            <div style="display:flex;gap:var(--sp-1)">
              <input class="form-input" style="flex:1;padding:4px 8px;font-size:0.8rem" placeholder="Add custom permission..." value=${permInput} onInput=${e => setPermInput(e.target.value)} onKeyDown=${e => e.key === 'Enter' && addPerm()} />
              <button class="btn btn-sm btn-primary" onClick=${addPerm}>Add</button>
            </div>
          </div>
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
  const [krbStatus, setKrbStatus] = useState(null);
  const [serverInfo, setServerInfo] = useState({});

  const load = () => {
    api('GET', '/api/admin/ldap').then(setProviders).catch(() => {});
    api('GET', '/api/admin/kerberos/status').then(setKrbStatus).catch(() => {});
    api('GET', '/api/admin/server-info').then(setServerInfo).catch(() => {});
  };
  useEffect(load, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => setToast(null), 3000);
  };

  const saveProvider = async () => {
    const payload = {
      ...form,
      use_tls: form.use_tls === true || form.use_tls === 'true',
      skip_tls_verify: form.skip_tls_verify === true || form.skip_tls_verify === 'true',
      priority: parseInt(form.priority) || 0,
    };
    try {
      if (form._editing) {
        await api('PUT', `/api/admin/ldap/${form.provider_id}`, payload);
      } else {
        await api('POST', '/api/admin/ldap', payload);
      }
      setModal(null);
      setForm({});
      load();
      showToast(form._editing ? 'Provider updated' : 'Provider added');
    } catch (e) { showToast(e.message, 'error'); }
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

  const generateScript = () => {
    const acct = form.script_account || 'svc-sauth-simpleauth';
    const pw = form.script_password || '';
    if (!pw) { showToast('Password is required', 'error'); return; }
    // Escape for PowerShell single-quoted strings: ' becomes ''
    const psEscSingle = (s) => s.replace(/'/g, "''");
    const safeAcct = psEscSingle(acct);
    const safePw = psEscSingle(pw);
    // Build script as array of lines to avoid template literal issues
    const lines = [
      '#Requires -Modules ActiveDirectory',
      '<#',
      '.SYNOPSIS',
      '    SimpleAuth AD Setup / Cleanup Script',
      '.DESCRIPTION',
      '    Interactive script to set up or remove a SimpleAuth service account in AD.',
      '    Run on a Domain Controller or a machine with RSAT AD tools.',
      '    Requires Domain Admin or Account Operator privileges.',
      '#>',
      '',
      '$ErrorActionPreference = "Stop"',
      "$AccountName = '" + safeAcct + "'",
      "$AccountPassword = '" + safePw + "'",
      '',
      '# -- Check admin privileges ----------------------------------------',
      '$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()',
      '$adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator',
      '$isAdmin = (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole($adminRole)',
      '',
      '# -- Header -------------------------------------------------------',
      'Write-Host ""',
      'Write-Host "  ========================================" -ForegroundColor Cyan',
      'Write-Host "       SimpleAuth  AD  Manager" -ForegroundColor Cyan',
      'Write-Host "  ========================================" -ForegroundColor Cyan',
      'Write-Host ""',
      'if (-not $isAdmin) {',
      '    Write-Host "  WARNING: Not running as Administrator." -ForegroundColor Yellow',
      '    Write-Host "  You may get Access Denied errors. Right-click PowerShell" -ForegroundColor Yellow',
      '    Write-Host "  and select Run as Administrator if this fails." -ForegroundColor Yellow',
      '    Write-Host ""',
      '}',
      '',
      '# -- Detect domain ------------------------------------------------',
      '$domain = Get-ADDomain',
      '$domainDNS = $domain.DNSRoot',
      '$domainDN = $domain.DistinguishedName',
      '$dc = (Get-ADDomainController -Discover -DomainName $domainDNS).HostName[0]',
      '',
      'Write-Host "  Domain:    $domainDNS" -ForegroundColor White',
      'Write-Host "  Base DN:   $domainDN" -ForegroundColor White',
      'Write-Host "  DC:        $dc" -ForegroundColor White',
      'Write-Host ""',
      '',
      '# -- Check if account already exists --------------------------------',
      '$adFilter = "sAMAccountName -eq \'$AccountName\'"',
      '$existingUser = Get-ADUser -Filter $adFilter -Properties servicePrincipalName -ErrorAction SilentlyContinue',
      '',
      'if ($existingUser) {',
      '    $existingSPNs = $existingUser.servicePrincipalName',
      '    Write-Host "  Account \'$AccountName\' already exists in AD." -ForegroundColor Yellow',
      '    if ($existingSPNs) {',
      '        Write-Host "  SPNs registered: $($existingSPNs -join \', \')" -ForegroundColor Yellow',
      '    }',
      '    Write-Host ""',
      '    Write-Host "  What would you like to do?" -ForegroundColor White',
      '    Write-Host "    1) Re-run setup (update password, re-export config)" -ForegroundColor White',
      '    Write-Host "    2) Remove everything (delete SPNs, disable/delete account)" -ForegroundColor White',
      '    Write-Host "    3) Exit" -ForegroundColor White',
      '    Write-Host ""',
      '    $choice = Read-Host "Enter choice [1]"',
      '    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }',
      '    Write-Host ""',
      '',
      '    if ($choice -eq "3") {',
      '        Write-Host "  Exiting." -ForegroundColor White',
      '        exit 0',
      '    }',
      '',
      '    if ($choice -eq "2") {',
      '        # ---- CLEANUP MODE ----',
      '        Write-Host "  ---- Cleanup Mode ----" -ForegroundColor Red',
      '        Write-Host ""',
      '',
      '        # Remove SPNs',
      '        if ($existingSPNs) {',
      '            foreach ($s in $existingSPNs) {',
      '                Write-Host "  Removing SPN: $s" -ForegroundColor White',
      '                try {',
      '                    $null = & setspn -D $s $AccountName 2>&1',
      '                    Write-Host "    Removed." -ForegroundColor Green',
      '                } catch {',
      '                    Write-Host "    Failed to remove: $_" -ForegroundColor Yellow',
      '                }',
      '            }',
      '        } else {',
      '            Write-Host "  No SPNs to remove." -ForegroundColor White',
      '        }',
      '        Write-Host ""',
      '',
      '        # Delete or disable account',
      '        Write-Host "  Delete the account entirely, or just disable it?" -ForegroundColor White',
      '        Write-Host "    1) Delete account" -ForegroundColor White',
      '        Write-Host "    2) Disable account (keep for reference)" -ForegroundColor White',
      '        Write-Host ""',
      '        $delChoice = Read-Host "Enter choice [1]"',
      '        if ([string]::IsNullOrWhiteSpace($delChoice)) { $delChoice = "1" }',
      '',
      '        if ($delChoice -eq "2") {',
      '            Disable-ADAccount -Identity $existingUser',
      '            Write-Host "  Account \'$AccountName\' disabled." -ForegroundColor Green',
      '        } else {',
      '            $confirm = Read-Host "  Type YES to permanently delete \'$AccountName\'"',
      '            if ($confirm -eq "YES") {',
      '                Remove-ADUser -Identity $existingUser -Confirm:$false',
      '                Write-Host "  Account \'$AccountName\' deleted." -ForegroundColor Green',
      '            } else {',
      '                Write-Host "  Aborted. Account not deleted." -ForegroundColor Yellow',
      '            }',
      '        }',
      '',
      '        # Clean up config file if present',
      '        $outFile = Join-Path (Get-Location) "simpleauth-config.json"',
      '        if (Test-Path $outFile) {',
      '            $delCfg = Read-Host "  Delete simpleauth-config.json too? [y/N]"',
      '            if ($delCfg -eq "y" -or $delCfg -eq "Y") {',
      '                Remove-Item $outFile',
      '                Write-Host "  Config file deleted." -ForegroundColor Green',
      '            }',
      '        }',
      '',
      '        Write-Host ""',
      '        Write-Host "  ========================================" -ForegroundColor Green',
      '        Write-Host "           Cleanup Complete" -ForegroundColor Green',
      '        Write-Host "  ========================================" -ForegroundColor Green',
      '        Write-Host ""',
      '        Write-Host "  Remember to also remove the LDAP provider" -ForegroundColor Yellow',
      '        Write-Host "  and Kerberos config in the SimpleAuth admin UI." -ForegroundColor Yellow',
      '        Write-Host ""',
      '        Read-Host "Press Enter to exit"',
      '        exit 0',
      '    }',
      '',
      '    # choice "1" falls through to setup below',
      '}',
      '',
      '# ==================================================================',
      '# SETUP MODE',
      '# ==================================================================',
      '',
      '# -- Select OU -----------------------------------------------------',
      'Write-Host "[1/4] Select where to create the service account" -ForegroundColor Yellow',
      'Write-Host ""',
      '',
      '$ous = @()',
      '$ous += [PSCustomObject]@{ Index = 0; Name = "(Default Users container)"; DN = $domain.UsersContainer }',
      '$ouList = Get-ADOrganizationalUnit -Filter * -Properties CanonicalName | Sort-Object CanonicalName',
      '$i = 1',
      'foreach ($ou in $ouList) {',
      '    $ous += [PSCustomObject]@{ Index = $i; Name = $ou.CanonicalName; DN = $ou.DistinguishedName }',
      '    $i++',
      '}',
      '',
      'if ($existingUser) {',
      '    Write-Host "  (Account already exists, OU selection skipped)" -ForegroundColor White',
      '    $targetOU = ($existingUser.DistinguishedName -replace "^CN=[^,]+,", "")',
      '} else {',
      '    foreach ($entry in $ous) {',
      '        $idx = $entry.Index.ToString().PadLeft(3)',
      '        if ($entry.Index -eq 0) {',
      '            Write-Host "  $idx) $($entry.Name)" -ForegroundColor Green',
      '        } else {',
      '            Write-Host "  $idx) $($entry.Name)" -ForegroundColor White',
      '        }',
      '    }',
      '    Write-Host ""',
      '    $selection = Read-Host "Enter number [0]"',
      '    if ([string]::IsNullOrWhiteSpace($selection)) { $selection = "0" }',
      '    $selectedIdx = [int]$selection',
      '    if ($selectedIdx -lt 0 -or $selectedIdx -ge $ous.Count) {',
      '        Write-Host "  Invalid selection, using default" -ForegroundColor Yellow',
      '        $selectedIdx = 0',
      '    }',
      '    $targetOU = $ous[$selectedIdx].DN',
      '    Write-Host "  Selected: $($ous[$selectedIdx].Name)" -ForegroundColor Cyan',
      '}',
      'Write-Host ""',
      '',
      '# -- Create or update account --------------------------------------',
      'Write-Host "[2/4] Setting up service account..." -ForegroundColor Yellow',
      '$securePw = ConvertTo-SecureString $AccountPassword -AsPlainText -Force',
      '',
      'if ($existingUser) {',
      '    try {',
      '        Set-ADAccountPassword -Identity $existingUser -NewPassword $securePw -Reset',
      '        Enable-ADAccount -Identity $existingUser',
      '        Write-Host "  Password updated, account enabled." -ForegroundColor Green',
      '    } catch {',
      '        Write-Host "  ERROR: Failed to update account: $_" -ForegroundColor Red',
      '        Read-Host "Press Enter to exit"',
      '        exit 1',
      '    }',
      '} else {',
      '    $newUserParams = @{',
      '        Name                 = $AccountName',
      '        SamAccountName       = $AccountName',
      '        UserPrincipalName    = "$AccountName@$domainDNS"',
      '        Path                 = $targetOU',
      '        AccountPassword      = $securePw',
      '        Enabled              = $true',
      '        PasswordNeverExpires = $true',
      '        CannotChangePassword = $true',
      '        Description          = "SimpleAuth LDAP bind account (do not delete)"',
      '    }',
      '    try {',
      '        New-ADUser @newUserParams',
      '        Write-Host "  Account created in: $targetOU" -ForegroundColor Green',
      '    } catch {',
      '        Write-Host "  ERROR: Failed to create account: $_" -ForegroundColor Red',
      '        Write-Host ""',
      '        Write-Host "  Possible causes:" -ForegroundColor Yellow',
      '        Write-Host "    - Access denied: run as Domain Admin or Account Operator" -ForegroundColor White',
      '        Write-Host "    - No permission on OU: try the default Users container" -ForegroundColor White',
      '        Write-Host "    - Password does not meet complexity requirements" -ForegroundColor White',
      '        Write-Host ""',
      '        Read-Host "Press Enter to exit"',
      '        exit 1',
      '    }',
      '}',
      'Write-Host ""',
      '',
      '# -- Kerberos SPN (optional) ---------------------------------------',
      'Write-Host "[3/4] Kerberos / SPNEGO setup (optional)" -ForegroundColor Yellow',
      '',
      '# Check for existing SPNs and offer to manage them',
      '$currentSPNs = (Get-ADUser -Filter $adFilter -Properties servicePrincipalName).servicePrincipalName',
      'if ($currentSPNs) {',
      '    Write-Host "  Existing SPNs on ${AccountName}:" -ForegroundColor White',
      '    foreach ($s in $currentSPNs) { Write-Host "    - $s" -ForegroundColor White }',
      '    Write-Host ""',
      '    Write-Host "  Options:" -ForegroundColor White',
      '    Write-Host "    1) Keep existing SPNs" -ForegroundColor White',
      '    Write-Host "    2) Remove all SPNs and set a new one" -ForegroundColor White',
      '    Write-Host "    3) Add an additional SPN" -ForegroundColor White',
      '    Write-Host ""',
      '    $spnChoice = Read-Host "Enter choice [1]"',
      '    if ([string]::IsNullOrWhiteSpace($spnChoice)) { $spnChoice = "1" }',
      '',
      '    $spnResult = $null',
      '    if ($spnChoice -eq "2") {',
      '        foreach ($s in $currentSPNs) {',
      '            Write-Host "  Removing SPN: $s" -ForegroundColor White',
      '            try { $null = & setspn -D $s $AccountName 2>&1 } catch {}',
      '        }',
      '        Write-Host "  All SPNs removed." -ForegroundColor Green',
      '        Write-Host ""',
      '        Write-Host "  Enter the FQDN clients use to reach SimpleAuth" -ForegroundColor White',
      '        Write-Host "  (e.g. simpleauth.corp.local) or press Enter to skip." -ForegroundColor White',
      '        $spnAnswer = Read-Host "SimpleAuth hostname"',
      '        if (-not [string]::IsNullOrWhiteSpace($spnAnswer)) {',
      '            $spn = "HTTP/$spnAnswer"',
      '            try {',
      '                $null = & setspn -A $spn $AccountName 2>&1',
      '                Write-Host "  SPN registered: $spn" -ForegroundColor Green',
      '                $spnResult = @{ spn = $spn; service_hostname = $spnAnswer }',
      '            } catch {',
      '                Write-Host "  Warning: SPN registration failed: $_" -ForegroundColor Yellow',
      '                $spnResult = @{ service_hostname = $spnAnswer }',
      '            }',
      '        }',
      '    } elseif ($spnChoice -eq "3") {',
      '        Write-Host "  Enter additional FQDN for SPN:" -ForegroundColor White',
      '        $spnAnswer = Read-Host "SimpleAuth hostname"',
      '        if (-not [string]::IsNullOrWhiteSpace($spnAnswer)) {',
      '            $spn = "HTTP/$spnAnswer"',
      '            try {',
      '                $null = & setspn -A $spn $AccountName 2>&1',
      '                Write-Host "  SPN registered: $spn" -ForegroundColor Green',
      '                $spnResult = @{ spn = $spn; service_hostname = $spnAnswer }',
      '            } catch {',
      '                Write-Host "  Warning: SPN registration failed: $_" -ForegroundColor Yellow',
      '                $spnResult = @{ service_hostname = $spnAnswer }',
      '            }',
      '        }',
      '    } else {',
      '        # Keep existing - use first HTTP SPN if any',
      '        foreach ($s in $currentSPNs) {',
      '            if ($s -like "HTTP/*") {',
      '                $hostname = $s -replace "^HTTP/", ""',
      '                $spnResult = @{ spn = $s; service_hostname = $hostname }',
      '                break',
      '            }',
      '        }',
      '    }',
      '} else {',
      '    Write-Host "  Enter the FQDN clients use to reach SimpleAuth" -ForegroundColor White',
      '    Write-Host "  (e.g. simpleauth.corp.local) or press Enter to skip." -ForegroundColor White',
      '    Write-Host ""',
      '    $spnAnswer = Read-Host "SimpleAuth hostname"',
      '    $spnResult = $null',
      '    if (-not [string]::IsNullOrWhiteSpace($spnAnswer)) {',
      '        $spn = "HTTP/$spnAnswer"',
      '        Write-Host "  Registering SPN: $spn on $AccountName" -ForegroundColor White',
      '        try {',
      '            $null = & setspn -A $spn $AccountName 2>&1',
      '            Write-Host "  SPN registered successfully" -ForegroundColor Green',
      '            $spnResult = @{ spn = $spn; service_hostname = $spnAnswer }',
      '        } catch {',
      '            Write-Host "  Warning: SPN registration failed: $_" -ForegroundColor Yellow',
      '            Write-Host "  Run manually: setspn -A $spn $AccountName" -ForegroundColor Yellow',
      '            $spnResult = @{ service_hostname = $spnAnswer }',
      '        }',
      '    }',
      '}',
      'Write-Host ""',
      '',
      '# -- Export config -------------------------------------------------',
      'Write-Host "[4/4] Exporting config..." -ForegroundColor Yellow',
      '',
      '$config = [ordered]@{',
      '    server   = $dc',
      '    username = "$AccountName@$domainDNS"',
      '    password = $AccountPassword',
      '    domain   = $domainDNS',
      '    base_dn  = $domainDN',
      '}',
      'if ($spnResult) {',
      '    foreach ($key in $spnResult.Keys) { $config[$key] = $spnResult[$key] }',
      '}',
      '',
      '$outFile = Join-Path (Get-Location) "simpleauth-config.json"',
      '$config | ConvertTo-Json | Set-Content -Path $outFile -Encoding UTF8',
      '',
      'Write-Host ""',
      'Write-Host "  ========================================" -ForegroundColor Green',
      'Write-Host "           Setup Complete!" -ForegroundColor Green',
      'Write-Host "  ========================================" -ForegroundColor Green',
      'Write-Host ""',
      'Write-Host "  Config file: $outFile" -ForegroundColor White',
      'Write-Host ""',
      'Write-Host "  Next steps:" -ForegroundColor Yellow',
      'Write-Host "    1. Copy simpleauth-config.json to your workstation" -ForegroundColor White',
      'Write-Host "    2. Open SimpleAuth admin UI -> LDAP Providers" -ForegroundColor White',
      'Write-Host "    3. Click Import Config and upload the file" -ForegroundColor White',
      'Write-Host ""',
      'Read-Host "Press Enter to exit"',
    ];
    const script = lines.join('\r\n');
    // UTF-8 BOM so Windows PowerShell reads encoding correctly
    const bom = new Uint8Array([0xEF, 0xBB, 0xBF]);
    const blob = new Blob([bom, script], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'Setup-SimpleAuth.ps1'; a.click();
    URL.revokeObjectURL(url);
    showToast('Script downloaded');
  };

  const importConfig = async () => {
    try {
      const cfg = JSON.parse(form.import_json);
      // First auto-discover to create the provider
      const result = await api('POST', '/api/admin/ldap/auto-discover', {
        server: cfg.server,
        username: cfg.username,
        password: cfg.password,
      });
      // If config has Kerberos info, auto-setup keytab via import endpoint
      let msg = `Provider configured: ${result.provider_id}`;
      if (cfg.service_hostname && result.provider_id) {
        try {
          const importResult = await api('POST', '/api/admin/ldap/import', {
            ldap_providers: [result],
            service_hostname: cfg.service_hostname,
            spn: cfg.spn || ('HTTP/' + cfg.service_hostname),
          });
          if (importResult.kerberos) {
            msg = `Provider + Kerberos configured: ${importResult.kerberos.spn}`;
          } else if (importResult.kerberos_error) {
            msg = `Provider configured. Kerberos failed: ${importResult.kerberos_error}`;
          }
        } catch (e) {
          msg += ` (Kerberos setup failed: ${e.message})`;
        }
      }
      setModal(null);
      setForm({});
      load();
      showToast(msg);
    } catch (e) {
      showToast(e.message || 'Invalid config file', 'error');
    }
  };

  const handleFileImport = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setForm({ ...form, import_json: ev.target.result });
    reader.readAsText(file);
  };

  const setupKerberos = async () => {
    try {
      const result = await api('POST', `/api/admin/ldap/${form.provider_id}/setup-kerberos`, {
        service_hostname: form.service_hostname,
      });
      setModal(null);
      setForm({});
      load();
      const msg = result.spn_warning
        ? `Kerberos configured (warning: ${result.spn_warning})`
        : `Kerberos configured: ${result.spn}`;
      showToast(msg);
    } catch (e) { showToast(e.message, 'error'); }
  };

  const cleanupKerberos = async () => {
    try {
      await api('POST', `/api/admin/ldap/${form.provider_id}/cleanup-kerberos`, {
        username: form.cleanup_username || undefined,
        password: form.cleanup_password || undefined,
      });
      setModal(null);
      setForm({});
      load();
      showToast('Kerberos configuration removed');
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

  const syncAllUsers = async (providerId) => {
    try {
      showToast('Syncing all users...', 'info');
      const result = await api('POST', `/api/admin/ldap/${providerId}/sync-all`);
      const msg = `Synced ${result.synced} user(s)` + (result.failed > 0 ? `, ${result.failed} failed` : '');
      showToast(msg, result.failed > 0 ? 'warning' : 'success');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const syncSingleUser = async () => {
    try {
      const result = await api('POST', `/api/admin/ldap/${form.sync_provider_id}/sync-user`, { username: form.sync_username });
      setModal(null);
      setForm({});
      showToast(`Synced: ${result.user.display_name || result.user.guid}`);
    } catch (e) { showToast(e.message, 'error'); }
  };

  const downloadSetupScript = async () => {
    try {
      const res = await fetch(BASE_PATH + '/api/admin/setup-script', {
        headers: { 'Authorization': `Bearer ${getApiKey()}` },
      });
      if (!res.ok) { const d = await res.json(); throw new Error(d.error); }
      const text = await res.text();
      const bom = new Uint8Array([0xEF, 0xBB, 0xBF]);
      const blob = new Blob([bom, text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'simpleauth-setup.ps1'; a.click();
      URL.revokeObjectURL(url);
      showToast('Setup script downloaded');
    } catch (e) { showToast(e.message, 'error'); }
  };

  return html`
    <div class="page-header">
      <h2>LDAP Providers</h2>
      <div class="page-header-actions">
        <button class="btn btn-secondary" onClick=${() => { setForm({ script_account: 'svc-sauth-' + (serverInfo.deployment_name || 'sauth') }); setModal('generate-script'); }}>Generate AD Script</button>
        <button class="btn btn-secondary" onClick=${() => { setForm({}); setModal('import-config'); }}>Import Config</button>
        <button class="btn btn-primary" onClick=${() => { setForm({ user_filter: '(sAMAccountName={{username}})', display_name_attr: 'displayName', email_attr: 'mail', groups_attr: 'memberOf' }); setModal('create'); }}>${icons.plus} Manual Setup</button>
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
                <td style="white-space:nowrap">
                  <button class="btn btn-sm btn-secondary" onClick=${() => { setForm({ ...p, _editing: true }); setModal('create'); }}>Edit</button>
                  <button class="btn btn-sm btn-secondary" style="margin-left:var(--sp-1)" onClick=${() => testConnection(p.provider_id)}>Test</button>
                  ${krbStatus?.configured && krbStatus?.provider_id === p.provider_id
                    ? html`<button class="btn btn-sm btn-danger" style="margin-left:var(--sp-1)" onClick=${() => { setForm({ provider_id: p.provider_id }); setModal('krb-cleanup'); }}>Remove Kerberos</button>`
                    : html`<button class="btn btn-sm btn-secondary" style="margin-left:var(--sp-1)" onClick=${() => { setForm({ provider_id: p.provider_id, service_hostname: serverInfo.hostname || '' }); setModal('krb-setup'); }}>Setup Kerberos</button>`
                  }
                  <button class="btn btn-sm btn-secondary" style="margin-left:var(--sp-1)" onClick=${() => syncAllUsers(p.provider_id)}>Sync All</button>
                  <button class="btn btn-sm btn-secondary" style="margin-left:var(--sp-1)" onClick=${() => { setForm({ sync_provider_id: p.provider_id }); setModal('sync-user'); }}>Sync User</button>
                  <button class="btn btn-sm btn-secondary" style="margin-left:var(--sp-1)" onClick=${() => downloadSetupScript()}>AD Script</button>
                  <button class="btn btn-sm btn-danger" style="margin-left:var(--sp-1)" onClick=${() => deleteProvider(p.provider_id)}>Delete</button>
                </td>
              </tr>
            `)
          }
        </tbody>
      </table>
    </div>

    ${modal === 'create' && html`
      <${Modal} title=${form._editing ? 'Edit LDAP Provider' : 'Add LDAP Provider'} onClose=${() => setModal(null)}>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Provider ID</label>
            <input class="form-input" value=${form.provider_id || ''} onInput=${e => setForm({ ...form, provider_id: e.target.value })} placeholder="corp" disabled=${form._editing} />
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
          <div class="form-help">Use ${'{{username}}'} as placeholder. E.g. (sAMAccountName=${'{{username}}'}) for AD, (uid=${'{{username}}'}) for LDAP</div>
        </div>
        <div class="form-group">
          <label class="form-label">Priority</label>
          <input class="form-input" type="number" value=${form.priority || '0'} onInput=${e => setForm({ ...form, priority: e.target.value })} />
          <div class="form-help">Lower = tried first</div>
        </div>
        <details style="margin-top:var(--sp-2)">
          <summary style="cursor:pointer;font-weight:600;margin-bottom:var(--sp-2)">Attribute Mapping</summary>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Display Name Attr</label>
              <input class="form-input" value=${form.display_name_attr || ''} onInput=${e => setForm({ ...form, display_name_attr: e.target.value })} placeholder="displayName" />
            </div>
            <div class="form-group">
              <label class="form-label">Email Attr</label>
              <input class="form-input" value=${form.email_attr || ''} onInput=${e => setForm({ ...form, email_attr: e.target.value })} placeholder="mail" />
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Department Attr</label>
              <input class="form-input" value=${form.department_attr || ''} onInput=${e => setForm({ ...form, department_attr: e.target.value })} placeholder="department" />
            </div>
            <div class="form-group">
              <label class="form-label">Company Attr</label>
              <input class="form-input" value=${form.company_attr || ''} onInput=${e => setForm({ ...form, company_attr: e.target.value })} placeholder="company" />
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">Job Title Attr</label>
              <input class="form-input" value=${form.job_title_attr || ''} onInput=${e => setForm({ ...form, job_title_attr: e.target.value })} placeholder="title" />
            </div>
            <div class="form-group">
              <label class="form-label">Groups Attr</label>
              <input class="form-input" value=${form.groups_attr || ''} onInput=${e => setForm({ ...form, groups_attr: e.target.value })} placeholder="memberOf" />
            </div>
          </div>
        </details>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${saveProvider}>${form._editing ? 'Save Changes' : 'Add Provider'}</button>
        </div>
      <//>
    `}

    ${krbStatus?.configured && html`
      <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius);padding:var(--sp-3);margin-bottom:var(--sp-4);display:flex;align-items:center;gap:var(--sp-3)">
        <span style="color:var(--success);font-size:1.25rem">&#9679;</span>
        <div style="flex:1">
          <strong>Kerberos Active</strong>
          <span style="color:var(--text-secondary);margin-left:var(--sp-2);font-size:0.875rem">
            ${krbStatus.spn || ''} ${krbStatus.realm ? `@ ${krbStatus.realm}` : ''} (${krbStatus.source})
          </span>
          <div style="color:var(--text-muted);font-size:0.75rem;margin-top:2px">SPNEGO test will authenticate via Kerberos and look up user data across all LDAP providers</div>
        </div>
        <a href="${BASE_PATH}/test-negotiate" target="_blank" class="btn btn-secondary" style="font-size:0.8rem;padding:4px 12px;text-decoration:none">Test SPNEGO</a>
      </div>
    `}

    ${modal === 'krb-setup' && html`
      <${Modal} title="Setup Kerberos / SPNEGO" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">Enter the hostname that clients use to reach SimpleAuth. A keytab will be generated and the SPN registered in AD.</p>
        <div class="form-group">
          <label class="form-label">Service Hostname</label>
          <input class="form-input" value=${form.service_hostname || ''} onInput=${e => setForm({ ...form, service_hostname: e.target.value })} placeholder="simpleauth.corp.local" />
          <div class="form-help">The FQDN clients use to access SimpleAuth (becomes HTTP/hostname SPN)</div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${setupKerberos}>Setup Kerberos</button>
        </div>
      <//>
    `}

    ${modal === 'krb-cleanup' && html`
      <${Modal} title="Remove Kerberos" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">This will delete the local keytab and disable Kerberos. Optionally provide AD admin credentials to also remove the SPN from Active Directory.</p>
        <div class="form-group">
          <label class="form-label">AD Admin Username (optional)</label>
          <input class="form-input" value=${form.cleanup_username || ''} onInput=${e => setForm({ ...form, cleanup_username: e.target.value })} placeholder="admin@corp.local" />
        </div>
        <div class="form-group">
          <label class="form-label">AD Admin Password (optional)</label>
          <input class="form-input" type="password" value=${form.cleanup_password || ''} onInput=${e => setForm({ ...form, cleanup_password: e.target.value })} />
        </div>
        <div class="form-help" style="margin-bottom:var(--sp-3)">Leave empty to only remove local config without touching AD.</div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-danger" onClick=${cleanupKerberos}>Remove Kerberos</button>
        </div>
      <//>
    `}

    ${modal === 'generate-script' && html`
      <${Modal} title="Generate AD Setup Script" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">Generate a PowerShell script to run on a Domain Controller. The script will interactively guide the AD admin through creating a service account, selecting an OU, and optionally setting up Kerberos.</p>
        <div class="form-group">
          <label class="form-label">Service Account Name</label>
          <input class="form-input" value=${form.script_account || ''} onInput=${e => setForm({ ...form, script_account: e.target.value })} placeholder="svc-sauth-simpleauth" />
        </div>
        <div class="form-group">
          <label class="form-label">Password</label>
          <div style="display:flex;gap:var(--sp-2)">
            <input class="form-input" style="flex:1" value=${form.script_password || ''} onInput=${e => setForm({ ...form, script_password: e.target.value })} placeholder="Strong password for the service account" />
            <button class="btn btn-secondary" style="white-space:nowrap" onClick=${() => {
              const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%&*';
              let pw = ''; for (let i = 0; i < 24; i++) pw += chars[Math.floor(Math.random() * chars.length)];
              setForm({ ...form, script_password: pw });
            }}>Generate</button>
          </div>
        </div>
        <div style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius);padding:var(--sp-3);margin-top:var(--sp-3);font-size:0.8rem;color:var(--text-secondary)">
          <strong style="color:var(--text-primary)">The script will interactively:</strong>
          <ul style="margin:var(--sp-1) 0 0 var(--sp-3);padding:0">
            <li>Auto-detect domain, base DN, and domain controller</li>
            <li>List OUs and let the admin pick where to create the account</li>
            <li>Ask if Kerberos SSO should be enabled</li>
            <li>Export <code>simpleauth-config.json</code> to bring back here</li>
          </ul>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${generateScript}>Download Script</button>
        </div>
      <//>
    `}

    ${modal === 'import-config' && html`
      <${Modal} title="Import AD Config" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">Upload the <strong>simpleauth-config.json</strong> file generated by the setup script. SimpleAuth will connect and configure everything automatically.</p>
        <div class="form-group">
          <label class="form-label">Config File</label>
          <input type="file" accept=".json" onChange=${handleFileImport} style="margin-bottom:var(--sp-2)" />
        </div>
        ${form.import_json && html`
          <div class="form-group">
            <label class="form-label">Preview</label>
            <pre style="background:var(--bg-tertiary);border:1px solid var(--border);border-radius:var(--radius);padding:var(--sp-2);font-size:0.8rem;overflow-x:auto;max-height:200px">${(() => {
              try { const c = JSON.parse(form.import_json); return JSON.stringify({...c, password: '***'}, null, 2); }
              catch { return 'Invalid JSON'; }
            })()}</pre>
          </div>
        `}
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" disabled=${!form.import_json} onClick=${importConfig}>Import & Configure</button>
        </div>
      <//>
    `}
    ${modal === 'sync-user' && html`
      <${Modal} title="Sync User from AD" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">Enter the sAMAccountName of a user to sync their profile (display name, email, department, company, job title) from Active Directory.</p>
        <div class="form-group">
          <label class="form-label">Username (sAMAccountName)</label>
          <input class="form-input" value=${form.sync_username || ''} onInput=${e => setForm({ ...form, sync_username: e.target.value })} placeholder="alice" />
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" disabled=${!form.sync_username} onClick=${syncSingleUser}>Sync User</button>
        </div>
      <//>
    `}
    ${toast && html`<${Toast} ...${toast} />`}
  `;
}

// === Impersonate Page ===
function ImpersonatePage() {
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState('');
  const [result, setResult] = useState(null);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    api('GET', '/api/admin/users').then(setUsers).catch(() => {});
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

  const eventTypes = ['login_success', 'login_failed', 'impersonation', 'user_created', 'user_merged', 'role_changed'];

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
    { id: 'roles', label: 'Roles', icon: icons.roles },
    { id: 'ldap', label: 'LDAP Providers', icon: icons.ldap },
    { id: 'mappings', label: 'Mappings', icon: icons.mappings },
    { id: 'impersonate', label: 'Impersonate', icon: icons.impersonate },
    { id: 'audit', label: 'Audit Log', icon: icons.audit },
  ];

  const pages = {
    dashboard: Dashboard,
    users: UsersPage,
    roles: RolesPage,
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
