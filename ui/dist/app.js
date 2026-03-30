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
  database: html`<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`,
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
  const [rolePerms, setRolePerms] = useState({});
  const [definedPerms, setDefinedPerms] = useState([]);
  const [selectedRole, setSelectedRole] = useState(null);
  const [newRoleName, setNewRoleName] = useState('');
  const [newPerm, setNewPerm] = useState('');
  const [newGlobalPerm, setNewGlobalPerm] = useState('');
  const [toast, setToast] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [confirmDeletePerm, setConfirmDeletePerm] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => setToast(null), 3000);
  };

  useEffect(() => {
    Promise.all([
      api('GET', '/api/admin/defaults/roles'),
      api('GET', '/api/admin/role-permissions'),
      api('GET', '/api/admin/permissions'),
    ]).then(([dRoles, rp, dp]) => {
      setDefaultRoles(dRoles || []);
      setRolePerms(rp || {});
      setDefinedPerms(dp || []);
    }).catch(() => {});
  }, []);

  const saveDefaultRoles = async (roles) => {
    try {
      await api('PUT', '/api/admin/defaults/roles', roles);
      setDefaultRoles(roles);
      showToast('Default roles updated');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const saveDefinedPerms = async (perms) => {
    try {
      await api('PUT', '/api/admin/permissions', perms);
      setDefinedPerms(perms);
    } catch (e) { showToast(e.message, 'error'); }
  };

  const saveRolePerms = async (mapping) => {
    try {
      await api('PUT', '/api/admin/role-permissions', mapping);
      setRolePerms(mapping);
      showToast('Saved');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const addRole = () => {
    const r = newRoleName.trim();
    if (!r || rolePerms[r]) return;
    const updated = { ...rolePerms, [r]: [] };
    setNewRoleName('');
    saveRolePerms(updated);
    setSelectedRole(r);
  };

  const deleteRole = (role) => {
    const updated = { ...rolePerms };
    delete updated[role];
    // Also remove from defaults if it was there
    const newDefaults = defaultRoles.filter(r => r !== role);
    if (newDefaults.length !== defaultRoles.length) {
      saveDefaultRoles(newDefaults);
    }
    saveRolePerms(updated);
    setSelectedRole(null);
    setConfirmDelete(false);
  };

  const toggleDefault = (role) => {
    if (defaultRoles.includes(role)) {
      saveDefaultRoles(defaultRoles.filter(r => r !== role));
    } else {
      saveDefaultRoles([...defaultRoles, role]);
    }
  };

  // Add a permission to the selected role (auto-registers in permission registry)
  const addPermission = async () => {
    const p = newPerm.trim();
    if (!p || !selectedRole || (rolePerms[selectedRole] || []).includes(p)) return;
    // Auto-register permission if not in registry
    if (!definedPerms.includes(p)) {
      await saveDefinedPerms([...definedPerms, p]);
    }
    const updated = { ...rolePerms, [selectedRole]: [...(rolePerms[selectedRole] || []), p] };
    setNewPerm('');
    saveRolePerms(updated);
  };

  const removePerm = (perm) => {
    if (!selectedRole) return;
    const updated = { ...rolePerms, [selectedRole]: (rolePerms[selectedRole] || []).filter(p => p !== perm) };
    saveRolePerms(updated);
  };

  // Add a global permission to the registry (not tied to any role)
  const addGlobalPerm = async () => {
    const p = newGlobalPerm.trim();
    if (!p || definedPerms.includes(p)) return;
    await saveDefinedPerms([...definedPerms, p]);
    setNewGlobalPerm('');
    showToast('Permission created');
  };

  // Delete a permission from registry and all roles
  const deleteGlobalPerm = async (perm) => {
    const newPerms = definedPerms.filter(p => p !== perm);
    // Also remove from all roles
    const updatedMapping = {};
    for (const [role, perms] of Object.entries(rolePerms)) {
      updatedMapping[role] = perms.filter(p => p !== perm);
    }
    await saveDefinedPerms(newPerms);
    await saveRolePerms(updatedMapping);
    setConfirmDeletePerm(null);
    showToast('Permission deleted');
  };

  const roleNames = Object.keys(rolePerms).sort();
  const selectedPerms = selectedRole ? (rolePerms[selectedRole] || []) : [];
  // Permissions available to add to the selected role (from registry, not already assigned)
  const availablePermsForRole = definedPerms.filter(p => !selectedPerms.includes(p));
  // Count how many roles use each permission
  const permUsage = {};
  for (const perms of Object.values(rolePerms)) {
    for (const p of perms) { permUsage[p] = (permUsage[p] || 0) + 1; }
  }

  return html`
    <div class="page-header"><h2>Roles & Permissions</h2></div>
    <div class="gold-bar" style="margin-bottom: var(--sp-8)"></div>

    <div class="roles-layout">
      <!-- Left: Roles list -->
      <div class="roles-sidebar">
        <div class="roles-sidebar-header">
          <h3>Roles</h3>
          <div style="font-size:0.75rem;color:var(--text-muted)">
            <span style="color:var(--brand-copper)">★</span> = auto-assigned to new users
          </div>
        </div>
        <div class="roles-list">
          ${roleNames.length === 0
            ? html`<div style="padding:var(--sp-4);text-align:center;color:var(--text-muted);font-size:0.8rem">No roles defined yet</div>`
            : roleNames.map(role => html`
              <div class="role-item ${selectedRole === role ? 'active' : ''}" onClick=${() => { setSelectedRole(role); setConfirmDelete(false); }}>
                <span class="role-name">${role}</span>
                <span class="role-perm-count">${(rolePerms[role] || []).length}</span>
                <span
                  class="role-default-star ${defaultRoles.includes(role) ? 'is-default' : ''}"
                  onClick=${(e) => { e.stopPropagation(); toggleDefault(role); }}
                  title=${defaultRoles.includes(role) ? 'Remove from default roles' : 'Make default role for new users'}
                >${defaultRoles.includes(role) ? '★' : '☆'}</span>
              </div>
            `)
          }
        </div>
        <div class="roles-add-form">
          <input class="form-input" style="padding:var(--sp-2) var(--sp-3);font-size:0.8rem" value=${newRoleName} onInput=${e => setNewRoleName(e.target.value)} placeholder="New role..." onKeyDown=${e => e.key === 'Enter' && addRole()} />
          <button class="btn btn-sm btn-primary" onClick=${addRole}>${icons.plus}</button>
        </div>
      </div>

      <!-- Right: Selected role detail OR permissions registry -->
      <div class="roles-detail">
        ${!selectedRole
          ? html`
            <div class="roles-detail-header">
              <h3>Permissions Registry</h3>
            </div>
            <div class="roles-detail-meta">All permissions that can be assigned to roles or directly to users</div>

            ${definedPerms.length === 0
              ? html`<div style="color:var(--text-muted);font-size:0.85rem;margin-bottom:var(--sp-4);padding:var(--sp-4);background:var(--bg-hover);border-radius:var(--radius-md);text-align:center">No permissions defined yet. Add some below, or they'll be auto-created when added to a role.</div>`
              : html`<div class="roles-perms-list">
                  ${definedPerms.map(p => html`
                    <span class="perm-tag">
                      ${p}
                      ${permUsage[p] ? html`<span class="perm-usage" title="Used by ${permUsage[p]} role(s)">${permUsage[p]}</span>` : null}
                      ${confirmDeletePerm === p
                        ? html`<span class="perm-confirm-delete">
                            <button class="perm-delete-yes" onClick=${() => deleteGlobalPerm(p)} title="Confirm delete">Yes</button>
                            <button class="perm-delete-no" onClick=${() => setConfirmDeletePerm(null)} title="Cancel">No</button>
                          </span>`
                        : html`<button onClick=${() => setConfirmDeletePerm(p)} title="Delete permission">×</button>`
                      }
                    </span>
                  `)}
                </div>`
            }

            <div style="display:flex;gap:var(--sp-2);margin-top:auto">
              <input class="form-input" value=${newGlobalPerm} onInput=${e => setNewGlobalPerm(e.target.value)} placeholder="New permission, e.g. documents:read" onKeyDown=${e => e.key === 'Enter' && addGlobalPerm()} />
              <button class="btn btn-sm btn-primary" style="white-space:nowrap" onClick=${addGlobalPerm}>${icons.plus} Add</button>
            </div>
          `
          : html`
            <div class="roles-detail-header">
              <h3>${selectedRole}</h3>
              <div style="display:flex;gap:var(--sp-2);align-items:center">
                <button class="btn btn-sm btn-secondary" onClick=${() => { setSelectedRole(null); setConfirmDelete(false); }}>View All Permissions</button>
                ${!confirmDelete
                  ? html`<button class="btn btn-sm btn-danger" onClick=${() => setConfirmDelete(true)}>Delete Role</button>`
                  : html`<div style="display:flex;gap:var(--sp-2);align-items:center">
                      <span style="font-size:0.8rem;color:var(--status-error-text)">Sure?</span>
                      <button class="btn btn-sm btn-danger" onClick=${() => deleteRole(selectedRole)}>Yes, delete</button>
                      <button class="btn btn-sm btn-secondary" onClick=${() => setConfirmDelete(false)}>Cancel</button>
                    </div>`
                }
              </div>
            </div>
            <div class="roles-detail-meta">
              ${defaultRoles.includes(selectedRole)
                ? html`<span style="color:var(--brand-copper)">★</span> Default role — automatically assigned to new users on first login`
                : 'Not a default role'}
              <span style="margin-left:var(--sp-3)">·</span>
              <span style="margin-left:var(--sp-3)">${selectedPerms.length} permission${selectedPerms.length !== 1 ? 's' : ''}</span>
            </div>

            <div style="font-size:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);margin-bottom:var(--sp-3)">Permissions</div>

            ${selectedPerms.length === 0
              ? html`<div style="color:var(--text-muted);font-size:0.85rem;margin-bottom:var(--sp-4);padding:var(--sp-4);background:var(--bg-hover);border-radius:var(--radius-md);text-align:center">No permissions assigned to this role yet</div>`
              : html`<div class="roles-perms-list">
                  ${selectedPerms.map(p => html`
                    <span class="perm-tag">
                      ${p}
                      <button onClick=${() => removePerm(p)} title="Remove from role">×</button>
                    </span>
                  `)}
                </div>`
            }

            <div style="display:flex;gap:var(--sp-2);margin-top:auto">
              <input class="form-input" list="perm-suggestions" value=${newPerm} onInput=${e => setNewPerm(e.target.value)} placeholder="Add permission..." onKeyDown=${e => e.key === 'Enter' && addPermission()} />
              <datalist id="perm-suggestions">
                ${availablePermsForRole.map(p => html`<option value=${p} />`)}
              </datalist>
              <button class="btn btn-sm btn-primary" style="white-space:nowrap" onClick=${addPermission}>${icons.plus} Add</button>
            </div>
          `
        }
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
  const [definedPermsList, setDefinedPermsList] = useState([]);

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
    try {
      const dp = await api('GET', '/api/admin/permissions');
      setDefinedPermsList(dp || []);
    } catch { setDefinedPermsList([]); }
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
          <strong style="font-size:0.875rem;display:block;margin-bottom:var(--sp-3)">Roles</strong>

          ${Object.keys(roleDefs).length > 0 ? html`
            <div style="display:flex;flex-direction:column;gap:var(--sp-2);margin-bottom:var(--sp-5)">
              ${Object.keys(roleDefs).sort().map(r => html`
                <label style="display:flex;align-items:center;gap:var(--sp-2);cursor:pointer;font-size:0.875rem">
                  <input type="checkbox" checked=${roles.includes(r)} onChange=${() => {
                    const updated = roles.includes(r) ? roles.filter(x => x !== r) : [...roles, r];
                    api('PUT', '/api/admin/users/' + detail.guid + '/roles', updated).then(() => { setRoles(updated); showToast(roles.includes(r) ? 'Role removed' : 'Role added'); }).catch(e => showToast(e.message, 'error'));
                  }} style="width:16px;height:16px;accent-color:var(--btn-primary-bg)" />
                  <span>${r}</span>
                  <span style="font-size:0.7rem;color:var(--text-muted)">(${(roleDefs[r] || []).length} perms)</span>
                </label>
              `)}
            </div>
          ` : html`<div style="color:var(--text-muted);font-size:0.85rem;margin-bottom:var(--sp-5)">No roles defined. Create roles on the Roles & Permissions page first.</div>`}

          <strong style="font-size:0.875rem;display:block;margin-bottom:var(--sp-1)">Direct Permissions</strong>
          <div style="font-size:0.8rem;color:var(--text-muted);margin-bottom:var(--sp-3)">Extra permissions on top of what roles grant.</div>
          <div style="display:flex;flex-wrap:wrap;gap:var(--sp-2);margin-bottom:var(--sp-3)">
            ${perms.map(p => html`
              <span class="perm-tag">
                ${p}
                <button onClick=${() => removePerm(p)} title="Remove">×</button>
              </span>
            `)}
            ${perms.length === 0 && html`<span style="color:var(--text-muted);font-size:0.85rem">None</span>`}
          </div>
          <div style="display:flex;gap:var(--sp-2)">
            <input class="form-input" style="flex:1" list="user-perm-suggestions" placeholder="Add permission..." value=${permInput} onInput=${e => setPermInput(e.target.value)} onKeyDown=${e => e.key === 'Enter' && addPerm()} />
            <datalist id="user-perm-suggestions">
              ${definedPermsList.filter(p => !perms.includes(p)).map(p => html`<option value=${p} />`)}
            </datalist>
            <button class="btn btn-sm btn-primary" onClick=${addPerm}>Add</button>
          </div>
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

    ${toast && html`<${Toast} ...${toast} />`}
  `;
}

// === LDAP Settings Page ===
function LDAPPage() {
  const [ldapConfig, setLdapConfig] = useState(null); // null = loading, false = not configured
  const [krbStatus, setKrbStatus] = useState(null);
  const [serverInfo, setServerInfo] = useState({});
  const [toast, setToast] = useState(null);
  const [wizardStep, setWizardStep] = useState(0); // 0=connect, 1=verify, 2=sso, 3=done
  const [form, setForm] = useState({});
  const [modal, setModal] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState(null); // null, 'ok', 'error'
  const [testUserResult, setTestUserResult] = useState(null);
  const [editing, setEditing] = useState(null); // which section is being edited
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState(null); // null = not searched, [] = no results
  const [searchLoading, setSearchLoading] = useState(false);
  const [selectedImports, setSelectedImports] = useState(new Set());

  const load = () => {
    api('GET', '/api/admin/ldap').then(cfg => {
      setLdapConfig(cfg || false);
      if (cfg && cfg.url) setConnectionStatus('ok');
    }).catch(() => setLdapConfig(false));
    api('GET', '/api/admin/kerberos/status').then(setKrbStatus).catch(() => {});
    api('GET', '/api/admin/server-info').then(setServerInfo).catch(() => {});
  };
  useEffect(load, []);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => setToast(null), 3000);
  };

  // --- Wizard Actions ---
  const autoDiscover = async () => {
    try {
      const result = await api('POST', '/api/admin/ldap/auto-discover', {
        server: form.server, username: form.username, password: form.password
      });
      setLdapConfig(result);
      setConnectionStatus('ok');
      setWizardStep(1);
      showToast('Connected and configured');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const saveManualConfig = async () => {
    try {
      await api('PUT', '/api/admin/ldap', form);
      const result = await api('POST', '/api/admin/ldap/test');
      if (result.status === 'ok') {
        setConnectionStatus('ok');
        setWizardStep(1);
        showToast('Connected');
      } else {
        setConnectionStatus('error');
        showToast('Saved but connection failed: ' + (result.error || ''), 'error');
      }
      load();
    } catch (e) { showToast(e.message, 'error'); }
  };

  const testUser = async (username) => {
    if (!username) return;
    try {
      const result = await api('POST', '/api/admin/ldap/test-user', { username });
      setTestUserResult(result);
      if (result.status === 'error') showToast(result.error, 'error');
    } catch (e) { showToast(e.message, 'error'); }
  };

  const setupKerberos = async () => {
    try {
      const result = await api('POST', '/api/admin/ldap/setup-kerberos', {
        service_hostname: form.service_hostname || serverInfo.hostname
      });
      showToast('Kerberos configured — SPN: ' + result.spn);
      if (result.spn_warning) showToast(result.spn_warning, 'warning');
      setWizardStep(3);
      load();
    } catch (e) { showToast(e.message, 'error'); }
  };

  const cleanupKerberos = async () => {
    try {
      await api('POST', '/api/admin/ldap/cleanup-kerberos', {
        username: form.cleanup_username, password: form.cleanup_password
      });
      showToast('Kerberos removed');
      setModal(null);
      load();
    } catch (e) { showToast(e.message, 'error'); }
  };

  const importConfig = async () => {
    try {
      const cfg = JSON.parse(form.import_json);
      const result = await api('POST', '/api/admin/ldap/import', cfg);
      showToast('Config imported');
      if (result.kerberos_error) showToast('Kerberos: ' + result.kerberos_error, 'warning');
      setModal(null);
      load();
    } catch (e) { showToast(e.message, 'error'); }
  };

  const saveConfig = async () => {
    try {
      await api('PUT', '/api/admin/ldap', form);
      showToast('Settings saved');
      setEditing(null);
      load();
    } catch (e) { showToast(e.message, 'error'); }
  };

  const deleteConfig = async () => {
    if (!confirm('Remove LDAP configuration? Users with local passwords will still be able to log in.')) return;
    try {
      await api('DELETE', '/api/admin/ldap');
      showToast('LDAP configuration removed');
      setLdapConfig(false);
      setConnectionStatus(null);
      setWizardStep(0);
    } catch (e) { showToast(e.message, 'error'); }
  };

  const testConnection = async () => {
    try {
      const result = await api('POST', '/api/admin/ldap/test');
      if (result.status === 'ok') { setConnectionStatus('ok'); showToast('Connection successful'); }
      else { setConnectionStatus('error'); showToast(result.error, 'error'); }
    } catch (e) { setConnectionStatus('error'); showToast(e.message, 'error'); }
  };

  const syncAll = async () => {
    try {
      const result = await api('POST', '/api/admin/ldap/sync-all');
      showToast(`Synced ${result.synced} users` + (result.failed ? `, ${result.failed} failed` : ''));
    } catch (e) { showToast(e.message, 'error'); }
  };

  const syncSingleUser = async () => {
    try {
      const result = await api('POST', '/api/admin/ldap/sync-user', { username: form.sync_username });
      showToast(`Synced: ${result.user.display_name || result.user.email}`);
      setModal(null);
    } catch (e) { showToast(e.message, 'error'); }
  };

  const searchLDAPUsers = async () => {
    if (!searchQuery.trim()) return;
    setSearchLoading(true);
    try {
      const results = await api('POST', '/api/admin/ldap/search-users', { query: searchQuery.trim(), limit: 50 });
      setSearchResults(results || []);
      setSelectedImports(new Set());
    } catch (e) { showToast(e.message, 'error'); }
    setSearchLoading(false);
  };

  const toggleImport = (username) => {
    const next = new Set(selectedImports);
    next.has(username) ? next.delete(username) : next.add(username);
    setSelectedImports(next);
  };

  const toggleAllImports = () => {
    if (!searchResults) return;
    const importable = searchResults.filter(r => !r.imported).map(r => r.username);
    if (selectedImports.size === importable.length) {
      setSelectedImports(new Set());
    } else {
      setSelectedImports(new Set(importable));
    }
  };

  const importSelectedUsers = async () => {
    if (selectedImports.size === 0) return;
    try {
      const results = await api('POST', '/api/admin/ldap/import-users', { usernames: [...selectedImports] });
      const imported = results.filter(r => r.status === 'imported').length;
      const existed = results.filter(r => r.status === 'exists').length;
      const failed = results.filter(r => r.status === 'error').length;
      let msg = `Imported ${imported} user${imported !== 1 ? 's' : ''}`;
      if (existed) msg += `, ${existed} already existed`;
      if (failed) msg += `, ${failed} failed`;
      showToast(msg);
      setSelectedImports(new Set());
      // Refresh search to update imported status
      searchLDAPUsers();
    } catch (e) { showToast(e.message, 'error'); }
  };

  const downloadSetupScript = async () => {
    try {
      const res = await fetch(BASE_PATH + '/api/admin/setup-script', {
        headers: { 'Authorization': `Bearer ${getApiKey()}` },
      });
      const text = await res.text();
      const bom = '\uFEFF';
      const blob = new Blob([bom + text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url;
      a.download = 'simpleauth-setup.ps1'; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { showToast(e.message, 'error'); }
  };

  const handleFileImport = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setForm({ ...form, import_json: ev.target.result });
    reader.readAsText(file);
  };

  // --- Loading ---
  if (ldapConfig === null) return html`<div class="page-header"><h2>LDAP Settings</h2></div><p>Loading...</p>`;

  // --- State Machine: Wizard (not configured) vs Dashboard (configured) ---
  const isConfigured = ldapConfig && ldapConfig.url;

  // ============================================================
  // WIZARD (before configuration)
  // ============================================================
  if (!isConfigured) {
    return html`
      <div class="page-header">
        <h2>LDAP Settings</h2>
        <div style="display:flex;gap:var(--sp-2)">
          <button class="btn btn-secondary" onClick=${() => { setModal('import-config'); setForm({}); }}>Import Config</button>
          <button class="btn btn-secondary" onClick=${downloadSetupScript}>AD Script</button>
        </div>
      </div>

      <div class="card" style="max-width:600px">
        <h3 style="margin-bottom:var(--sp-3)">Connect to Active Directory / LDAP</h3>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">Enter your domain or server address, and a service account to connect with.</p>

        <div class="form-group">
          <label class="form-label">Domain or Server</label>
          <input class="form-input" value=${form.server || ''} onInput=${e => setForm({ ...form, server: e.target.value })} placeholder="corp.contoso.com" />
          <div style="color:var(--text-muted);font-size:0.75rem;margin-top:2px">Domain name, hostname, or IP address. SimpleAuth will auto-discover the rest.</div>
        </div>
        <div class="form-group">
          <label class="form-label">Username</label>
          <input class="form-input" value=${form.username || ''} onInput=${e => setForm({ ...form, username: e.target.value })} placeholder="svc-simpleauth@corp.contoso.com" />
        </div>
        <div class="form-group">
          <label class="form-label">Password</label>
          <input class="form-input" type="password" value=${form.password || ''} onInput=${e => setForm({ ...form, password: e.target.value })} />
        </div>

        <div style="display:flex;gap:var(--sp-2);margin-top:var(--sp-4)">
          <button class="btn btn-primary" disabled=${!form.server || !form.username || !form.password} onClick=${autoDiscover}>Connect</button>
          <button class="btn btn-secondary" onClick=${() => {
            setForm({ url: '', base_dn: '', bind_dn: '', bind_password: '', username_attr: 'sAMAccountName', custom_filter: '', display_name_attr: 'displayName', email_attr: 'mail', department_attr: 'department', company_attr: 'company', job_title_attr: 'title', groups_attr: 'memberOf' });
            setModal('manual-setup');
          }}>Manual Setup</button>
        </div>
      </div>

      ${modal === 'manual-setup' && html`
        <${Modal} title="Manual LDAP Setup" onClose=${() => setModal(null)}>
          <div class="form-group"><label class="form-label">URL</label><input class="form-input" value=${form.url || ''} onInput=${e => setForm({ ...form, url: e.target.value })} placeholder="ldap://dc01.corp.local:389" /></div>
          <div class="form-group"><label class="form-label">Base DN</label><input class="form-input" value=${form.base_dn || ''} onInput=${e => setForm({ ...form, base_dn: e.target.value })} placeholder="DC=corp,DC=local" /></div>
          <div class="form-group"><label class="form-label">Bind DN</label><input class="form-input" value=${form.bind_dn || ''} onInput=${e => setForm({ ...form, bind_dn: e.target.value })} placeholder="CN=svc-simpleauth,CN=Users,DC=corp,DC=local" /></div>
          <div class="form-group"><label class="form-label">Bind Password</label><input class="form-input" type="password" value=${form.bind_password || ''} onInput=${e => setForm({ ...form, bind_password: e.target.value })} /></div>
          <div class="form-group">
            <label class="form-label">Username Attribute</label>
            <select class="form-input" value=${form.username_attr || 'sAMAccountName'} onChange=${e => setForm({ ...form, username_attr: e.target.value })}>
              <option value="sAMAccountName">sAMAccountName (Active Directory)</option>
              <option value="userPrincipalName">userPrincipalName (UPN)</option>
              <option value="uid">uid (OpenLDAP / FreeIPA)</option>
              <option value="mail">mail (Email)</option>
            </select>
          </div>
          <details style="margin-top:var(--sp-3)">
            <summary style="cursor:pointer;color:var(--text-secondary);font-size:0.875rem">Advanced</summary>
            <div style="margin-top:var(--sp-2)">
              <div class="form-group"><label class="form-label">Custom Filter</label><input class="form-input" value=${form.custom_filter || ''} onInput=${e => setForm({ ...form, custom_filter: e.target.value })} placeholder="e.g. (&(objectClass=person)(sAMAccountName={{username}}))" /><small style="color:var(--text-muted)">Overrides username attribute. Use {{username}} as placeholder.</small></div>
            </div>
          </details>
          <details style="margin-top:var(--sp-3)">
            <summary style="cursor:pointer;color:var(--text-secondary);font-size:0.875rem">Attribute Mapping</summary>
            <div style="margin-top:var(--sp-2)">
              <div class="form-group"><label class="form-label">Display Name</label><input class="form-input" value=${form.display_name_attr || ''} onInput=${e => setForm({ ...form, display_name_attr: e.target.value })} /></div>
              <div class="form-group"><label class="form-label">Email</label><input class="form-input" value=${form.email_attr || ''} onInput=${e => setForm({ ...form, email_attr: e.target.value })} /></div>
              <div class="form-group"><label class="form-label">Department</label><input class="form-input" value=${form.department_attr || ''} onInput=${e => setForm({ ...form, department_attr: e.target.value })} /></div>
              <div class="form-group"><label class="form-label">Company</label><input class="form-input" value=${form.company_attr || ''} onInput=${e => setForm({ ...form, company_attr: e.target.value })} /></div>
              <div class="form-group"><label class="form-label">Job Title</label><input class="form-input" value=${form.job_title_attr || ''} onInput=${e => setForm({ ...form, job_title_attr: e.target.value })} /></div>
              <div class="form-group"><label class="form-label">Groups</label><input class="form-input" value=${form.groups_attr || ''} onInput=${e => setForm({ ...form, groups_attr: e.target.value })} /></div>
            </div>
          </details>
          <div style="display:flex;gap:var(--sp-2);justify-content:flex-end;margin-top:var(--sp-4)">
            <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
            <button class="btn btn-primary" disabled=${!form.url || !form.base_dn} onClick=${() => { setModal(null); saveManualConfig(); }}>Save & Test</button>
          </div>
        <//>
      `}

      ${modal === 'import-config' && html`
        <${Modal} title="Import Config" onClose=${() => setModal(null)}>
          <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">Upload the <strong>simpleauth-config.json</strong> file generated by the AD setup script.</p>
          <input type="file" accept=".json" onChange=${handleFileImport} style="margin-bottom:var(--sp-3)" />
          ${form.import_json && html`<pre style="font-size:0.75rem;background:var(--bg-secondary);padding:var(--sp-2);border-radius:var(--radius);max-height:200px;overflow:auto">${form.import_json.replace(/"password":\s*"[^"]*"/, '"password": "••••••••"')}</pre>`}
          <div style="display:flex;gap:var(--sp-2);justify-content:flex-end;margin-top:var(--sp-4)">
            <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
            <button class="btn btn-primary" disabled=${!form.import_json} onClick=${importConfig}>Import</button>
          </div>
        <//>
      `}
      ${toast && html`<${Toast} ...${toast} />`}
    `;
  }

  // ============================================================
  // DASHBOARD (after configuration)
  // ============================================================
  return html`
    <div class="page-header">
      <h2>LDAP Settings</h2>
      <div style="display:flex;gap:var(--sp-2)">
        <button class="btn btn-secondary" onClick=${downloadSetupScript}>AD Script</button>
        <button class="btn btn-secondary" onClick=${() => { setModal('import-config'); setForm({}); }}>Import Config</button>
        <button class="btn btn-secondary" onClick=${syncAll}>Sync All Users</button>
        <button class="btn btn-secondary" onClick=${() => { setForm({}); setModal('sync-user'); }}>Sync User</button>
      </div>
    </div>

    <!-- Connection -->
    <div class="card" style="margin-bottom:var(--sp-4)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--sp-3)">
        <h3 style="margin:0;display:flex;align-items:center;gap:var(--sp-2)">
          Connection
          <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${connectionStatus === 'ok' ? 'var(--color-success,#22c55e)' : connectionStatus === 'error' ? 'var(--color-danger,#ef4444)' : 'var(--text-muted)'}"></span>
        </h3>
        <div style="display:flex;gap:var(--sp-2)">
          <button class="btn btn-secondary btn-sm" onClick=${testConnection}>Test</button>
          <button class="btn btn-secondary btn-sm" onClick=${() => { setEditing('connection'); setForm({...ldapConfig}); }}>Edit</button>
        </div>
      </div>
      ${editing !== 'connection' ? html`
        <div style="display:grid;grid-template-columns:120px 1fr;gap:var(--sp-1) var(--sp-3);font-size:0.875rem">
          <span style="color:var(--text-muted)">URL</span><span>${ldapConfig.url}</span>
          <span style="color:var(--text-muted)">Base DN</span><span>${ldapConfig.base_dn}</span>
          <span style="color:var(--text-muted)">Bind DN</span><span>${ldapConfig.bind_dn}</span>
          ${ldapConfig.domain && html`<span style="color:var(--text-muted)">Domain</span><span>${ldapConfig.domain}</span>`}
        </div>
      ` : html`
        <div class="form-group"><label class="form-label">URL</label><input class="form-input" value=${form.url || ''} onInput=${e => setForm({ ...form, url: e.target.value })} /></div>
        <div class="form-group"><label class="form-label">Base DN</label><input class="form-input" value=${form.base_dn || ''} onInput=${e => setForm({ ...form, base_dn: e.target.value })} /></div>
        <div class="form-group"><label class="form-label">Bind DN</label><input class="form-input" value=${form.bind_dn || ''} onInput=${e => setForm({ ...form, bind_dn: e.target.value })} /></div>
        <div class="form-group"><label class="form-label">Bind Password</label><input class="form-input" type="password" value=${form.bind_password || ''} onInput=${e => setForm({ ...form, bind_password: e.target.value })} /></div>
        <div style="display:flex;gap:var(--sp-2);margin-top:var(--sp-3)">
          <button class="btn btn-primary" onClick=${saveConfig}>Save</button>
          <button class="btn btn-secondary" onClick=${() => setEditing(null)}>Cancel</button>
        </div>
      `}
    </div>

    <!-- User Search & Attribute Mapping -->
    <div class="card" style="margin-bottom:var(--sp-4)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--sp-3)">
        <h3 style="margin:0">User Search & Attributes</h3>
        <button class="btn btn-secondary btn-sm" onClick=${() => { setEditing('attributes'); setForm({...ldapConfig}); }}>Edit</button>
      </div>
      ${editing !== 'attributes' ? html`
        <div style="display:grid;grid-template-columns:120px 1fr;gap:var(--sp-1) var(--sp-3);font-size:0.875rem;margin-bottom:var(--sp-4)">
          <span style="color:var(--text-muted)">Username Attr</span><span style="font-family:var(--font-mono)">${ldapConfig.username_attr || 'sAMAccountName'}</span>
          ${ldapConfig.custom_filter ? html`<span style="color:var(--text-muted)">Custom Filter</span><span style="font-family:var(--font-mono)">${ldapConfig.custom_filter}</span>` : ''}
          <span style="color:var(--text-muted)">Display Name</span><span>${ldapConfig.display_name_attr || '—'}</span>
          <span style="color:var(--text-muted)">Email</span><span>${ldapConfig.email_attr || '—'}</span>
          <span style="color:var(--text-muted)">Department</span><span>${ldapConfig.department_attr || '—'}</span>
          <span style="color:var(--text-muted)">Company</span><span>${ldapConfig.company_attr || '—'}</span>
          <span style="color:var(--text-muted)">Job Title</span><span>${ldapConfig.job_title_attr || '—'}</span>
          <span style="color:var(--text-muted)">Groups</span><span>${ldapConfig.groups_attr || '—'}</span>
        </div>
        <div style="border-top:1px solid var(--border);padding-top:var(--sp-3)">
          <div style="display:flex;gap:var(--sp-2);align-items:center">
            <input class="form-input" style="max-width:240px" value=${form.test_username || ''} onInput=${e => setForm({ ...form, test_username: e.target.value })} onKeyDown=${e => e.key === 'Enter' && testUser(form.test_username)} placeholder="Test username (sAMAccountName)" />
            <button class="btn btn-secondary btn-sm" disabled=${!form.test_username} onClick=${() => testUser(form.test_username)}>Look Up</button>
          </div>
          ${testUserResult && testUserResult.status === 'ok' && html`
            <div style="margin-top:var(--sp-3);display:grid;grid-template-columns:120px 1fr auto;gap:var(--sp-1) var(--sp-3);font-size:0.875rem;background:var(--bg-secondary);padding:var(--sp-3);border-radius:var(--radius)">
              <span style="color:var(--text-muted)">Display Name</span><span style="font-weight:500">${testUserResult.display_name || '—'}</span><span style="color:var(--text-muted);font-size:0.75rem">${ldapConfig.display_name_attr}</span>
              <span style="color:var(--text-muted)">Email</span><span>${testUserResult.email || '—'}</span><span style="color:var(--text-muted);font-size:0.75rem">${ldapConfig.email_attr}</span>
              <span style="color:var(--text-muted)">Department</span><span>${testUserResult.department || '—'}</span><span style="color:var(--text-muted);font-size:0.75rem">${ldapConfig.department_attr}</span>
              <span style="color:var(--text-muted)">Company</span><span>${testUserResult.company || '—'}</span><span style="color:var(--text-muted);font-size:0.75rem">${ldapConfig.company_attr}</span>
              <span style="color:var(--text-muted)">Job Title</span><span>${testUserResult.job_title || '—'}</span><span style="color:var(--text-muted);font-size:0.75rem">${ldapConfig.job_title_attr}</span>
              <span style="color:var(--text-muted)">Groups</span><span style="grid-column:span 2">${(testUserResult.groups || []).join(', ') || '—'}</span>
            </div>
          `}
        </div>
      ` : html`
        <div class="form-group">
          <label class="form-label">Username Attribute</label>
          <select class="form-input" value=${form.username_attr || 'sAMAccountName'} onChange=${e => setForm({ ...form, username_attr: e.target.value })}>
            <option value="sAMAccountName">sAMAccountName (Active Directory)</option>
            <option value="userPrincipalName">userPrincipalName (UPN)</option>
            <option value="uid">uid (OpenLDAP / FreeIPA)</option>
            <option value="mail">mail (Email)</option>
          </select>
        </div>
        <details>
          <summary style="cursor:pointer;color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-2)">Advanced</summary>
          <div class="form-group"><label class="form-label">Custom Filter</label><input class="form-input" value=${form.custom_filter || ''} onInput=${e => setForm({ ...form, custom_filter: e.target.value })} placeholder="e.g. (&(objectClass=person)(sAMAccountName={{username}}))" /><small style="color:var(--text-muted)">Overrides username attribute. Use {{username}} as placeholder.</small></div>
        </details>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-2)">
          <div class="form-group"><label class="form-label">Display Name Attr</label><input class="form-input" value=${form.display_name_attr || ''} onInput=${e => setForm({ ...form, display_name_attr: e.target.value })} /></div>
          <div class="form-group"><label class="form-label">Email Attr</label><input class="form-input" value=${form.email_attr || ''} onInput=${e => setForm({ ...form, email_attr: e.target.value })} /></div>
          <div class="form-group"><label class="form-label">Department Attr</label><input class="form-input" value=${form.department_attr || ''} onInput=${e => setForm({ ...form, department_attr: e.target.value })} /></div>
          <div class="form-group"><label class="form-label">Company Attr</label><input class="form-input" value=${form.company_attr || ''} onInput=${e => setForm({ ...form, company_attr: e.target.value })} /></div>
          <div class="form-group"><label class="form-label">Job Title Attr</label><input class="form-input" value=${form.job_title_attr || ''} onInput=${e => setForm({ ...form, job_title_attr: e.target.value })} /></div>
          <div class="form-group"><label class="form-label">Groups Attr</label><input class="form-input" value=${form.groups_attr || ''} onInput=${e => setForm({ ...form, groups_attr: e.target.value })} /></div>
        </div>
        <div style="display:flex;gap:var(--sp-2);margin-top:var(--sp-3)">
          <button class="btn btn-primary" onClick=${saveConfig}>Save</button>
          <button class="btn btn-secondary" onClick=${() => setEditing(null)}>Cancel</button>
        </div>
      `}
    </div>

    <!-- Kerberos SSO -->
    <div class="card" style="margin-bottom:var(--sp-4)">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--sp-3)">
        <h3 style="margin:0">Kerberos SSO</h3>
        ${krbStatus && krbStatus.configured ? html`
          <button class="btn btn-secondary btn-sm" style="color:var(--color-danger,#ef4444)" onClick=${() => { setForm({}); setModal('krb-cleanup'); }}>Remove Kerberos</button>
        ` : html`
          <button class="btn btn-primary btn-sm" onClick=${() => { setForm({ service_hostname: serverInfo.hostname }); setModal('krb-setup'); }}>Setup Kerberos</button>
        `}
      </div>
      ${krbStatus && krbStatus.configured ? html`
        <div style="display:grid;grid-template-columns:120px 1fr;gap:var(--sp-1) var(--sp-3);font-size:0.875rem">
          <span style="color:var(--text-muted)">Status</span><span style="color:var(--color-success,#22c55e);font-weight:500">Active</span>
          <span style="color:var(--text-muted)">SPN</span><span style="font-family:var(--font-mono)">${krbStatus.spn}</span>
          <span style="color:var(--text-muted)">Realm</span><span>${krbStatus.realm}</span>
          <span style="color:var(--text-muted)">Source</span><span>${krbStatus.source}</span>
        </div>
      ` : html`
        <p style="color:var(--text-secondary);font-size:0.875rem;margin:0">Not configured. Set up Kerberos to enable single sign-on (SSO) for domain-joined browsers.</p>
      `}
    </div>

    <!-- Import Users -->
    <div class="card" style="margin-bottom:var(--sp-4)">
      <h3 style="margin:0 0 var(--sp-3) 0">Import Users from LDAP</h3>
      <div style="display:flex;gap:var(--sp-2);margin-bottom:var(--sp-3)">
        <input class="form-input" style="flex:1" placeholder="Search by name, email, or username..." value=${searchQuery} onInput=${e => setSearchQuery(e.target.value)} onKeyDown=${e => e.key === 'Enter' && searchLDAPUsers()} />
        <button class="btn btn-primary" onClick=${searchLDAPUsers} disabled=${searchLoading || !searchQuery.trim()}>${searchLoading ? 'Searching...' : 'Search'}</button>
      </div>
      ${searchResults && searchResults.length > 0 && html`
        <div class="table-wrap" style="max-height:400px;overflow-y:auto">
          <table>
            <thead><tr>
              <th style="width:30px"><input type="checkbox" checked=${selectedImports.size > 0 && selectedImports.size === searchResults.filter(r => !r.imported).length} onChange=${toggleAllImports} /></th>
              <th>Username</th>
              <th>Name</th>
              <th>Email</th>
              <th>Status</th>
            </tr></thead>
            <tbody>
              ${searchResults.map(r => html`
                <tr style=${r.imported ? 'opacity:0.5' : ''}>
                  <td><input type="checkbox" disabled=${r.imported} checked=${r.imported || selectedImports.has(r.username)} onChange=${() => toggleImport(r.username)} /></td>
                  <td style="font-family:var(--font-mono);font-size:0.8rem">${r.username}</td>
                  <td>${r.display_name || '—'}</td>
                  <td>${r.email || '—'}</td>
                  <td>${r.imported ? html`<span class="badge badge-success">Imported</span>` : html`<span class="badge">New</span>`}</td>
                </tr>
              `)}
            </tbody>
          </table>
        </div>
        ${selectedImports.size > 0 && html`
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:var(--sp-3)">
            <span style="color:var(--text-secondary);font-size:0.875rem">${selectedImports.size} selected</span>
            <button class="btn btn-primary" onClick=${importSelectedUsers}>Import Selected</button>
          </div>
        `}
      `}
      ${searchResults && searchResults.length === 0 && html`
        <p style="color:var(--text-muted);font-size:0.875rem;margin:0">No users found matching "${searchQuery}"</p>
      `}
    </div>

    <!-- Danger Zone -->
    <div class="card" style="border-color:var(--color-danger,#ef4444)">
      <h3 style="margin:0 0 var(--sp-2) 0;color:var(--color-danger,#ef4444)">Danger Zone</h3>
      <div style="display:flex;justify-content:space-between;align-items:center">
        <p style="color:var(--text-secondary);font-size:0.875rem;margin:0">Remove LDAP configuration. Users with local passwords will still work.</p>
        <button class="btn btn-secondary btn-sm" style="color:var(--color-danger,#ef4444)" onClick=${deleteConfig}>Remove LDAP</button>
      </div>
    </div>

    <!-- Modals -->
    ${modal === 'krb-setup' && html`
      <${Modal} title="Setup Kerberos/SPNEGO" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">SimpleAuth will use the LDAP bind account to generate a Kerberos keytab and register the SPN.</p>
        <div class="form-group">
          <label class="form-label">Service Hostname</label>
          <input class="form-input" value=${form.service_hostname || ''} onInput=${e => setForm({ ...form, service_hostname: e.target.value })} placeholder="${serverInfo.hostname || 'simpleauth.corp.local'}" />
          <div style="color:var(--text-muted);font-size:0.75rem;margin-top:2px">The hostname users access SimpleAuth at. SPN will be HTTP/hostname.</div>
        </div>
        <div style="display:flex;gap:var(--sp-2);justify-content:flex-end;margin-top:var(--sp-4)">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" onClick=${() => { setModal(null); setupKerberos(); }}>Setup</button>
        </div>
      <//>
    `}

    ${modal === 'krb-cleanup' && html`
      <${Modal} title="Remove Kerberos" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">This will delete the local keytab. Optionally provide admin credentials to also remove the SPN from AD.</p>
        <div class="form-group"><label class="form-label">AD Admin Username (optional)</label><input class="form-input" value=${form.cleanup_username || ''} onInput=${e => setForm({ ...form, cleanup_username: e.target.value })} placeholder="admin@corp.local" /></div>
        <div class="form-group"><label class="form-label">AD Admin Password (optional)</label><input class="form-input" type="password" value=${form.cleanup_password || ''} onInput=${e => setForm({ ...form, cleanup_password: e.target.value })} /></div>
        <div style="display:flex;gap:var(--sp-2);justify-content:flex-end;margin-top:var(--sp-4)">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" style="background:var(--color-danger,#ef4444)" onClick=${cleanupKerberos}>Remove</button>
        </div>
      <//>
    `}

    ${modal === 'import-config' && html`
      <${Modal} title="Import Config" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">Upload the <strong>simpleauth-config.json</strong> file generated by the AD setup script.</p>
        <input type="file" accept=".json" onChange=${handleFileImport} style="margin-bottom:var(--sp-3)" />
        ${form.import_json && html`<pre style="font-size:0.75rem;background:var(--bg-secondary);padding:var(--sp-2);border-radius:var(--radius);max-height:200px;overflow:auto">${form.import_json.replace(/"password":\s*"[^"]*"/, '"password": "••••••••"')}</pre>`}
        <div style="display:flex;gap:var(--sp-2);justify-content:flex-end;margin-top:var(--sp-4)">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" disabled=${!form.import_json} onClick=${importConfig}>Import</button>
        </div>
      <//>
    `}

    ${modal === 'sync-user' && html`
      <${Modal} title="Sync User from AD" onClose=${() => setModal(null)}>
        <p style="color:var(--text-secondary);font-size:0.875rem;margin-bottom:var(--sp-4)">Enter the sAMAccountName of a user to sync their profile from Active Directory.</p>
        <div class="form-group">
          <label class="form-label">Username (sAMAccountName)</label>
          <input class="form-input" value=${form.sync_username || ''} onInput=${e => setForm({ ...form, sync_username: e.target.value })} placeholder="alice" />
        </div>
        <div style="display:flex;gap:var(--sp-2);justify-content:flex-end;margin-top:var(--sp-4)">
          <button class="btn btn-secondary" onClick=${() => setModal(null)}>Cancel</button>
          <button class="btn btn-primary" disabled=${!form.sync_username} onClick=${syncSingleUser}>Sync</button>
        </div>
      <//>
    `}
    ${toast && html`<${Toast} ...${toast} />`}
  `;
}

// === Impersonate Page ===
function ImpersonatePage() {
  const [users, setUsers] = useState([]);
  const [appURI, setAppURI] = useState('');
  const [selectedUser, setSelectedUser] = useState('');
  const [result, setResult] = useState(null);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    api('GET', '/api/admin/users').then(setUsers).catch(() => {});
    api('GET', '/api/admin/server-info').then(info => {
      if (info.redirect_uri) setAppURI(info.redirect_uri);
    }).catch(() => {});
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

  const launchInApp = () => {
    if (!result || !appURI) return;
    const fragment = `access_token=${encodeURIComponent(result.access_token)}&refresh_token=${encodeURIComponent(result.refresh_token || '')}&expires_in=${result.expires_in}&token_type=Bearer`;
    window.open(appURI + '#' + fragment, '_blank');
  };

  return html`
    <div class="page-header"><h2>Impersonate User</h2></div>
    <div class="card" style="max-width:600px">
      <div class="form-group">
        <label class="form-label">User</label>
        <select class="form-select" value=${selectedUser} onChange=${e => { setSelectedUser(e.target.value); setResult(null); }}>
          <option value="">Select a user...</option>
          ${users.map(u => html`<option value=${u.guid}>${u.display_name || u.guid} (${u.email || 'no email'})</option>`)}
        </select>
      </div>
      <button class="btn btn-primary" onClick=${impersonate} disabled=${!selectedUser}>Impersonate</button>

      ${result && html`
        <div style="margin-top:var(--sp-6)">
          <div class="gold-bar" style="margin-bottom:var(--sp-4)"></div>

          ${appURI && html`
            <button class="btn btn-primary" style="width:100%;margin-bottom:var(--sp-3)" onClick=${launchInApp}>Launch in App</button>
          `}

          <details>
            <summary style="cursor:pointer;color:var(--text-secondary);font-size:0.875rem">Raw Token</summary>
            <div style="margin-top:var(--sp-2)">
              <div style="position:relative">
                <textarea class="form-textarea" style="font-family:var(--font-mono);font-size:0.75rem;height:120px" readonly value=${result.access_token}></textarea>
                <button class="btn-icon" style="position:absolute;top:var(--sp-2);right:var(--sp-2)" onClick=${() => { navigator.clipboard.writeText(result.access_token); showToast('Copied'); }}>${icons.copy}</button>
              </div>
            </div>
          </details>
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

// === Database ===
function DatabasePage() {
  const [dbInfo, setDbInfo] = useState(null);
  const [pgUrl, setPgUrl] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [migrating, setMigrating] = useState(false);
  const [migrationStatus, setMigrationStatus] = useState(null);
  const [toast, setToast] = useState(null);

  useEffect(() => {
    api('GET', '/api/admin/database/info').then(setDbInfo);
    // Check if migration is running
    api('GET', '/api/admin/database/migrate/status').then(s => {
      if (s.state === 'running') {
        setMigrating(true);
        setMigrationStatus(s);
        pollStatus();
      } else if (s.state === 'completed' || s.state === 'failed') {
        setMigrationStatus(s);
      }
    });
  }, []);

  const pollStatus = () => {
    const interval = setInterval(async () => {
      const s = await api('GET', '/api/admin/database/migrate/status');
      setMigrationStatus(s);
      if (s.state !== 'running') {
        clearInterval(interval);
        setMigrating(false);
        if (s.state === 'completed') {
          setToast({ message: 'Migration completed successfully!', type: 'success' });
        } else if (s.state === 'failed') {
          setToast({ message: 'Migration failed: ' + s.error, type: 'error' });
        }
      }
    }, 2000);
  };

  const testConnection = async () => {
    setTestResult(null);
    const result = await api('POST', '/api/admin/database/test', { postgres_url: pgUrl });
    setTestResult(result);
  };

  const startMigration = async () => {
    if (!confirm('Start migration from BoltDB to PostgreSQL? This may take a while for large databases.')) return;
    setMigrating(true);
    setMigrationStatus({ state: 'running', progress: {} });
    await api('POST', '/api/admin/database/migrate', { postgres_url: pgUrl });
    pollStatus();
  };

  const progressPercent = migrationStatus && migrationStatus.total_items > 0
    ? Math.round((migrationStatus.migrated_items / migrationStatus.total_items) * 100)
    : 0;

  return html`
    <${Toast} message=${toast?.message} type=${toast?.type} />
    <div class="page-header"><h2>Database</h2></div>

    <div class="card">
      <div class="card-header"><h3>Current Backend</h3></div>
      <div class="card-body">
        <p><strong>Backend:</strong> ${dbInfo?.backend || 'loading...'}</p>
      </div>
    </div>

    ${dbInfo?.backend === 'boltdb' && html`
      <div class="card" style="margin-top: 16px;">
        <div class="card-header"><h3>Migrate to PostgreSQL</h3></div>
        <div class="card-body">
          <div style="margin-bottom: 12px;">
            <label style="display: block; font-size: 0.875rem; font-weight: 600; margin-bottom: 8px;">PostgreSQL Connection URL</label>
            <input type="text" value=${pgUrl} onInput=${e => setPgUrl(e.target.value)}
              placeholder="postgres://user:pass@host:5432/dbname?sslmode=disable"
              style="width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 0.875rem; font-family: monospace; background: var(--card); color: var(--text);" />
          </div>
          <div style="display: flex; gap: 8px; margin-bottom: 12px;">
            <button class="btn btn-secondary" onClick=${testConnection} disabled=${!pgUrl || migrating}>Test Connection</button>
            <button class="btn btn-primary" onClick=${startMigration} disabled=${!pgUrl || migrating || !testResult?.ok}>Start Migration</button>
          </div>

          ${testResult && html`
            <div class="alert ${testResult.ok ? 'alert-success' : 'alert-error'}">
              ${testResult.ok ? 'Connection successful!' : 'Connection failed: ' + testResult.error}
            </div>
          `}

          ${migrationStatus && migrationStatus.state !== 'idle' && html`
            <div style="margin-top: 16px;">
              <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                <span style="font-size: 0.875rem; font-weight: 600;">Migration ${migrationStatus.state}</span>
                <span style="font-size: 0.875rem; color: var(--muted);">
                  ${migrationStatus.migrated_items} / ${migrationStatus.total_items} items (${progressPercent}%)
                </span>
              </div>
              <div style="background: var(--border); border-radius: 4px; height: 8px; overflow: hidden;">
                <div style="background: var(--burgundy); height: 100%; width: ${progressPercent}%; transition: width 0.3s;"></div>
              </div>
              ${migrationStatus.progress && Object.keys(migrationStatus.progress).length > 0 && html`
                <div style="margin-top: 8px; font-size: 0.8rem; color: var(--muted);">
                  ${Object.entries(migrationStatus.progress).map(([table, status]) => html`
                    <span style="margin-right: 12px;">${table}: <strong>${status}</strong></span>
                  `)}
                </div>
              `}
              ${migrationStatus.state === 'completed' && html`
                <div class="alert alert-success" style="margin-top: 12px;">
                  Migration completed! Set <code>AUTH_POSTGRES_URL</code> in your environment and restart SimpleAuth to switch to PostgreSQL.
                </div>
              `}
              ${migrationStatus.state === 'failed' && html`
                <div class="alert alert-error" style="margin-top: 12px;">
                  Migration failed: ${migrationStatus.error}
                </div>
              `}
            </div>
          `}
        </div>
      </div>
    `}

    ${dbInfo?.backend === 'postgres' && html`
      <div class="card" style="margin-top: 16px;">
        <div class="card-body">
          <div class="alert alert-success">Running on PostgreSQL.</div>
        </div>
      </div>
    `}
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
    { id: 'ldap', label: 'LDAP Settings', icon: icons.ldap },
    { id: 'mappings', label: 'Mappings', icon: icons.mappings },
    { id: 'impersonate', label: 'Impersonate', icon: icons.impersonate },
    { id: 'audit', label: 'Audit Log', icon: icons.audit },
    { id: 'database', label: 'Database', icon: icons.database },
  ];

  const pages = {
    dashboard: Dashboard,
    users: UsersPage,
    roles: RolesPage,
    ldap: LDAPPage,
    mappings: MappingsPage,
    impersonate: ImpersonatePage,
    audit: AuditPage,
    database: DatabasePage,
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
