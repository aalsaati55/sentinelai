const BASE = '/api'

// ── Token helpers ─────────────────────────────────────────────
export const token = {
  get:    ()      => localStorage.getItem('sentinel_token'),
  set:    (t)     => localStorage.setItem('sentinel_token', t),
  remove: ()      => localStorage.removeItem('sentinel_token'),
  user:   ()      => {
    const raw = localStorage.getItem('sentinel_user')
    return raw ? JSON.parse(raw) : null
  },
  setUser: (u)    => localStorage.setItem('sentinel_user', JSON.stringify(u)),
  clear:   ()     => { localStorage.removeItem('sentinel_token'); localStorage.removeItem('sentinel_user') },
}

function authHeaders() {
  const t = token.get()
  return t ? { Authorization: `Bearer ${t}` } : {}
}

async function get(path) {
  const r = await fetch(BASE + path, { headers: authHeaders() })
  if (r.status === 401) { token.clear(); window.location.reload(); return }
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json()
}

async function patch(path, body) {
  const r = await fetch(BASE + path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  })
  if (r.status === 401) { token.clear(); window.location.reload(); return }
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json()
}

export const api = {
  // Dashboard
  summary:          () => get('/dashboard/summary'),
  topIps:           (limit = 10) => get(`/dashboard/top-ips?limit=${limit}`),
  severity:         () => get('/dashboard/severity'),
  eventTypes:       () => get('/dashboard/event-types'),
  timeline:         (bucket = 'hour') => get(`/dashboard/timeline?bucket=${bucket}`),
  incidentTimeline: (days = 30) => get(`/dashboard/incident-timeline?days=${days}`),
  alertTimeline:    (days = 30) => get(`/dashboard/alert-timeline?days=${days}`),
  riskTrend:        (days = 7)  => get(`/dashboard/risk-trend?days=${days}`),
  mttdMttr:         ()          => get('/dashboard/mttd-mttr'),
  teamActivity:     ()          => get('/dashboard/team-activity'),
  fpStats:          ()          => get('/dashboard/fp-stats'),

  // Events
  events: (params = {}) => {
    const q = new URLSearchParams({ limit: 300, ...params }).toString()
    return get(`/events?${q}`)
  },
  eventsDistinctTypes: () => get(`/events/types`),
  eventCount: () => get('/events/count'),

  // Alerts
  alerts: (params = {}) => {
    const q = new URLSearchParams({ limit: 200, ...params }).toString()
    return get(`/alerts?${q}`)
  },
  alertCount: (severity) => get(`/alerts/count${severity ? `?severity=${severity}` : ''}`),

  // Incidents
  incidents: (params = {}) => {
    const q = new URLSearchParams({ limit: 200, ...params }).toString()
    return get(`/incidents?${q}`)
  },
  incident:      (id) => get(`/incidents/${id}`),
  incidentEvents:(id) => get(`/incidents/${id}/events`),
  updateStatus:  (id, status) => patch(`/incidents/${id}/status`, { status }),
  assignIncident:(id, assigned_to) => patch(`/incidents/${id}/assign`, { assigned_to }),
  incidentNotes: (id) => get(`/incidents/${id}/notes`),
  addNote:       (id, note) => {
    return fetch(`${BASE}/incidents/${id}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ note }),
    }).then(async r => {
      if (!r.ok) { const e = await r.json().catch(()=>({})); throw new Error(e.detail || 'Failed') }
      return r.json()
    })
  },

  // CSV exports — authenticated fetch then trigger browser download
  exportIncidentsCsv: async (status = '') => {
    const q = status ? `?status=${status}` : ''
    const r = await fetch(`${BASE}/incidents/export/csv${q}`, { headers: authHeaders() })
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'incidents.csv'; a.click(); URL.revokeObjectURL(url)
  },
  exportAlertsCsv: async (severity = '') => {
    const q = severity ? `?severity=${severity}` : ''
    const r = await fetch(`${BASE}/alerts/export/csv${q}`, { headers: authHeaders() })
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'alerts.csv'; a.click(); URL.revokeObjectURL(url)
  },
  exportAuditCsv: async () => {
    const r = await fetch(`${BASE}/audit/export/csv`, { headers: authHeaders() })
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'audit_log.csv'; a.click(); URL.revokeObjectURL(url)
  },

  // Alert Tuning
  tuningRules:      () => get('/tuning/rules'),
  tuningThresholds: () => get('/tuning/thresholds'),
  tuningSetThreshold: (rule_name, threshold) => fetch(`${BASE}/tuning/thresholds`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ rule_name, threshold }),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),
  tuningResetThreshold: (rule_name) => fetch(`${BASE}/tuning/thresholds/${encodeURIComponent(rule_name)}`, {
    method: 'DELETE', headers: authHeaders(),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),

  // Alert notes
  alertNotes:   (id) => get(`/alerts/${id}/notes`),
  addAlertNote: (id, note) => fetch(`${BASE}/alerts/${id}/notes`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ note }),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),

  // Alert assign
  assignAlert: (id, assigned_to) => fetch(`${BASE}/alerts/${id}/assign`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ assigned_to }),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),

  // Suppression with expiry
  suppressRuleExpiry: (rule_name, reason = '', expires_at = null) => fetch(`${BASE}/suppression`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ rule_name, reason, expires_at }),
  }).then(r => { if (!r.ok) throw new Error('Failed'); return r.json() }),

  // False positive
  markAlertFP: (id, false_positive, reason = '') => fetch(`${BASE}/alerts/${id}/false-positive`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ false_positive, reason }),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),
  markIncidentFP: (id, false_positive, reason = '') => fetch(`${BASE}/incidents/${id}/false-positive`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ false_positive, reason }),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),

  // Suppression
  suppressedRules:  () => get('/suppression'),
  suppressRule:     (rule_name, reason = '') => {
    return fetch(`${BASE}/suppression`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ rule_name, reason }),
    }).then(r => { if (!r.ok) throw new Error('Failed'); return r.json() })
  },
  unsuppressRule:   (rule_name) => {
    return fetch(`${BASE}/suppression/${encodeURIComponent(rule_name)}`, {
      method: 'DELETE', headers: authHeaders(),
    }).then(r => { if (!r.ok) throw new Error('Failed'); return r.json() })
  },

  // GeoIP
  geoLookup:  (ip) => get(`/geoip/lookup?ip=${encodeURIComponent(ip)}`),
  geoBulk:    (ips) => fetch(`${BASE}/geoip/bulk`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() }, body: JSON.stringify({ ips }) }).then(r => r.json()),
  geoMap:     () => get('/geoip/map'),

  // Watchlist
  watchlist:          () => get('/watchlist'),
  watchlistCheck:     (ip) => get(`/watchlist/check/${encodeURIComponent(ip)}`),
  watchlistAdd:       (source_ip, reason = '') => {
    return fetch(`${BASE}/watchlist`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ source_ip, reason }),
    }).then(async r => {
      if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || 'Failed') }
      return r.json()
    })
  },
  watchlistRemove:    (ip) => fetch(`${BASE}/watchlist/${encodeURIComponent(ip)}`, {
    method: 'DELETE', headers: authHeaders(),
  }).then(r => { if (!r.ok) throw new Error('Failed'); return r.json() }),

  // Threat Intelligence
  threatIntel:      (ip) => get(`/threatintel/${encodeURIComponent(ip)}`),
  threatIntelBulk:  (ips) => fetch(`${BASE}/threatintel/bulk`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ ips }),
  }).then(r => r.json()),

  // Incident playbook + SOAR
  incidentPlaybook:   (id) => get(`/incidents/${id}/playbook`),
  incidentSoar:       (id) => get(`/incidents/${id}/soar`),
  riskTrend:          (days = 7) => get(`/dashboard/risk-trend?days=${days}`),
  mttdMttr:           () => get(`/dashboard/mttd-mttr`),
  teamActivity:       () => get(`/dashboard/team-activity`),

  // SOAR auto-execute
  soarExecute: (command, incidentId, label) => fetch(`${BASE}/soar/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ command, incident_id: incidentId, label }),
  }).then(r => r.json()),
  sshConfigGet: () => get('/soar/ssh-config'),
  sshConfigSave: (cfg) => fetch(`${BASE}/soar/ssh-config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(cfg),
  }).then(r => r.json()),
  sshConfigTest: () => fetch(`${BASE}/soar/ssh-test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
  }).then(async r => {
    const data = await r.json()
    if (!r.ok) throw new Error(data.detail || 'Connection failed')
    return data
  }),

  // SOAR audit log
  logSoarExecuted: (incidentId, label) => fetch(`${BASE}/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ action: 'soar_executed', target_type: 'incident', target_id: incidentId, detail: `SOAR: ${label}` }),
  }).then(r => r.json()).catch(() => {}),

  // Notifications
  notifications: (since) => get(`/notifications?since=${encodeURIComponent(since)}`),

  // Audit log
  auditLog: (params = {}) => {
    const q = new URLSearchParams({ limit: 200, ...params }).toString()
    return get(`/audit?${q}`)
  },

  // Dashboard charts
  incidentTimeline: (days = 30) => get(`/dashboard/incident-timeline?days=${days}`),
  alertTimeline:    (days = 30) => get(`/dashboard/alert-timeline?days=${days}`),

  // Auth
  login: async (username, password) => {
    const form = new URLSearchParams({ username, password })
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    })
    if (!r.ok) {
      const err = await r.json().catch(() => ({}))
      throw new Error(err.detail || 'Login failed')
    }
    return r.json()
  },
  register: async (username, email, password) => {
    const r = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    })
    if (!r.ok) {
      const err = await r.json().catch(() => ({}))
      throw new Error(err.detail || 'Registration failed')
    }
    return r.json()
  },
  me: () => get('/auth/me'),
  changePassword: (current_password, new_password) => fetch(`${BASE}/auth/change-password`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ current_password, new_password }),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),

  // User notifications
  userNotifications: (since) => get(`/auth/notifications${since ? `?since=${encodeURIComponent(since)}` : ''}`),
  markNotifsRead:    () => fetch(`${BASE}/auth/notifications/read`, { method: 'POST', headers: authHeaders() }),
  clearNotifs:       () => fetch(`${BASE}/auth/notifications`, { method: 'DELETE', headers: authHeaders() }),

  // MFA
  mfaStatus:  () => get('/auth/mfa/status'),
  mfaSetup:   () => fetch(`${BASE}/auth/mfa/setup`, { method: 'POST', headers: authHeaders() }).then(async r => {
    const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d
  }),
  mfaEnable:  (code) => fetch(`${BASE}/auth/mfa/enable`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ code }),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),
  mfaDisable: (code) => fetch(`${BASE}/auth/mfa/disable`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ code }),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),
  mfaConfirm: (mfa_token, code) => fetch(`${BASE}/auth/mfa/confirm`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfa_token, code }),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),

  // Scheduled reports (admin only)
  reportConfigGet:  () => get('/settings/reports'),
  reportConfigSave: (body) => fetch(`${BASE}/settings/reports`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),
  reportSendNow: () => fetch(`${BASE}/settings/reports/send-now`, {
    method: 'POST', headers: authHeaders(),
  }).then(async r => { const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Failed'); return d }),

  // User management (admin only)
  users:          () => get('/auth/users'),
  changeRole:     (id, role) => patch(`/auth/users/${id}/role`, { role }),
  deleteUser:     async (id) => {
    const r = await fetch(`${BASE}/auth/users/${id}`, {
      method: 'DELETE',
      headers: authHeaders(),
    })
    if (r.status === 401) { token.clear(); window.location.reload(); return }
    if (!r.ok) {
      const err = await r.json().catch(() => ({}))
      throw new Error(err.detail || 'Delete failed')
    }
  },
}
