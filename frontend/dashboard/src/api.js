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
  summary:      () => get('/dashboard/summary'),
  topIps:       (limit = 10) => get(`/dashboard/top-ips?limit=${limit}`),
  severity:     () => get('/dashboard/severity'),
  eventTypes:   () => get('/dashboard/event-types'),
  timeline:     (bucket = 'hour') => get(`/dashboard/timeline?bucket=${bucket}`),

  // Events
  events: (params = {}) => {
    const q = new URLSearchParams({ limit: 300, ...params }).toString()
    return get(`/events?${q}`)
  },
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

  // Incident playbook
  incidentPlaybook:   (id) => get(`/incidents/${id}/playbook`),
  riskTrend:          (days = 7) => get(`/dashboard/risk-trend?days=${days}`),

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
