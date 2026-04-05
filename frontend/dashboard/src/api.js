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
