const BASE = '/api'

async function get(path) {
  const r = await fetch(BASE + path)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return r.json()
}

async function patch(path, body) {
  const r = await fetch(BASE + path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
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
}
