import { useEffect, useState } from 'react'
import { api } from '../api'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 19)
}

function severityFromScore(s) {
  if (s >= 80) return 'Critical'
  if (s >= 60) return 'High'
  if (s >= 30) return 'Medium'
  return 'Low'
}

const SEV_COLOR = {
  Critical: '#ef4444',
  High:     '#f97316',
  Medium:   '#eab308',
  Low:      '#22c55e',
}

function buildPrintHTML({ inc, events, notes, alerts, allMitre }) {
  const sev = severityFromScore(inc.risk_score)
  const sevColor = SEV_COLOR[sev] || '#111827'
  const now = new Date().toLocaleString()

  const mitreHTML = allMitre.length === 0 ? '' : `
    <section>
      <h2 class="section-title">MITRE ATT&amp;CK Techniques</h2>
      <div style="display:flex;flex-wrap:wrap;gap:8px;">
        ${allMitre.map(t => `
          <span style="display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:6px;background:#eef2ff;border:1px solid #c7d2fe;font-size:12px;">
            <b style="font-family:monospace;color:#4338ca;">${t.id}</b>
            <span style="color:#6366f1;">${t.name}</span>
          </span>`).join('')}
      </div>
    </section>`

  const alertsHTML = alerts.length === 0 ? '' : `
    <section>
      <h2 class="section-title">Related Alerts (${alerts.length})</h2>
      <table style="width:100%;border-collapse:collapse;font-size:12px;">
        <thead><tr style="background:#f9fafb;">
          ${['Rule','Severity','Score','Description','Time'].map(h => `<th style="padding:6px 8px;text-align:left;font-size:11px;font-weight:600;color:#6b7280;text-transform:uppercase;border-bottom:1px solid #e5e7eb;">${h}</th>`).join('')}
        </tr></thead>
        <tbody>
          ${alerts.map(a => `<tr style="border-top:1px solid #e5e7eb;">
            <td style="padding:5px 8px;font-family:monospace;font-size:11px;">${a.rule_name}</td>
            <td style="padding:5px 8px;font-weight:700;color:${SEV_COLOR[a.severity]||'#111'};">${a.severity}</td>
            <td style="padding:5px 8px;">${a.risk_score}</td>
            <td style="padding:5px 8px;font-size:11px;color:#6b7280;">${(a.description||'').slice(0,100)}${(a.description||'').length>100?'…':''}</td>
            <td style="padding:5px 8px;font-size:11px;white-space:nowrap;">${fmtTs(a.created_at)}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </section>`

  const eventsHTML = events.length === 0 ? '' : `
    <section>
      <h2 class="section-title">Event Timeline (${events.length} events)</h2>
      ${events.map((e, idx) => `
        <div style="display:flex;gap:12px;padding:10px 0;${idx > 0 ? 'border-top:1px solid #f3f4f6;' : ''}">
          <div style="display:flex;flex-direction:column;align-items:center;width:16px;">
            <div style="width:8px;height:8px;border-radius:50%;background:#6366f1;margin-top:4px;flex-shrink:0;"></div>
          </div>
          <div style="flex:1;">
            <div style="display:flex;justify-content:space-between;">
              <b style="font-size:12px;font-family:monospace;color:#1f2937;">${e.event_type}</b>
              <span style="font-size:11px;color:#9ca3af;">${fmtTs(e.timestamp)}</span>
            </div>
            <div style="font-size:11px;color:#6b7280;margin-top:2px;">
              ${[e.source_ip, e.username].filter(Boolean).join(' · ')}${e.message ? ' — ' + e.message : ''}
            </div>
          </div>
        </div>`).join('')}
    </section>`

  const notesHTML = notes.length === 0 ? '' : `
    <section>
      <h2 class="section-title">Investigation Notes (${notes.length})</h2>
      ${notes.map(n => `
        <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:10px 14px;margin-bottom:8px;">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
            <b style="font-size:12px;color:#3b82f6;">${n.username}</b>
            <span style="font-size:11px;color:#9ca3af;">${fmtTs(n.created_at)}</span>
          </div>
          <p style="font-size:13px;color:#374151;margin:0;">${n.note}</p>
        </div>`).join('')}
    </section>`

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>SentinelAI Incident Report — ${inc.title}</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 0; background: white; color: #111827; }
    .header { background: #0d1117; color: white; padding: 24px 32px; }
    .header-sub { font-size: 11px; color: #6b7280; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 4px; }
    h1 { font-size: 20px; font-weight: 700; margin: 0; }
    .summary-bar { display: flex; border-bottom: 1px solid #e5e7eb; }
    .summary-cell { flex: 1; padding: 12px 16px; border-right: 1px solid #e5e7eb; }
    .summary-label { font-size: 10px; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 3px; }
    .summary-value { font-size: 13px; font-weight: 600; }
    .body { padding: 24px 32px; }
    section { margin-bottom: 24px; }
    .section-title { font-size: 13px; font-weight: 700; color: #111827; text-transform: uppercase; letter-spacing: 0.06em; margin: 0 0 10px 0; padding-bottom: 6px; border-bottom: 2px solid #e5e7eb; }
    p { font-size: 13px; color: #374151; line-height: 1.6; margin: 0; }
    .footer { border-top: 1px solid #e5e7eb; padding-top: 16px; display: flex; justify-content: space-between; font-size: 11px; color: #9ca3af; }
    @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
  </style>
</head>
<body>
  <div class="header">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;">
      <div>
        <div class="header-sub">SentinelAI — Incident Report</div>
        <h1>${inc.title}</h1>
      </div>
      <div style="text-align:right;">
        <div style="font-size:12px;color:#9ca3af;">Generated</div>
        <div style="font-size:12px;color:#d1d5db;">${now}</div>
      </div>
    </div>
  </div>

  <div class="summary-bar">
    ${[
      ['Incident ID', `#${inc.id}`, null],
      ['Severity', sev, sevColor],
      ['Risk Score', `${inc.risk_score}/100`, null],
      ['Status', inc.status.toUpperCase(), null],
      ['Assigned To', inc.assigned_to || 'Unassigned', null],
      ['Created', fmtTs(inc.created_at), null],
    ].map(([k, v, color]) => `
      <div class="summary-cell">
        <div class="summary-label">${k}</div>
        <div class="summary-value" style="color:${color || '#111827'};">${v}</div>
      </div>`).join('')}
  </div>

  <div class="body">
    <section>
      <h2 class="section-title">Description</h2>
      <p>${inc.description || '—'}</p>
    </section>

    <section>
      <h2 class="section-title">Source Information</h2>
      <table style="font-size:13px;border-collapse:collapse;">
        ${[['Source IP', inc.source_ip||'—'],['Username', inc.username||'—'],['Anomaly Level', inc.anomaly_level||'—']].map(([k,v])=>`
          <tr><td style="padding:5px 16px 5px 0;color:#6b7280;font-weight:500;width:140px;">${k}</td><td style="padding:5px 8px;">${v}</td></tr>`).join('')}
      </table>
    </section>

    ${mitreHTML}
    ${alertsHTML}
    ${eventsHTML}
    ${notesHTML}

    <div class="footer">
      <span>SentinelAI — Confidential Security Report</span>
      <span>Incident #${inc.id} · ${fmtTs(inc.created_at)}</span>
    </div>
  </div>

  <script>window.onload = function(){ window.print(); }</script>
</body>
</html>`
}

export function IncidentReport({ id, onClose }) {
  const [inc, setInc]       = useState(null)
  const [events, setEvents] = useState([])
  const [notes, setNotes]   = useState([])
  const [alerts, setAlerts] = useState([])

  useEffect(() => {
    if (!id) return
    Promise.all([
      api.incident(id),
      api.incidentEvents(id),
      api.incidentNotes(id),
      api.alerts({ limit: 500 }),
    ]).then(([inc, evts, nts, allAlerts]) => {
      setInc(inc)
      setEvents(evts)
      setNotes(nts)
      const related = allAlerts.filter(a =>
        (inc.source_ip && a.source_ip === inc.source_ip) ||
        (inc.username  && a.username  === inc.username)
      ).slice(0, 20)
      setAlerts(related)
    })
  }, [id])

  function handlePrint() {
    if (!inc) return
    const mitreSet = new Map()
    alerts.forEach(a => (a.mitre_techniques || []).forEach(t => mitreSet.set(t.id, t)))
    const allMitre = [...mitreSet.values()]
    const html = buildPrintHTML({ inc, events, notes, alerts, allMitre })
    const win = window.open('', '_blank')
    win.document.write(html)
    win.document.close()
  }

  if (!inc) return (
    <div className="fixed inset-0 bg-black/60 z-[100] flex items-center justify-center">
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-8 text-slate-400">Loading report…</div>
    </div>
  )

  const sev = severityFromScore(inc.risk_score)
  const mitreSet = new Map()
  alerts.forEach(a => (a.mitre_techniques || []).forEach(t => mitreSet.set(t.id, t)))
  const allMitre = [...mitreSet.values()]

  return (
    <div className="fixed inset-0 bg-black/70 z-[100] flex items-center justify-center p-4">
      {/* Controls */}
      <div className="absolute top-4 right-4 flex gap-2 z-[110]">
        <button
          onClick={handlePrint}
          className="bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
        >
          Print / Save PDF
        </button>
        <button
          onClick={onClose}
          className="bg-[#1c2128] border border-[#30363d] hover:border-red-500 text-slate-300 text-sm px-4 py-2 rounded-lg transition-colors"
        >
          Close
        </button>
      </div>

      {/* Preview */}
      <div
        className="bg-white text-gray-900 w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-xl shadow-2xl"
        style={{ fontFamily: 'system-ui, sans-serif' }}
      >
        {/* Header */}
        <div style={{ background: '#0d1117', color: 'white', padding: '24px 32px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ fontSize: 11, color: '#6b7280', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4 }}>
                SentinelAI — Incident Report
              </div>
              <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>{inc.title}</h1>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: 12, color: '#9ca3af' }}>Generated</div>
              <div style={{ fontSize: 12, color: '#d1d5db' }}>{new Date().toLocaleString()}</div>
            </div>
          </div>
        </div>

        {/* Summary bar */}
        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid #e5e7eb' }}>
          {[
            ['Incident ID', `#${inc.id}`],
            ['Severity',    sev],
            ['Risk Score',  `${inc.risk_score}/100`],
            ['Status',      inc.status.toUpperCase()],
            ['Assigned To', inc.assigned_to || 'Unassigned'],
            ['Created',     fmtTs(inc.created_at)],
          ].map(([k, v]) => (
            <div key={k} style={{ flex: 1, padding: '12px 16px', borderRight: '1px solid #e5e7eb' }}>
              <div style={{ fontSize: 10, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>{k}</div>
              <div style={{
                fontSize: 13, fontWeight: 600,
                color: k === 'Severity' ? SEV_COLOR[v] : '#111827',
              }}>{v}</div>
            </div>
          ))}
        </div>

        <div style={{ padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: 24 }}>

          {/* Description */}
          <section>
            <h2 style={h2Style}>Description</h2>
            <p style={{ fontSize: 13, color: '#374151', lineHeight: 1.6, margin: 0 }}>{inc.description}</p>
          </section>

          {/* Source Info */}
          <section>
            <h2 style={h2Style}>Source Information</h2>
            <table style={tableStyle}>
              <tbody>
                {[
                  ['Source IP',  inc.source_ip  || '—'],
                  ['Username',   inc.username   || '—'],
                  ['Anomaly Level', inc.anomaly_level || '—'],
                ].map(([k, v]) => (
                  <tr key={k}>
                    <td style={tdLabelStyle}>{k}</td>
                    <td style={tdValueStyle}>{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          {/* MITRE ATT&CK */}
          {allMitre.length > 0 && (
            <section>
              <h2 style={h2Style}>MITRE ATT&CK Techniques</h2>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {allMitre.map(t => (
                  <div key={t.id} style={{
                    display: 'inline-flex', alignItems: 'center', gap: 6,
                    padding: '4px 10px', borderRadius: 6,
                    background: '#eef2ff', border: '1px solid #c7d2fe',
                    fontSize: 12,
                  }}>
                    <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#4338ca' }}>{t.id}</span>
                    <span style={{ color: '#6366f1' }}>{t.name}</span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Related Alerts */}
          {alerts.length > 0 && (
            <section>
              <h2 style={h2Style}>Related Alerts ({alerts.length})</h2>
              <table style={{ ...tableStyle, width: '100%' }}>
                <thead>
                  <tr style={{ background: '#f9fafb' }}>
                    {['Rule', 'Severity', 'Score', 'Description', 'Time'].map(h => (
                      <th key={h} style={thStyle}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {alerts.map(a => (
                    <tr key={a.id} style={{ borderTop: '1px solid #e5e7eb' }}>
                      <td style={{ ...tdValueStyle, fontFamily: 'monospace', fontSize: 11 }}>{a.rule_name}</td>
                      <td style={{ ...tdValueStyle, fontWeight: 700, color: SEV_COLOR[a.severity] || '#111' }}>{a.severity}</td>
                      <td style={tdValueStyle}>{a.risk_score}</td>
                      <td style={{ ...tdValueStyle, maxWidth: 240, fontSize: 11, color: '#6b7280' }}>{a.description?.slice(0, 100)}{a.description?.length > 100 ? '…' : ''}</td>
                      <td style={{ ...tdValueStyle, whiteSpace: 'nowrap', fontSize: 11 }}>{fmtTs(a.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {/* Timeline of Events */}
          {events.length > 0 && (
            <section>
              <h2 style={h2Style}>Event Timeline ({events.length} events)</h2>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {events.map((e, idx) => (
                  <div key={e.id} style={{ display: 'flex', gap: 12, paddingBottom: 10, paddingTop: idx > 0 ? 10 : 0, borderTop: idx > 0 ? '1px solid #f3f4f6' : 'none' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 16 }}>
                      <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#6366f1', marginTop: 4, flexShrink: 0 }} />
                      {idx < events.length - 1 && <div style={{ width: 1, flex: 1, background: '#e5e7eb', marginTop: 4 }} />}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: 12, fontWeight: 600, fontFamily: 'monospace', color: '#1f2937' }}>{e.event_type}</span>
                        <span style={{ fontSize: 11, color: '#9ca3af' }}>{fmtTs(e.timestamp)}</span>
                      </div>
                      <div style={{ fontSize: 11, color: '#6b7280', marginTop: 2 }}>
                        {[e.source_ip, e.username].filter(Boolean).join(' · ')} {e.message ? `— ${e.message}` : ''}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Investigation Notes */}
          {notes.length > 0 && (
            <section>
              <h2 style={h2Style}>Investigation Notes ({notes.length})</h2>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {notes.map(n => (
                  <div key={n.id} style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 8, padding: '10px 14px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: 12, fontWeight: 700, color: '#3b82f6' }}>{n.username}</span>
                      <span style={{ fontSize: 11, color: '#9ca3af' }}>{fmtTs(n.created_at)}</span>
                    </div>
                    <p style={{ fontSize: 13, color: '#374151', margin: 0 }}>{n.note}</p>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Footer */}
          <div style={{ borderTop: '1px solid #e5e7eb', paddingTop: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#9ca3af' }}>SentinelAI — Confidential Security Report</span>
            <span style={{ fontSize: 11, color: '#9ca3af' }}>Incident #{inc.id} · {fmtTs(inc.created_at)}</span>
          </div>
        </div>
      </div>
    </div>
  )
}

const h2Style = {
  fontSize: 13, fontWeight: 700, color: '#111827',
  textTransform: 'uppercase', letterSpacing: '0.06em',
  margin: '0 0 10px 0', paddingBottom: 6,
  borderBottom: '2px solid #e5e7eb',
}
const tableStyle = {
  fontSize: 13, borderCollapse: 'collapse',
}
const tdLabelStyle = {
  padding: '5px 16px 5px 0', color: '#6b7280',
  fontWeight: 500, width: 140, verticalAlign: 'top',
}
const tdValueStyle = {
  padding: '5px 8px', color: '#111827',
}
const thStyle = {
  padding: '6px 8px', textAlign: 'left',
  fontSize: 11, fontWeight: 600, color: '#6b7280',
  textTransform: 'uppercase', letterSpacing: '0.06em',
}
