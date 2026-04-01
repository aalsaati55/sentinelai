import { useEffect, useState } from 'react'
import { RefreshCw, X, ChevronDown } from 'lucide-react'
import { api } from '../api'
import { Panel } from '../components/Panel'
import { Badge, severityFromScore } from '../components/Badge'
import { ScoreBar } from '../components/ScoreBar'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

function IncidentModal({ id, onClose }) {
  const [inc, setInc]       = useState(null)
  const [status, setStatus] = useState('')
  const [saving, setSaving] = useState(false)
  const [events, setEvents] = useState([])

  useEffect(() => {
    if (!id) return
    Promise.all([api.incident(id), api.incidentEvents(id)]).then(([i, evts]) => {
      setInc(i)
      setStatus(i.status)
      setEvents(evts)
    })
  }, [id])

  async function save() {
    setSaving(true)
    try {
      await api.updateStatus(id, status)
      onClose(true)
    } finally { setSaving(false) }
  }

  if (!inc) return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center">
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-8 text-slate-400">Loading…</div>
    </div>
  )

  const sev = severityFromScore(inc.risk_score)

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b border-[#30363d]">
          <div>
            <h3 className="text-base font-semibold text-white mb-1">{inc.title}</h3>
            <div className="flex items-center gap-2 flex-wrap">
              <Badge value={sev} />
              <Badge value={inc.status} />
              {inc.anomaly_level && <Badge value={inc.anomaly_level} override={inc.anomaly_level} />}
            </div>
          </div>
          <button onClick={() => onClose()} className="text-slate-500 hover:text-slate-300 transition-colors ml-4 mt-0.5">
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-6">
          {/* KV grid */}
          <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            {[
              ['Incident ID', `#${inc.id}`],
              ['Source IP',   inc.source_ip  || '—'],
              ['Username',    inc.username   || '—'],
              ['Anomaly',     inc.anomaly_level || '—'],
              ['Created',     fmtTs(inc.created_at)],
            ].map(([k, v]) => (
              <div key={k} className="flex flex-col gap-0.5">
                <span className="text-xs text-slate-500 uppercase tracking-wider">{k}</span>
                <span className="text-slate-200 font-mono text-xs">{v}</span>
              </div>
            ))}
            <div className="flex flex-col gap-0.5">
              <span className="text-xs text-slate-500 uppercase tracking-wider">Risk Score</span>
              <ScoreBar score={inc.risk_score} />
            </div>
          </div>

          {/* Description */}
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Description</p>
            <div className="bg-[#1c2128] border border-[#30363d] rounded-lg p-4 text-sm text-slate-300 leading-relaxed">
              {inc.description}
            </div>
          </div>

          {/* Linked events */}
          {events.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Linked Events ({events.length})</p>
              <div className="bg-[#1c2128] border border-[#30363d] rounded-lg overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#30363d]">
                      {['Time', 'Type', 'IP', 'User', 'Status'].map(h => (
                        <th key={h} className="px-3 py-2 text-left text-slate-500 font-semibold uppercase tracking-wider">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {events.map(e => (
                      <tr key={e.id} className="border-t border-[#30363d]/50 hover:bg-white/[0.02]">
                        <td className="px-3 py-2 text-slate-400 whitespace-nowrap">{fmtTs(e.timestamp)}</td>
                        <td className="px-3 py-2 font-mono text-slate-300">{e.event_type}</td>
                        <td className="px-3 py-2 text-slate-400">{e.source_ip || '—'}</td>
                        <td className="px-3 py-2 text-slate-400">{e.username || '—'}</td>
                        <td className="px-3 py-2"><Badge value={e.status} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Status update */}
          <div className="flex items-center gap-3 pt-2 border-t border-[#30363d]">
            <span className="text-xs text-slate-500 uppercase tracking-wider">Update Status</span>
            <div className="relative">
              <select
                value={status}
                onChange={e => setStatus(e.target.value)}
                className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 pr-8 outline-none focus:border-blue-500 cursor-pointer"
              >
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="closed">Closed</option>
              </select>
              <ChevronDown size={14} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
            </div>
            <button
              onClick={save}
              disabled={saving}
              className="bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export function Incidents() {
  const [incidents, setIncidents] = useState([])
  const [filter, setFilter]       = useState('')
  const [loading, setLoading]     = useState(true)
  const [selected, setSelected]   = useState(null)

  async function load() {
    setLoading(true)
    const params = filter ? { status: filter } : {}
    try {
      setIncidents(await api.incidents(params))
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [filter])

  function handleModalClose(refresh) {
    setSelected(null)
    if (refresh) load()
  }

  return (
    <div className="space-y-5">
      {selected && <IncidentModal id={selected} onClose={handleModalClose} />}

      <div>
        <h2 className="text-xl font-bold text-white mb-1">Incidents</h2>
        <p className="text-sm text-slate-500">Correlated security incidents grouped from alerts</p>
      </div>

      <Panel>
        {/* Toolbar */}
        <div className="flex items-center gap-3 mb-5 flex-wrap">
          <div className="relative">
            <select
              value={filter}
              onChange={e => setFilter(e.target.value)}
              className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 pr-8 outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="closed">Closed</option>
            </select>
            <ChevronDown size={14} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
          </div>
          <button
            onClick={load}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <span className="text-xs text-slate-500 ml-1">{incidents.length} incidents</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['#', 'Title', 'Source IP', 'User', 'Risk Score', 'Anomaly', 'Status', 'Created', ''].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} className="py-10 text-center text-slate-500">Loading…</td></tr>
              ) : incidents.length ? incidents.map(i => (
                <tr key={i.id} className="border-t border-[#30363d] hover:bg-white/[0.02] transition-colors cursor-pointer"
                    onClick={() => setSelected(i.id)}>
                  <td className="py-3 pr-4 text-slate-500 text-xs">{i.id}</td>
                  <td className="py-3 pr-4 text-slate-200 max-w-[220px]">
                    <span className="truncate block">{i.title}</span>
                  </td>
                  <td className="py-3 pr-4 text-slate-400 font-mono text-xs">{i.source_ip || '—'}</td>
                  <td className="py-3 pr-4 text-slate-400">{i.username || '—'}</td>
                  <td className="py-3 pr-4"><ScoreBar score={i.risk_score} /></td>
                  <td className="py-3 pr-4">
                    {i.anomaly_level ? <Badge value={i.anomaly_level} /> : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="py-3 pr-4"><Badge value={i.status} /></td>
                  <td className="py-3 pr-4 text-slate-500 text-xs whitespace-nowrap">{fmtTs(i.created_at)}</td>
                  <td className="py-3">
                    <button
                      onClick={e => { e.stopPropagation(); setSelected(i.id) }}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      Details
                    </button>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan={9} className="py-10 text-center text-slate-500 text-sm">
                  No incidents found. Run the pipeline to generate data.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
