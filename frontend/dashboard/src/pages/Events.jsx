import { useEffect, useState } from 'react'
import { RefreshCw, ChevronDown, Download } from 'lucide-react'
import { api } from '../api'
import { Panel } from '../components/Panel'
import { Badge } from '../components/Badge'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

export function Events() {
  const [events, setEvents]       = useState([])
  const [loading, setLoading]     = useState(true)
  const [source, setSource]       = useState('')
  const [evtType, setEvtType]     = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [ipFilter, setIpFilter]   = useState('')
  const [ipInput, setIpInput]     = useState('')
  const [eventTypes, setEventTypes] = useState([])

  async function load() {
    setLoading(true)
    const params = { limit: 300 }
    if (source)       params.log_source = source
    if (evtType)      params.event_type = evtType
    if (ipFilter)     params.source_ip  = ipFilter
    if (statusFilter) params.status     = statusFilter
    try {
      setEvents(await api.events(params))
    } finally { setLoading(false) }
  }

  useEffect(() => {
    api.eventsDistinctTypes().then(types => setEventTypes(types)).catch(() => {})
  }, [])

  useEffect(() => { load() }, [source, evtType, ipFilter, statusFilter])

  function applyIp() { setIpFilter(ipInput.trim()) }

  function exportFilteredCsv() {
    if (events.length === 0) return
    const headers = ['ID','Timestamp','Source','Type','Source IP','User','Host','Status','Message']
    const escape = v => `"${String(v ?? '').replace(/"/g, '""')}"`
    const lines = [
      headers.join(','),
      ...events.map(e => [
        e.id,
        escape(fmtTs(e.timestamp)),
        escape(e.log_source || ''),
        escape(e.event_type || ''),
        escape(e.source_ip || ''),
        escape(e.username || ''),
        escape(e.hostname || ''),
        escape(e.status || ''),
        escape(e.message || ''),
      ].join(','))
    ].join('\n')
    const blob = new Blob([lines], { type: 'text/csv;charset=utf-8;' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    const suffix = [source, evtType, ipFilter, statusFilter].filter(Boolean).join('_') || 'all'
    a.download = `events_${suffix}_${new Date().toISOString().slice(0,10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  function statusOverride(status) {
    if (status === 'success') return 'success'
    if (status === 'failure') return 'failure'
    return 'info'
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="page-title">Events</h2>
        <p className="page-sub">Raw parsed and normalized log events</p>
      </div>

      <Panel>
        {/* Toolbar */}
        <div className="toolbar">
          <div className="relative">
            <select value={source} onChange={e => setSource(e.target.value)} className="ctrl-select">
              <option value="">All sources</option>
              <option value="auth">auth</option>
              <option value="syslog">syslog</option>
              <option value="custom">custom</option>
            </select>
            <ChevronDown size={12} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none" />
          </div>
          <div className="relative">
            <select value={evtType} onChange={e => setEvtType(e.target.value)} className="ctrl-select">
              <option value="">All types</option>
              {eventTypes.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <ChevronDown size={12} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none" />
          </div>
          <div className="relative">
            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="ctrl-select">
              <option value="">All statuses</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="unknown">Unknown</option>
            </select>
            <ChevronDown size={12} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none" />
          </div>
          <div className="flex gap-2">
            <input
              value={ipInput}
              onChange={e => setIpInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && applyIp()}
              placeholder="Filter by IP…"
              className="ctrl-input w-36"
            />
            <button onClick={applyIp} className="btn-ghost text-xs px-3 py-[0.4rem] rounded-[10px]">Search</button>
            {ipFilter && (
              <button onClick={() => { setIpInput(''); setIpFilter('') }} className="text-xs text-slate-600 hover:text-slate-300 px-1 transition-colors">
                ✕
              </button>
            )}
          </div>
          <button onClick={load} className="btn-ghost flex items-center gap-2 text-xs px-3 py-[0.4rem] rounded-[10px]">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button onClick={exportFilteredCsv} className="btn-success flex items-center gap-2 text-xs px-3 py-[0.4rem] rounded-[10px] ml-auto">
            <Download size={12} />
            Export CSV
          </button>
          <span className="text-xs text-slate-600 tabular-nums">{events.length} events</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['#', 'Timestamp', 'Source', 'Type', 'Source IP', 'User', 'Host', 'Status', 'Message'].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} className="py-10 text-center text-slate-500">Loading…</td></tr>
              ) : events.length ? events.map(e => (
                <tr key={e.id} className="border-t border-[#30363d] hover:bg-white/[0.02] transition-colors">
                  <td className="py-2.5 pr-4 text-slate-500 text-xs">{e.id}</td>
                  <td className="py-2.5 pr-4 text-slate-400 text-xs whitespace-nowrap">{fmtTs(e.timestamp)}</td>
                  <td className="py-2.5 pr-4">
                    <span className="text-xs bg-[#1c2128] border border-[#30363d] px-2 py-0.5 rounded text-slate-400">
                      {e.log_source}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4">
                    <code className="text-xs text-blue-300 font-mono">{e.event_type}</code>
                  </td>
                  <td className="py-2.5 pr-4 text-slate-400 font-mono text-xs">{e.source_ip || '—'}</td>
                  <td className="py-2.5 pr-4 text-slate-400 text-xs">{e.username || '—'}</td>
                  <td className="py-2.5 pr-4 text-slate-500 text-xs">{e.hostname || '—'}</td>
                  <td className="py-2.5 pr-4">
                    <Badge value={e.status} override={statusOverride(e.status)} />
                  </td>
                  <td className="py-2.5 text-slate-500 text-xs max-w-[260px]">
                    <span className="truncate block" title={e.message}>{e.message}</span>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan={9} className="py-10 text-center text-slate-500 text-sm">
                  No events found.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
