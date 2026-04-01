import { useEffect, useState } from 'react'
import { RefreshCw, ChevronDown } from 'lucide-react'
import { api } from '../api'
import { Panel } from '../components/Panel'
import { Badge } from '../components/Badge'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

const EVENT_TYPES = [
  'login_failure', 'login_success', 'login_invalid_user',
  'sudo_success', 'sudo_failure', 'service_started', 'service_failed',
  'file_access', 'file_modified', 'sensitive_command',
  'network_anomaly', 'system_error', 'session_opened', 'session_closed',
  'cron_job', 'kernel_event',
]

export function Events() {
  const [events, setEvents]       = useState([])
  const [loading, setLoading]     = useState(true)
  const [source, setSource]       = useState('')
  const [evtType, setEvtType]     = useState('')
  const [ipFilter, setIpFilter]   = useState('')
  const [ipInput, setIpInput]     = useState('')

  async function load() {
    setLoading(true)
    const params = { limit: 300 }
    if (source)  params.log_source = source
    if (evtType) params.event_type = evtType
    if (ipFilter) params.source_ip = ipFilter
    try {
      setEvents(await api.events(params))
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [source, evtType, ipFilter])

  function applyIp() { setIpFilter(ipInput.trim()) }

  function statusOverride(status) {
    if (status === 'success') return 'success'
    if (status === 'failure') return 'failure'
    return 'info'
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Events</h2>
        <p className="text-sm text-slate-500">Raw parsed and normalized log events</p>
      </div>

      <Panel>
        {/* Toolbar */}
        <div className="flex items-center gap-3 mb-5 flex-wrap">
          {/* Source filter */}
          <div className="relative">
            <select
              value={source}
              onChange={e => setSource(e.target.value)}
              className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 pr-8 outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="">All sources</option>
              <option value="auth">auth</option>
              <option value="syslog">syslog</option>
              <option value="custom">custom</option>
            </select>
            <ChevronDown size={14} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
          </div>

          {/* Type filter */}
          <div className="relative">
            <select
              value={evtType}
              onChange={e => setEvtType(e.target.value)}
              className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 pr-8 outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="">All types</option>
              {EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <ChevronDown size={14} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
          </div>

          {/* IP filter */}
          <div className="flex gap-2">
            <input
              value={ipInput}
              onChange={e => setIpInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && applyIp()}
              placeholder="Filter by IP…"
              className="bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 outline-none focus:border-blue-500 w-40 placeholder:text-slate-600"
            />
            <button
              onClick={applyIp}
              className="bg-[#1c2128] border border-[#30363d] hover:border-blue-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors"
            >
              Search
            </button>
            {ipFilter && (
              <button
                onClick={() => { setIpInput(''); setIpFilter('') }}
                className="text-xs text-slate-500 hover:text-slate-300 px-2"
              >
                ✕ clear
              </button>
            )}
          </div>

          <button
            onClick={load}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <span className="text-xs text-slate-500 ml-1">{events.length} events</span>
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
