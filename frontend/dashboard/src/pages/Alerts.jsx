import { useEffect, useState } from 'react'
import { RefreshCw, ChevronDown } from 'lucide-react'
import { api } from '../api'
import { Panel } from '../components/Panel'
import { Badge } from '../components/Badge'
import { ScoreBar } from '../components/ScoreBar'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

export function Alerts() {
  const [alerts, setAlerts]   = useState([])
  const [filter, setFilter]   = useState('')
  const [loading, setLoading] = useState(true)

  async function load() {
    setLoading(true)
    const params = filter ? { severity: filter } : {}
    try {
      setAlerts(await api.alerts(params))
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [filter])

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Alerts</h2>
        <p className="text-sm text-slate-500">Rule-based detection alerts with ML anomaly scoring</p>
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
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
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
          <span className="text-xs text-slate-500 ml-1">{alerts.length} alerts</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['#', 'Rule', 'Severity', 'Risk Score', 'Anomaly Score', 'Anomaly Level', 'Description', 'Created'].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} className="py-10 text-center text-slate-500">Loading…</td></tr>
              ) : alerts.length ? alerts.map(a => (
                <tr key={a.id} className="border-t border-[#30363d] hover:bg-white/[0.02] transition-colors">
                  <td className="py-3 pr-4 text-slate-500 text-xs">{a.id}</td>
                  <td className="py-3 pr-4">
                    <code className="text-xs bg-[#1c2128] border border-[#30363d] px-2 py-0.5 rounded text-slate-300 font-mono">
                      {a.rule_name}
                    </code>
                  </td>
                  <td className="py-3 pr-4"><Badge value={a.severity} /></td>
                  <td className="py-3 pr-4"><ScoreBar score={a.risk_score} /></td>
                  <td className="py-3 pr-4 text-slate-400 font-mono text-xs">
                    {a.anomaly_score != null ? a.anomaly_score.toFixed(3) : '—'}
                  </td>
                  <td className="py-3 pr-4">
                    {a.anomaly_level ? <Badge value={a.anomaly_level} /> : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="py-3 pr-4 text-slate-400 text-xs max-w-[280px]">
                    <span className="truncate block" title={a.description}>{a.description}</span>
                  </td>
                  <td className="py-3 text-slate-500 text-xs whitespace-nowrap">{fmtTs(a.created_at)}</td>
                </tr>
              )) : (
                <tr><td colSpan={8} className="py-10 text-center text-slate-500 text-sm">
                  No alerts found.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
