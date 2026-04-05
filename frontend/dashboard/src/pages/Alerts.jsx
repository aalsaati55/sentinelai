import { useEffect, useState, useMemo, useCallback } from 'react'
import { RefreshCw, ChevronDown, Download, Search, VolumeX, Volume2 } from 'lucide-react'
import { api, token } from '../api'
import { Panel } from '../components/Panel'
import { Badge } from '../components/Badge'
import { ScoreBar } from '../components/ScoreBar'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

export function Alerts() {
  const [alerts, setAlerts]         = useState([])
  const [filter, setFilter]         = useState('')
  const [search, setSearch]         = useState('')
  const [loading, setLoading]       = useState(true)
  const [suppressed, setSuppressed] = useState(new Set())
  const [suppressing, setSuppressing] = useState('')
  const me = token.user()

  const loadSuppressed = useCallback(async () => {
    try {
      const rows = await api.suppressedRules()
      setSuppressed(new Set(rows.map(r => r.rule_name)))
    } catch (_) {}
  }, [])

  async function load() {
    setLoading(true)
    const params = filter ? { severity: filter } : {}
    try {
      setAlerts(await api.alerts(params))
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [filter])
  useEffect(() => { loadSuppressed() }, [])

  async function toggleSuppress(ruleName) {
    setSuppressing(ruleName)
    try {
      if (suppressed.has(ruleName)) {
        await api.unsuppressRule(ruleName)
      } else {
        await api.suppressRule(ruleName, 'Suppressed via UI')
      }
      await loadSuppressed()
    } finally { setSuppressing('') }
  }

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return alerts
    return alerts.filter(a =>
      (a.rule_name   || '').toLowerCase().includes(q) ||
      (a.description || '').toLowerCase().includes(q)
    )
  }, [alerts, search])

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
          <div className="relative">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Search rule, description…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg pl-8 pr-3 py-2 w-52 outline-none focus:border-blue-500 placeholder-slate-600"
            />
          </div>
          <button
            onClick={load}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button
            onClick={() => api.exportAlertsCsv(filter)}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-green-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors ml-auto"
          >
            <Download size={13} />
            Export CSV
          </button>
          <span className="text-xs text-slate-500">{filtered.length} alert{filtered.length !== 1 ? 's' : ''}</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['#', 'Rule', 'MITRE ATT&CK', 'Severity', 'Risk Score', 'Anomaly Level', 'Description', 'Created'].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} className="py-10 text-center text-slate-500">Loading…</td></tr>
              ) : filtered.length ? filtered.map(a => (
                <tr key={a.id} className={`border-t border-[#30363d] transition-colors ${suppressed.has(a.rule_name) ? 'opacity-40' : 'hover:bg-white/[0.02]'}`}>
                  <td className="py-3 pr-4 text-slate-500 text-xs">{a.id}</td>
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <code className="text-xs bg-[#1c2128] border border-[#30363d] px-2 py-0.5 rounded text-slate-300 font-mono">
                        {a.rule_name}
                      </code>
                      {suppressed.has(a.rule_name) && (
                        <span className="text-[10px] text-slate-500 border border-[#30363d] px-1.5 py-0.5 rounded">suppressed</span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 pr-4">
                    <div className="flex flex-wrap gap-1">
                      {(a.mitre_techniques || []).map(t => (
                        <a
                          key={t.id}
                          href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          title={t.name}
                          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-950 border border-indigo-700 text-indigo-300 hover:bg-indigo-900 hover:text-indigo-100 transition-colors whitespace-nowrap"
                        >
                          {t.id}
                        </a>
                      ))}
                      {(!a.mitre_techniques || a.mitre_techniques.length === 0) && (
                        <span className="text-slate-600 text-xs">—</span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 pr-4"><Badge value={a.severity} /></td>
                  <td className="py-3 pr-4"><ScoreBar score={a.risk_score} /></td>
                  <td className="py-3 pr-4">
                    {a.anomaly_level ? <Badge value={a.anomaly_level} /> : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="py-3 pr-4 text-slate-400 text-xs max-w-[280px]">
                    <span className="truncate block" title={a.description}>{a.description}</span>
                  </td>
                  <td className="py-3 text-slate-500 text-xs whitespace-nowrap">{fmtTs(a.created_at)}</td>
                  {me?.role === 'admin' && (
                    <td className="py-3 pl-2">
                      <button
                        onClick={() => toggleSuppress(a.rule_name)}
                        disabled={suppressing === a.rule_name}
                        title={suppressed.has(a.rule_name) ? 'Unsuppress rule' : 'Suppress rule'}
                        className={`p-1.5 rounded transition-colors ${
                          suppressed.has(a.rule_name)
                            ? 'text-slate-500 hover:text-green-400 hover:bg-green-500/10'
                            : 'text-slate-500 hover:text-red-400 hover:bg-red-500/10'
                        }`}
                      >
                        {suppressed.has(a.rule_name) ? <Volume2 size={13} /> : <VolumeX size={13} />}
                      </button>
                    </td>
                  )}
                </tr>
              )) : (
                <tr><td colSpan={9} className="py-10 text-center text-slate-500 text-sm">
                  {search ? `No alerts match "${search}"` : 'No alerts found.'}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
