import { useEffect, useState, useMemo, useCallback, useRef } from 'react'
import { RefreshCw, ChevronDown, Download, Search, VolumeX, Volume2, Copy, Check, ShieldOff, ShieldCheck, CheckSquare, Square, Trash2 } from 'lucide-react'
import { api, token } from '../api'

import { Panel } from '../components/Panel'
import { Badge } from '../components/Badge'
import { ScoreBar } from '../components/ScoreBar'

function countryFlag(code) {
  if (!code || code.length !== 2) return null
  if (code === '--') return '🏠'
  const o = 0x1F1E6 - 65
  return String.fromCodePoint(code.toUpperCase().charCodeAt(0) + o) +
         String.fromCodePoint(code.toUpperCase().charCodeAt(1) + o)
}

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

function CopyIpButton({ ip }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => navigator.clipboard.writeText(ip).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })}
      title="Copy IP"
      className="p-0.5 rounded text-slate-600 hover:text-slate-300 transition-colors"
    >
      {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
    </button>
  )
}

export function Alerts() {
  const [alerts, setAlerts]         = useState([])
  const [filter, setFilter]         = useState('')
  const [ruleFilter, setRuleFilter] = useState('')
  const [search, setSearch]         = useState('')
  const [loading, setLoading]       = useState(true)
  const [suppressed, setSuppressed] = useState(new Set())
  const [suppressing, setSuppressing] = useState('')
  const [geoMap, setGeoMap]         = useState({})
  const [watchlistedIps, setWatchlistedIps] = useState(new Set())
  const [tiMap, setTiMap]           = useState({})
  const [fpFilter, setFpFilter]     = useState('all') // 'all' | 'real' | 'fp'
  const [fpPending, setFpPending]   = useState(null)  // { id, current } — awaiting reason pick
  const [fpReason, setFpReason]     = useState('')
  const [selected, setSelected]     = useState(new Set()) // bulk selection: Set of alert ids
  const [bulkFpPending, setBulkFpPending] = useState(false)
  const [bulkFpReason, setBulkFpReason]   = useState('')
  const me = token.user()

  const loadSuppressed = useCallback(async () => {
    try {
      const rows = await api.suppressedRules()
      setSuppressed(new Set(rows.map(r => r.rule_name)))
    } catch (_) {}
  }, [])

  const loadRef = useRef(null)

  async function load() {
    setLoading(true)
    const params = filter ? { severity: filter } : {}
    try {
      const data = await api.alerts(params)
      setAlerts(data)
      // Bulk geo-lookup for all distinct source IPs
      const ips = [...new Set(data.map(a => a.source_ip).filter(Boolean))]
      if (ips.length > 0) {
        try { const geo = await api.geoBulk(ips); setGeoMap(geo) } catch (_) {}
        try { const ti = await api.threatIntelBulk(ips); setTiMap(ti) } catch (_) {}
      }
    } finally { setLoading(false) }
  }

  loadRef.current = load

  useEffect(() => { load() }, [filter])
  useEffect(() => {
    loadSuppressed()
    api.watchlist().then(wl => setWatchlistedIps(new Set(wl.map(w => w.source_ip)))).catch(() => {})
  }, [])

  useEffect(() => {
    let ws
    let dead = false
    let pingTimer

    function connect() {
      if (dead) return
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      ws = new WebSocket(`${proto}://${window.location.hostname}:8000/api/live/ws`)
      ws.onopen = () => {
        pingTimer = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send('ping')
        }, 20000)
      }
      let debounceTimer = null
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'alert') {
            clearTimeout(debounceTimer)
            debounceTimer = setTimeout(() => loadRef.current?.(), 2000)
          }
        } catch (_) {}
      }
      ws.onclose = () => {
        clearInterval(pingTimer)
        if (!dead) setTimeout(connect, 3000)
      }
      ws.onerror = () => ws.close()
    }

    connect()
    return () => {
      dead = true
      clearInterval(pingTimer)
      ws?.close()
    }
  }, [])

  async function markFP(alertId, isFP, reason = '') {
    try {
      const updated = await api.markAlertFP(alertId, isFP, reason)
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, false_positive: updated.false_positive, fp_reason: updated.fp_reason } : a))
    } catch (_) {}
    setFpPending(null)
    setFpReason('')
  }

  async function bulkMarkFP(reason) {
    await Promise.allSettled([...selected].map(id => api.markAlertFP(id, true, reason)))
    setAlerts(prev => prev.map(a => selected.has(a.id) ? { ...a, false_positive: 1, fp_reason: reason } : a))
    setSelected(new Set())
    setBulkFpPending(false)
    setBulkFpReason('')
  }

  async function bulkClearFP() {
    const fpIds = filtered.filter(a => selected.has(a.id) && a.false_positive).map(a => a.id)
    await Promise.allSettled(fpIds.map(id => api.markAlertFP(id, false, '')))
    setAlerts(prev => prev.map(a => fpIds.includes(a.id) ? { ...a, false_positive: 0, fp_reason: '' } : a))
    setSelected(new Set())
  }

  async function bulkSuppress() {
    const ruleNames = [...new Set(filtered.filter(a => selected.has(a.id)).map(a => a.rule_name))]
    await Promise.allSettled(ruleNames.filter(r => !suppressed.has(r)).map(r => api.suppressRule(r, 'Bulk suppressed via UI')))
    await loadSuppressed()
    setSelected(new Set())
  }

  function toggleSelect(id) {
    setSelected(prev => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s })
  }

  function toggleSelectAll() {
    if (selected.size === filtered.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(filtered.map(a => a.id)))
    }
  }

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

  const ruleNames = useMemo(() => [...new Set(alerts.map(a => a.rule_name).filter(Boolean))].sort(), [alerts])

  const filtered = useMemo(() => {
    let result = alerts
    if (ruleFilter) result = result.filter(a => a.rule_name === ruleFilter)
    if (fpFilter === 'real') result = result.filter(a => !a.false_positive)
    if (fpFilter === 'fp')   result = result.filter(a =>  a.false_positive)
    const q = search.trim().toLowerCase()
    if (q) {
      const idQ = q.startsWith('#') ? q.slice(1) : null
      result = result.filter(a =>
        idQ !== null ? String(a.id) === idQ :
          (a.rule_name   || '').toLowerCase().includes(q) ||
          (a.description || '').toLowerCase().includes(q) ||
          (a.source_ip   || '').toLowerCase().includes(q) ||
          (a.username    || '').toLowerCase().includes(q) ||
          String(a.id).includes(q)
      )
    }
    return result
  }, [alerts, search, ruleFilter, fpFilter])

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
            <select
              value={ruleFilter}
              onChange={e => setRuleFilter(e.target.value)}
              className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 pr-8 outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="">All rules</option>
              {ruleNames.map(r => (
                <option key={r} value={r}>{r.replace(/_/g, ' ')}</option>
              ))}
            </select>
            <ChevronDown size={14} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
          </div>
          <div className="relative">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Search #ID, IP, rule, description…"
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
          {/* FP filter */}
          <div className="relative">
            <select
              value={fpFilter}
              onChange={e => setFpFilter(e.target.value)}
              className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 pr-8 outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="all">All alerts</option>
              <option value="real">Real attacks only</option>
              <option value="fp">False positives</option>
            </select>
            <ChevronDown size={14} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
          </div>
          <span className="text-xs text-slate-500">{filtered.length} alert{filtered.length !== 1 ? 's' : ''}</span>
        </div>

        {/* Bulk action bar */}
        {selected.size > 0 && (
          <div className="flex items-center gap-3 mb-4 px-3 py-2 bg-blue-500/5 border border-blue-500/20 rounded-lg">
            <span className="text-sm text-blue-300 font-semibold">{selected.size} alert{selected.size !== 1 ? 's' : ''} selected</span>
            <button
              onClick={() => { setBulkFpPending(true); setBulkFpReason('') }}
              className="flex items-center gap-1.5 text-xs bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 px-3 py-1.5 rounded-lg hover:bg-yellow-500/20 transition-colors"
            >
              <ShieldOff size={12} /> Mark all as FP
            </button>
            {filtered.some(a => selected.has(a.id) && a.false_positive) && (
              <button
                onClick={bulkClearFP}
                className="flex items-center gap-1.5 text-xs bg-green-500/10 border border-green-500/30 text-green-300 px-3 py-1.5 rounded-lg hover:bg-green-500/20 transition-colors"
              >
                <ShieldCheck size={12} /> Clear FP
              </button>
            )}
            {me?.role === 'admin' && (
              <button
                onClick={bulkSuppress}
                className="flex items-center gap-1.5 text-xs bg-red-500/10 border border-red-500/30 text-red-300 px-3 py-1.5 rounded-lg hover:bg-red-500/20 transition-colors"
              >
                <VolumeX size={12} /> Suppress rules
              </button>
            )}
            <button
              onClick={() => setSelected(new Set())}
              className="ml-auto text-xs text-slate-500 hover:text-slate-300 transition-colors"
            >
              Clear selection
            </button>
          </div>
        )}

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                <th className="pb-3 pr-2">
                  <button onClick={toggleSelectAll} className="text-slate-500 hover:text-slate-300 transition-colors">
                    {selected.size > 0 && selected.size === filtered.length
                      ? <CheckSquare size={14} className="text-blue-400" />
                      : <Square size={14} />}
                  </button>
                </th>
                {['#', 'Rule', 'MITRE ATT&CK', 'Severity', 'Risk Score', 'Anomaly Level', 'Source', 'Description', 'Created', ''].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={9} className="py-10 text-center text-slate-500">Loading…</td></tr>
              )}
              {!loading && filtered.length === 0 && (
                <tr><td colSpan={9} className="py-10 text-center text-slate-500 text-sm">
                  {search ? `No alerts match "${search}"` : 'No alerts found.'}
                </td></tr>
              )}
              {!loading && filtered.map(a => {
                const geo = a.source_ip ? geoMap[a.source_ip] : null
                const flag = geo?.country_code ? countryFlag(geo.country_code) : null
                const isSelected = selected.has(a.id)
                return (
                  <tr key={a.id} className={`border-t border-[#30363d] transition-colors ${
                    isSelected ? 'bg-blue-500/5' :
                    !!a.false_positive ? 'opacity-50 bg-slate-500/5' :
                    suppressed.has(a.rule_name) ? 'opacity-40' : 'hover:bg-white/[0.02]'
                  }`}>
                    <td className="py-3 pr-2">
                      <button onClick={() => toggleSelect(a.id)} className="text-slate-500 hover:text-blue-400 transition-colors">
                        {isSelected ? <CheckSquare size={14} className="text-blue-400" /> : <Square size={14} />}
                      </button>
                    </td>
                    <td className="py-3 pr-4 text-slate-500 text-xs">{a.id}</td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2 flex-wrap">
                        <code className="text-xs bg-[#1c2128] border border-[#30363d] px-2 py-0.5 rounded text-slate-300 font-mono">
                          {a.rule_name}
                        </code>
                        {suppressed.has(a.rule_name) && (
                          <span className="text-[10px] text-slate-500 border border-[#30363d] px-1.5 py-0.5 rounded">suppressed</span>
                        )}
                        {!!a.false_positive && (
                          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border bg-yellow-500/10 border-yellow-500/30 text-yellow-400" title={a.fp_reason || 'False positive'}>FP</span>
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
                    <td className="py-3 pr-4 whitespace-nowrap">
                      {a.source_ip ? (
                        <div className="flex items-center gap-1.5">
                          {flag && <span className="text-base leading-none" title={geo?.country}>{flag}</span>}
                          <div>
                            <code className="text-[11px] font-mono text-slate-300">{a.source_ip}</code>
                            {geo?.city && <div className="text-[10px] text-slate-500">{geo.city}{geo.country_code ? `, ${geo.country_code}` : ''}</div>}
                          </div>
                          {watchlistedIps.has(a.source_ip) && <span title="Watchlisted IP">🚫</span>}
                          {tiMap[a.source_ip]?.abuse_score >= 75 && (
                            <span title={`AbuseIPDB: ${tiMap[a.source_ip].abuse_score}%`} className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 whitespace-nowrap">🔴 Threat</span>
                          )}
                          {tiMap[a.source_ip]?.abuse_score >= 25 && tiMap[a.source_ip]?.abuse_score < 75 && (
                            <span title={`AbuseIPDB: ${tiMap[a.source_ip].abuse_score}%`} className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/30 whitespace-nowrap">⚠ Suspicious</span>
                          )}
                          <CopyIpButton ip={a.source_ip} />
                        </div>
                      ) : <span className="text-slate-600 text-xs">—</span>}
                    </td>
                    <td className="py-3 pr-4 text-slate-400 text-xs max-w-[280px]">
                      <span className="truncate block" title={a.description}>{a.description}</span>
                    </td>
                    <td className="py-3 text-slate-500 text-xs whitespace-nowrap">{fmtTs(a.created_at)}</td>
                    <td className="py-3 pl-2">
                      <div className="flex items-center gap-1">
                        {/* False positive toggle — all users */}
                        <button
                          onClick={() => {
                            if (a.false_positive) { markFP(a.id, false) }
                            else { setFpPending({ id: a.id }); setFpReason('') }
                          }}
                          title={!!a.false_positive ? `FP: ${a.fp_reason || 'false positive'} — click to clear` : 'Mark as false positive'}
                          className={`p-1.5 rounded transition-colors ${
                            !!a.false_positive
                              ? 'text-yellow-400 bg-yellow-500/10 hover:bg-yellow-500/20'
                              : 'text-slate-500 hover:text-yellow-400 hover:bg-yellow-500/10'
                          }`}
                        >
                          <ShieldOff size={13} />
                        </button>
                        {/* Suppress — admin only */}
                        {me?.role === 'admin' && (
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
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Bulk FP Reason Modal */}
      {bulkFpPending && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-sm p-5 space-y-4">
            <h3 className="text-white font-semibold text-sm">Mark {selected.size} Alert{selected.size !== 1 ? 's' : ''} as False Positive</h3>
            <p className="text-slate-500 text-xs">Select the reason these alerts are not real threats:</p>
            <div className="space-y-2">
              {[
                'Known scanner / security tool',
                'Internal service activity',
                'Misconfigured rule',
                'Test / lab traffic',
                'Authorized admin activity',
                'Other',
              ].map(r => (
                <button
                  key={r}
                  onClick={() => setBulkFpReason(r)}
                  className={`w-full text-left px-3 py-2 rounded-lg text-sm border transition-colors ${
                    bulkFpReason === r
                      ? 'bg-yellow-500/15 border-yellow-500/40 text-yellow-300'
                      : 'bg-[#1c2128] border-[#30363d] text-slate-300 hover:border-yellow-500/30'
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
            <div className="flex gap-3 pt-1">
              <button
                onClick={() => bulkMarkFP(bulkFpReason)}
                disabled={!bulkFpReason}
                className="flex-1 bg-yellow-600 hover:bg-yellow-500 disabled:opacity-40 text-white text-sm font-semibold py-2 rounded-lg transition-colors"
              >
                Confirm
              </button>
              <button
                onClick={() => { setBulkFpPending(false); setBulkFpReason('') }}
                className="flex-1 bg-[#1c2128] border border-[#30363d] text-slate-300 text-sm py-2 rounded-lg hover:border-slate-500 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FP Reason Modal */}
      {fpPending && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-sm p-5 space-y-4">
            <h3 className="text-white font-semibold text-sm">Mark as False Positive</h3>
            <p className="text-slate-500 text-xs">Select the reason this alert is not a real threat:</p>
            <div className="space-y-2">
              {[
                'Known scanner / security tool',
                'Internal service activity',
                'Misconfigured rule',
                'Test / lab traffic',
                'Authorized admin activity',
                'Other',
              ].map(r => (
                <button
                  key={r}
                  onClick={() => setFpReason(r)}
                  className={`w-full text-left px-3 py-2 rounded-lg text-sm border transition-colors ${
                    fpReason === r
                      ? 'bg-yellow-500/15 border-yellow-500/40 text-yellow-300'
                      : 'bg-[#1c2128] border-[#30363d] text-slate-300 hover:border-yellow-500/30'
                  }`}
                >
                  {r}
                </button>
              ))}
            </div>
            <div className="flex gap-3 pt-1">
              <button
                onClick={() => markFP(fpPending.id, true, fpReason)}
                disabled={!fpReason}
                className="flex-1 bg-yellow-600 hover:bg-yellow-500 disabled:opacity-40 text-white text-sm font-semibold py-2 rounded-lg transition-colors"
              >
                Confirm
              </button>
              <button
                onClick={() => { setFpPending(null); setFpReason('') }}
                className="flex-1 bg-[#1c2128] border border-[#30363d] text-slate-300 text-sm py-2 rounded-lg hover:border-slate-500 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
