import { useEffect, useState, useRef } from 'react'
import { ShieldOff, Trash2, RefreshCw, Plus, X } from 'lucide-react'
import { api, token } from '../api'
import { Panel } from '../components/Panel'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

export function Watchlist() {
  const [entries, setEntries]   = useState([])
  const [loading, setLoading]   = useState(true)
  const [removing, setRemoving] = useState('')
  const [showAdd, setShowAdd]   = useState(false)
  const [newIp, setNewIp]           = useState('')
  const [newReason, setNewReason]   = useState('')
  const [customReason, setCustomReason] = useState('')
  const [adding, setAdding]         = useState(false)
  const [error, setError]       = useState('')
  const me = token.user()

  const loadRef = useRef(null)

  async function load() {
    setLoading(true)
    try {
      const data = await api.watchlist()
      setEntries(data)
    } finally { setLoading(false) }
  }

  loadRef.current = load

  useEffect(() => { load() }, [])

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
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'watchlist') loadRef.current?.()
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

  async function remove(ip) {
    setRemoving(ip)
    try {
      await api.watchlistRemove(ip)
      setEntries(prev => prev.filter(e => e.source_ip !== ip))
    } catch (_) {} finally { setRemoving('') }
  }

  const PRESET_REASONS = [
    'Brute force attack detected',
    'Port scan / reconnaissance',
    'Invalid user enumeration',
    'Suspicious login activity',
    'Reverse shell / C2 traffic',
    'Privilege escalation attempt',
    'Known malicious IP',
    'Other',
  ]

  const resolvedReason = newReason === 'Other' ? customReason.trim() : newReason

  async function add() {
    if (!newIp.trim()) return
    setAdding(true)
    setError('')
    try {
      const entry = await api.watchlistAdd(newIp.trim(), resolvedReason)
      setEntries(prev => {
        const filtered = prev.filter(e => e.source_ip !== entry.source_ip)
        return [entry, ...filtered]
      })
      setNewIp('')
      setNewReason('')
      setCustomReason('')
      setShowAdd(false)
    } catch (e) {
      setError(e.message || 'Failed to add')
    } finally { setAdding(false) }
  }

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-xl font-bold text-white mb-1 flex items-center gap-2">
            <ShieldOff size={20} className="text-red-400" />
            IP Watchlist
          </h2>
          <p className="text-sm text-slate-500">IPs automatically or manually flagged as threats</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={load}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 text-slate-400 text-xs px-3 py-1.5 rounded-lg transition-colors"
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          {me?.role === 'admin' && (
            <button
              onClick={() => setShowAdd(v => !v)}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-xs px-3 py-1.5 rounded-lg transition-colors"
            >
              <Plus size={12} />
              Add IP
            </button>
          )}
        </div>
      </div>

      {/* Add IP form */}
      {showAdd && me?.role === 'admin' && (
        <Panel>
          <div className="flex items-end gap-3 flex-wrap">
            <div className="flex-1 min-w-[140px]">
              <label className="text-xs text-slate-500 mb-1 block">IP Address</label>
              <input
                value={newIp}
                onChange={e => setNewIp(e.target.value)}
                placeholder="192.168.1.100"
                className="w-full bg-[#0d1117] border border-[#30363d] focus:border-blue-500 text-slate-200 text-sm rounded-lg px-3 py-2 outline-none"
              />
            </div>
            <div className="flex-1 min-w-[220px]">
              <label className="text-xs text-slate-500 mb-1 block">Reason <span className="text-slate-600">(optional)</span></label>
              <select
                value={newReason}
                onChange={e => setNewReason(e.target.value)}
                className="w-full appearance-none bg-[#0d1117] border border-[#30363d] focus:border-blue-500 text-slate-200 text-sm rounded-lg px-3 py-2 outline-none cursor-pointer"
              >
                <option value="">— select a reason —</option>
                {PRESET_REASONS.map(r => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
            </div>
            {newReason === 'Other' && (
              <div className="flex-1 min-w-[200px]">
                <label className="text-xs text-slate-500 mb-1 block">Describe the reason</label>
                <input
                  value={customReason}
                  onChange={e => setCustomReason(e.target.value)}
                  placeholder="e.g. DDoS traffic observed"
                  className="w-full bg-[#0d1117] border border-[#30363d] focus:border-blue-500 text-slate-200 text-sm rounded-lg px-3 py-2 outline-none"
                />
              </div>
            )}
            <div className="flex gap-2">
              <button
                onClick={add}
                disabled={adding || !newIp.trim()}
                className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs px-4 py-2 rounded-lg transition-colors"
              >
                {adding ? 'Adding…' : 'Add'}
              </button>
              <button
                onClick={() => { setShowAdd(false); setError('') }}
                className="text-slate-500 hover:text-slate-300 p-2"
              >
                <X size={14} />
              </button>
            </div>
          </div>
          {error && <p className="text-red-400 text-xs mt-2">{error}</p>}
        </Panel>
      )}

      <Panel>
        {/* Summary bar */}
        <div className="flex items-center gap-4 mb-4 pb-4 border-b border-[#30363d]">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-400" />
            <span className="text-sm text-slate-300 font-semibold">{entries.length}</span>
            <span className="text-xs text-slate-500">watchlisted IP{entries.length !== 1 ? 's' : ''}</span>
          </div>
          <div className="text-xs text-slate-600">
            {entries.filter(e => e.added_by === 'system').length} auto-detected ·{' '}
            {entries.filter(e => e.added_by !== 'system').length} manually added
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['IP Address', 'Reason', 'Alert Count', 'Added By', 'Added At', ''].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={6} className="py-10 text-center text-slate-500">Loading…</td></tr>
              )}
              {!loading && entries.length === 0 && (
                <tr><td colSpan={6} className="py-10 text-center text-slate-500 text-sm">
                  No watchlisted IPs yet — they appear automatically when Critical/High alerts fire.
                </td></tr>
              )}
              {!loading && entries.map(e => (
                <tr key={e.source_ip} className="border-t border-[#30363d] hover:bg-white/[0.02] transition-colors">
                  <td className="py-3 pr-4">
                    <div className="flex items-center gap-2">
                      <span className="text-red-400">🚫</span>
                      <code className="text-sm font-mono text-slate-200">{e.source_ip}</code>
                    </div>
                  </td>
                  <td className="py-3 pr-4 text-slate-400 text-xs max-w-[280px]">
                    <span className="truncate block" title={e.reason}>{e.reason || '—'}</span>
                  </td>
                  <td className="py-3 pr-4">
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${
                      e.alert_count >= 10
                        ? 'bg-red-500/10 border-red-500/20 text-red-400'
                        : e.alert_count >= 3
                        ? 'bg-orange-500/10 border-orange-500/20 text-orange-400'
                        : 'bg-slate-500/10 border-slate-500/20 text-slate-400'
                    }`}>
                      {e.alert_count} alert{e.alert_count !== 1 ? 's' : ''}
                    </span>
                  </td>
                  <td className="py-3 pr-4">
                    <span className={`text-xs px-2 py-0.5 rounded border ${
                      e.added_by === 'system'
                        ? 'bg-blue-500/10 border-blue-500/20 text-blue-400'
                        : 'bg-purple-500/10 border-purple-500/20 text-purple-400'
                    }`}>
                      {e.added_by === 'system' ? '🤖 auto' : `👤 ${e.added_by}`}
                    </span>
                  </td>
                  <td className="py-3 pr-4 text-slate-500 text-xs whitespace-nowrap">{fmtTs(e.created_at)}</td>
                  <td className="py-3">
                    {me?.role === 'admin' && (
                      <button
                        onClick={() => remove(e.source_ip)}
                        disabled={removing === e.source_ip}
                        title="Remove from watchlist"
                        className="p-1.5 rounded text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-40"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
