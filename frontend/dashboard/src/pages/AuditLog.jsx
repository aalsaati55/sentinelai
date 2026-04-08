import { useEffect, useState } from 'react'
import { RefreshCw, Download, ClipboardList } from 'lucide-react'
import { api } from '../api'
import { Panel } from '../components/Panel'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 19)
}

const ACTION_STYLES = {
  status_change:    'bg-blue-500/10 text-blue-400 border-blue-500/20',
  assignment:       'bg-purple-500/10 text-purple-400 border-purple-500/20',
  note_added:       'bg-green-500/10 text-green-400 border-green-500/20',
  role_change:      'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  user_deleted:     'bg-red-500/10 text-red-400 border-red-500/20',
  'Watchlist Add':  'bg-red-500/10 text-red-400 border-red-500/20',
  'Watchlist Remove': 'bg-slate-500/10 text-slate-300 border-slate-500/20',
  soar_executed:    'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
}

const ACTION_LABELS = {
  status_change:    'Status Change',
  assignment:       'Assignment',
  note_added:       'Note Added',
  role_change:      'Role Change',
  user_deleted:     'User Deleted',
  'Watchlist Add':  'Watchlist Add',
  'Watchlist Remove': 'Watchlist Remove',
  soar_executed:    'SOAR Executed',
}

function ActionBadge({ action }) {
  const cls = ACTION_STYLES[action] || 'bg-slate-500/10 text-slate-400 border-slate-500/20'
  return (
    <span className={`inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded-full border ${cls}`}>
      {ACTION_LABELS[action] || action}
    </span>
  )
}

export function AuditLog() {
  const [entries, setEntries] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState('')

  async function load() {
    setLoading(true)
    try {
      setEntries(await api.auditLog())
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const filtered = filter
    ? entries.filter(e => e.action === filter)
    : entries

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Audit Log</h2>
        <p className="text-sm text-slate-500">Track all changes — status updates, assignments, role changes, notes</p>
      </div>

      <Panel>
        {/* Toolbar */}
        <div className="flex items-center gap-3 mb-5 flex-wrap">
          <select
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 outline-none focus:border-blue-500 cursor-pointer"
          >
            <option value="">All actions</option>
            <option value="status_change">Status Change</option>
            <option value="assignment">Assignment</option>
            <option value="note_added">Note Added</option>
            <option value="role_change">Role Change</option>
            <option value="user_deleted">User Deleted</option>
            <option value="Watchlist Add">Watchlist Add</option>
            <option value="Watchlist Remove">Watchlist Remove</option>
            <option value="soar_executed">SOAR Executed</option>
          </select>

          <button
            onClick={load}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>

          <button
            onClick={() => api.exportAuditCsv()}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-green-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors ml-auto"
          >
            <Download size={13} />
            Export CSV
          </button>
          <span className="text-xs text-slate-500">{filtered.length} entries</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['Time', 'User', 'Action', 'Target', 'Detail'].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5} className="py-10 text-center text-slate-500">Loading…</td></tr>
              ) : filtered.length ? filtered.map(e => (
                <tr key={e.id} className="border-t border-[#30363d] hover:bg-white/[0.02] transition-colors">
                  <td className="py-3 pr-4 text-slate-500 text-xs whitespace-nowrap font-mono">{fmtTs(e.created_at)}</td>
                  <td className="py-3 pr-4">
                    <span className="text-blue-400 font-semibold text-xs">{e.username}</span>
                  </td>
                  <td className="py-3 pr-4">
                    <ActionBadge action={e.action} />
                  </td>
                  <td className="py-3 pr-4 text-slate-400 text-xs">
                    {e.target_type}
                    {e.target_id ? <span className="text-slate-600 ml-1">#{e.target_id}</span> : null}
                  </td>
                  <td className="py-3 text-slate-400 text-xs max-w-[320px]">
                    <span className="truncate block" title={e.detail}>{e.detail || '—'}</span>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={5} className="py-16 text-center">
                    <ClipboardList size={28} className="text-slate-700 mx-auto mb-2" />
                    <p className="text-slate-500 text-sm">No audit entries yet</p>
                    <p className="text-slate-600 text-xs mt-1">Actions like status changes, assignments, and role changes will appear here</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
