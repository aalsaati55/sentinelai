import { useEffect, useState } from 'react'
import { RefreshCw, Download, ClipboardList, ChevronDown } from 'lucide-react'
import { api, token } from '../api'
import { Panel } from '../components/Panel'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 19)
}

const ACTION_STYLES = {
  status_change:      'bg-blue-500/10 text-blue-400 border-blue-500/20',
  assignment:         'bg-purple-500/10 text-purple-400 border-purple-500/20',
  note_added:         'bg-green-500/10 text-green-400 border-green-500/20',
  role_change:        'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  user_deleted:       'bg-red-500/10 text-red-400 border-red-500/20',
  user_created:       'bg-green-500/10 text-green-400 border-green-500/20',
  'Watchlist Add':    'bg-red-500/10 text-red-400 border-red-500/20',
  'Watchlist Remove': 'bg-slate-500/10 text-slate-300 border-slate-500/20',
  soar_executed:      'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  fp_marked:          'bg-yellow-500/10 text-yellow-300 border-yellow-500/20',
  fp_cleared:         'bg-slate-500/10 text-slate-300 border-slate-500/20',
  threshold_set:      'bg-orange-500/10 text-orange-400 border-orange-500/20',
  threshold_reset:    'bg-slate-500/10 text-slate-400 border-slate-500/20',
  rule_suppressed:    'bg-red-500/10 text-red-400 border-red-500/20',
  rule_unsuppressed:  'bg-green-500/10 text-green-400 border-green-500/20',
  password_reset:     'bg-orange-500/10 text-orange-400 border-orange-500/20',
  password_changed:   'bg-orange-500/10 text-orange-300 border-orange-500/20',
  mfa_enabled:        'bg-green-500/10 text-green-400 border-green-500/20',
  mfa_disabled:       'bg-red-500/10 text-red-400 border-red-500/20',
}

const ACTION_LABELS = {
  status_change:      'Status Change',
  assignment:         'Assignment',
  note_added:         'Note Added',
  role_change:        'Role Change',
  user_deleted:       'User Deleted',
  user_created:       'User Created',
  'Watchlist Add':    'Watchlist Add',
  'Watchlist Remove': 'Watchlist Remove',
  soar_executed:      'SOAR Executed',
  fp_marked:          'FP Marked',
  fp_cleared:         'FP Cleared',
  threshold_set:      'Threshold Changed',
  threshold_reset:    'Threshold Reset',
  rule_suppressed:    'Rule Suppressed',
  rule_unsuppressed:  'Rule Unsuppressed',
  password_reset:     'Password Reset',
  password_changed:   'Password Changed',
  mfa_enabled:        'MFA Enabled',
  mfa_disabled:       'MFA Disabled',
}

// Actions that only admins should see
const ADMIN_ONLY_ACTIONS = new Set([
  'role_change', 'user_deleted', 'user_created',
  'password_reset', 'password_changed', 'mfa_enabled', 'mfa_disabled',
])

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
  const [userFilter, setUserFilter] = useState('')
  const me = token.user()
  const isAdmin = me?.role === 'admin'

  async function load() {
    setLoading(true)
    try {
      setEntries(await api.auditLog())
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const users = [...new Set(entries.map(e => e.username).filter(Boolean))].sort()

  const filtered = entries
    .filter(e => isAdmin || !ADMIN_ONLY_ACTIONS.has(e.action))
    .filter(e => !filter     || e.action   === filter)
    .filter(e => !userFilter || e.username === userFilter)

  function exportFilteredCsv() {
    if (filtered.length === 0) return
    const headers = ['ID', 'Time', 'User', 'Action', 'Target Type', 'Target ID', 'Detail']
    const escape = v => `"${String(v ?? '').replace(/"/g, '""')}"`
    const lines = [
      headers.join(','),
      ...filtered.map(e => [
        e.id,
        escape(fmtTs(e.created_at)),
        escape(e.username || ''),
        escape(ACTION_LABELS[e.action] || e.action),
        escape(e.target_type || ''),
        e.target_id ?? '',
        escape(e.detail || ''),
      ].join(','))
    ].join('\n')
    const blob = new Blob([lines], { type: 'text/csv;charset=utf-8;' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    const suffix = [userFilter, filter ? (ACTION_LABELS[filter] || filter) : ''].filter(Boolean).join('_') || 'all'
    a.download = `auditlog_${suffix}_${new Date().toISOString().slice(0,10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="page-title">Audit Log</h2>
        <p className="page-sub">Track all changes — status updates, assignments, role changes, notes</p>
      </div>

      <Panel>
        {/* Toolbar */}
        <div className="toolbar">
          <div className="relative">
            <select value={userFilter} onChange={e => setUserFilter(e.target.value)} className="ctrl-select">
              <option value="">All users</option>
              {users.map(u => (
                <option key={u} value={u}>{u}</option>
              ))}
            </select>
            <ChevronDown size={12} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none" />
          </div>

          <div className="relative">
            <select value={filter} onChange={e => setFilter(e.target.value)} className="ctrl-select">
            <option value="">All actions</option>
            <optgroup label="── Incidents / Alerts">
              <option value="status_change">Status Change</option>
              <option value="assignment">Assignment</option>
              <option value="note_added">Note Added</option>
              <option value="fp_marked">FP Marked</option>
              <option value="fp_cleared">FP Cleared</option>
            </optgroup>
            <optgroup label="── Rules">
              <option value="rule_suppressed">Rule Suppressed</option>
              <option value="rule_unsuppressed">Rule Unsuppressed</option>
              <option value="threshold_set">Threshold Changed</option>
              <option value="threshold_reset">Threshold Reset</option>
            </optgroup>
            <optgroup label="── Watchlist / SOAR">
              <option value="Watchlist Add">Watchlist Add</option>
              <option value="Watchlist Remove">Watchlist Remove</option>
              <option value="soar_executed">SOAR Executed</option>
            </optgroup>
            {isAdmin && (
              <optgroup label="── User Management (Admin)">
                <option value="user_created">User Created</option>
                <option value="user_deleted">User Deleted</option>
                <option value="role_change">Role Change</option>
                <option value="password_reset">Password Reset</option>
                <option value="password_changed">Password Changed</option>
                <option value="mfa_enabled">MFA Enabled</option>
                <option value="mfa_disabled">MFA Disabled</option>
              </optgroup>
            )}
            </select>
            <ChevronDown size={12} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none" />
          </div>

          <button onClick={load} className="btn-ghost flex items-center gap-2 text-xs px-3 py-[0.4rem] rounded-[10px]">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>

          <button onClick={exportFilteredCsv} className="btn-success flex items-center gap-2 text-xs px-3 py-[0.4rem] rounded-[10px] ml-auto">
            <Download size={12} />
            Export CSV
          </button>
          <span className="text-xs text-slate-600 tabular-nums">{filtered.length} entries</span>
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
                    {(e.action === 'fp_marked' || e.action === 'fp_cleared') && e.detail ? (
                      <span className="inline-flex items-center gap-1.5">
                        <span className="text-yellow-400/80">{e.action === 'fp_marked' ? 'Reason:' : 'Cleared:'}</span>
                        <span className="truncate" title={e.detail}>{e.detail || '—'}</span>
                      </span>
                    ) : (
                      <span className="truncate block" title={e.detail}>{e.detail || '—'}</span>
                    )}
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
