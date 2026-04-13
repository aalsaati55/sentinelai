import { useState, useEffect, useRef, useCallback } from 'react'
import { Bell, X, AlertTriangle, Zap, UserCheck, AtSign } from 'lucide-react'
import { api } from '../api'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

// ── Alert-type notification rendering ─────────────────────────
const ALERT_ICON = {
  critical: <Zap size={12} className="text-red-400" />,
  high:     <AlertTriangle size={12} className="text-orange-400" />,
}
const ALERT_COLOR = {
  critical: 'border-l-red-500 bg-red-500/5',
  high:     'border-l-orange-500 bg-orange-500/5',
}

// ── User-notification rendering ────────────────────────────────
const USER_NOTIF_ICON = {
  assignment: <UserCheck size={12} className="text-blue-400" />,
  mention:    <AtSign size={12} className="text-purple-400" />,
}
const USER_NOTIF_COLOR = {
  assignment: 'border-l-blue-500 bg-blue-500/5',
  mention:    'border-l-purple-500 bg-purple-500/5',
}

export function NotificationBell() {
  const [alertNotifs, setAlertNotifs]     = useState([])
  const [userNotifs,  setUserNotifs]      = useState([])
  const [unseen, setUnseen]               = useState(0)
  const [open, setOpen]                   = useState(false)

  const alertSinceRef = useRef(new Date().toISOString())
  const userSinceRef  = useRef(new Date().toISOString())
  const intervalRef   = useRef(null)
  const panelRef      = useRef(null)

  const poll = useCallback(async () => {
    try {
      const [freshAlerts, freshUser] = await Promise.all([
        api.notifications(alertSinceRef.current),
        api.userNotifications(userSinceRef.current),
      ])
      let added = 0
      if (freshAlerts.length > 0) {
        alertSinceRef.current = freshAlerts[0].created_at
        setAlertNotifs(prev => [...freshAlerts, ...prev].slice(0, 40))
        added += freshAlerts.length
      }
      if (freshUser.length > 0) {
        userSinceRef.current = freshUser[0].created_at
        setUserNotifs(prev => [...freshUser, ...prev].slice(0, 20))
        added += freshUser.length
      }
      if (added > 0) setUnseen(prev => prev + added)
    } catch (_) {}
  }, [])

  useEffect(() => {
    poll()
    intervalRef.current = setInterval(poll, 15000)
    return () => clearInterval(intervalRef.current)
  }, [poll])

  // Close panel on outside click
  useEffect(() => {
    function handler(e) {
      if (panelRef.current && !panelRef.current.contains(e.target)) setOpen(false)
    }
    if (open) document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  function openPanel() {
    setOpen(o => !o)
    setUnseen(0)
    if (!open) api.markNotifsRead().catch(() => {})
  }

  function dismissAlert(idx) {
    setAlertNotifs(prev => prev.filter((_, i) => i !== idx))
  }
  function dismissUser(idx) {
    setUserNotifs(prev => prev.filter((_, i) => i !== idx))
  }

  function clearAll() {
    setAlertNotifs([])
    setUserNotifs([])
    setUnseen(0)
    setOpen(false)
    api.clearNotifs().catch(() => {})
  }

  // Merge and sort all notifications newest-first for unified display
  const allNotifs = [
    ...userNotifs.map(n => ({ ...n, _kind: 'user' })),
    ...alertNotifs.map(n => ({ ...n, _kind: 'alert' })),
  ].sort((a, b) => (b.created_at > a.created_at ? 1 : -1)).slice(0, 50)

  const total = allNotifs.length

  return (
    <div className="relative" ref={panelRef}>
      {/* Bell button */}
      <button
        onClick={openPanel}
        className="relative flex items-center justify-center w-8 h-8 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-colors"
        title="Notifications"
      >
        <Bell size={16} />
        {unseen > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-0.5 flex items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white leading-none">
            {unseen > 99 ? '99+' : unseen}
          </span>
        )}
      </button>

      {/* Dropdown panel */}
      {open && (
        <div className="absolute right-0 top-10 w-80 bg-[#161b22] border border-[#30363d] rounded-xl shadow-2xl z-50 overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#30363d]">
            <span className="text-sm font-semibold text-white">
              Notifications {total > 0 && <span className="text-slate-500 font-normal">({total})</span>}
            </span>
            {total > 0 && (
              <button onClick={clearAll} className="text-xs text-slate-500 hover:text-slate-300 transition-colors">
                Clear all
              </button>
            )}
          </div>

          {/* Notifications list */}
          <div className="max-h-96 overflow-y-auto">
            {total === 0 ? (
              <div className="px-4 py-8 text-center text-slate-600 text-sm">No new notifications</div>
            ) : (
              allNotifs.map((n, idx) => {
                if (n._kind === 'user') {
                  const origIdx = userNotifs.findIndex(u => u.id === n.id)
                  return (
                    <div
                      key={`u-${n.id}`}
                      className={`flex items-start gap-3 px-4 py-3 border-b border-[#30363d]/50 border-l-2 ${USER_NOTIF_COLOR[n.type] || 'border-l-slate-600'}`}
                    >
                      <div className="mt-0.5 shrink-0">{USER_NOTIF_ICON[n.type] || <Bell size={12} className="text-slate-400" />}</div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold text-slate-200 truncate">{n.title}</p>
                        <p className="text-xs text-slate-500 mt-0.5 line-clamp-2" title={n.body}>{n.body}</p>
                        <span className="text-[10px] text-slate-600">{fmtTs(n.created_at)}</span>
                      </div>
                      <button onClick={() => dismissUser(origIdx)} className="shrink-0 text-slate-600 hover:text-slate-400 transition-colors mt-0.5">
                        <X size={12} />
                      </button>
                    </div>
                  )
                }
                // Alert notification
                const origIdx = alertNotifs.findIndex(a => a.id === n.id)
                return (
                  <div
                    key={`a-${n.id}`}
                    className={`flex items-start gap-3 px-4 py-3 border-b border-[#30363d]/50 border-l-2 ${ALERT_COLOR[n.severity] || 'border-l-slate-600'}`}
                  >
                    <div className="mt-0.5 shrink-0">{ALERT_ICON[n.severity]}</div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <code className="text-[11px] font-mono text-slate-300 truncate">{n.rule_name}</code>
                        <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded shrink-0 ${n.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                          {n.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-500 mt-0.5 truncate" title={n.description}>{n.description}</p>
                      <span className="text-[10px] text-slate-600">{fmtTs(n.created_at)}</span>
                    </div>
                    <button onClick={() => dismissAlert(origIdx)} className="shrink-0 text-slate-600 hover:text-slate-400 transition-colors mt-0.5">
                      <X size={12} />
                    </button>
                  </div>
                )
              })
            )}
          </div>
        </div>
      )}
    </div>
  )
}
