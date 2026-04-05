import { useState, useEffect, useRef, useCallback } from 'react'
import { Bell, X, AlertTriangle, Zap } from 'lucide-react'
import { api } from '../api'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

const SEV_ICON = {
  critical: <Zap size={12} className="text-red-400" />,
  high:     <AlertTriangle size={12} className="text-orange-400" />,
}
const SEV_COLOR = {
  critical: 'border-l-red-500 bg-red-500/5',
  high:     'border-l-orange-500 bg-orange-500/5',
}

export function NotificationBell() {
  const [notifs, setNotifs]     = useState([])
  const [unseen, setUnseen]     = useState(0)
  const [open, setOpen]         = useState(false)
  const sinceRef                = useRef(new Date().toISOString())
  const intervalRef             = useRef(null)
  const panelRef                = useRef(null)

  const poll = useCallback(async () => {
    try {
      const fresh = await api.notifications(sinceRef.current)
      if (fresh.length > 0) {
        sinceRef.current = fresh[0].created_at
        setNotifs(prev => [...fresh, ...prev].slice(0, 50))
        setUnseen(prev => prev + fresh.length)
      }
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
  }

  function dismiss(idx) {
    setNotifs(prev => prev.filter((_, i) => i !== idx))
  }

  function clearAll() {
    setNotifs([])
    setUnseen(0)
    setOpen(false)
  }

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
              Alerts {notifs.length > 0 && <span className="text-slate-500 font-normal">({notifs.length})</span>}
            </span>
            {notifs.length > 0 && (
              <button onClick={clearAll} className="text-xs text-slate-500 hover:text-slate-300 transition-colors">
                Clear all
              </button>
            )}
          </div>

          {/* Notifications list */}
          <div className="max-h-80 overflow-y-auto">
            {notifs.length === 0 ? (
              <div className="px-4 py-8 text-center text-slate-600 text-sm">No new alerts</div>
            ) : (
              notifs.map((n, idx) => (
                <div
                  key={`${n.id}-${idx}`}
                  className={`flex items-start gap-3 px-4 py-3 border-b border-[#30363d]/50 border-l-2 ${SEV_COLOR[n.severity] || 'border-l-slate-600'}`}
                >
                  <div className="mt-0.5 shrink-0">{SEV_ICON[n.severity]}</div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <code className="text-[11px] font-mono text-slate-300">{n.rule_name}</code>
                      <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${n.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                        {n.severity}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 truncate" title={n.description}>{n.description}</p>
                    <span className="text-[10px] text-slate-600">{fmtTs(n.created_at)}</span>
                  </div>
                  <button onClick={() => dismiss(idx)} className="shrink-0 text-slate-600 hover:text-slate-400 transition-colors mt-0.5">
                    <X size={12} />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
