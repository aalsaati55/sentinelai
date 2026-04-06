import { useEffect, useRef, useState } from 'react'
import { Radio, ShieldAlert, Activity } from 'lucide-react'
import { token } from '../api'

const ORIGINAL_TITLE = document.title

function requestNotificationPermission() {
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission()
  }
}

function fireNotification(alert) {
  if (!('Notification' in window) || Notification.permission !== 'granted') return
  const sev = (alert.severity || '').toUpperCase()
  const rule = (alert.rule_name || '').replace(/_/g, ' ')
  const ip   = alert.source_ip || 'unknown'
  new Notification(`🚨 SentinelAI — ${sev} Alert`, {
    body: `${rule} from ${ip}`,
    icon: '/favicon.ico',
    tag:  `sentinel-${alert.rule_name}-${ip}`,
  })
}

const MAX_ITEMS = 50

const SEVERITY_COLORS = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high:     'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low:      'text-green-400 bg-green-500/10 border-green-500/20',
}

const EVENT_TYPE_COLORS = {
  auth_failure:    'text-red-400',
  auth_success:    'text-green-400',
  sudo:            'text-orange-400',
  service_failed:  'text-red-400',
  service_stopped: 'text-slate-500',
  service_started: 'text-blue-400',
}

function fmtTime(ts) {
  if (!ts) return ''
  return ts.replace('T', ' ').slice(11, 19)
}

export function LiveFeed({ onNewAlert, onNewEvent }) {
  const [items, setItems]         = useState([])
  const [connected, setConnected] = useState(false)
  const [alertCount, setAlertCount]     = useState(0)
  const [unreadCritical, setUnreadCritical] = useState(0)
  const wsRef   = useRef(null)
  const listRef = useRef(null)

  // Update tab title with unread critical/high badge
  useEffect(() => {
    if (unreadCritical > 0) {
      document.title = `(${unreadCritical}) 🚨 ${ORIGINAL_TITLE}`
    } else {
      document.title = ORIGINAL_TITLE
    }
  }, [unreadCritical])

  // Reset badge when tab becomes active
  useEffect(() => {
    function onFocus() { setUnreadCritical(0) }
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [])

  useEffect(() => {
    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const host     = window.location.hostname
      const ws       = new WebSocket(`${protocol}://${host}:8000/api/live/ws`)
      wsRef.current  = ws

      ws.onopen = () => {
        setConnected(true)
        requestNotificationPermission()
        // keep-alive ping every 20s
        ws._pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send('ping')
        }, 20000)
      }

      ws.onclose = () => {
        setConnected(false)
        clearInterval(ws._pingInterval)
        // Reconnect after 3 seconds
        setTimeout(connect, 3000)
      }

      ws.onerror = () => {
        ws.close()
      }

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'event') {
            const item = { ...msg.data, _kind: 'event', _id: Date.now() + Math.random() }
            setItems(prev => [item, ...prev].slice(0, MAX_ITEMS))
            onNewEvent?.()
          } else if (msg.type === 'alert') {
            const item = { ...msg.data, _kind: 'alert', _id: Date.now() + Math.random() }
            setItems(prev => [item, ...prev].slice(0, MAX_ITEMS))
            setAlertCount(c => c + 1)
            onNewAlert?.(msg.data)
            // Fire browser notification + tab badge for Critical and High
            const sev = msg.data?.severity
            if (sev === 'critical' || sev === 'high') {
              fireNotification(msg.data)
              if (!document.hasFocus()) {
                setUnreadCritical(c => c + 1)
              }
            }
          }
        } catch {}
      }
    }

    connect()
    return () => {
      clearInterval(wsRef.current?._pingInterval)
      wsRef.current?.close()
    }
  }, [])

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Radio size={14} className={connected ? 'text-green-400' : 'text-slate-600'} />
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Live Feed
          </span>
          {connected
            ? <span className="text-xs text-green-400 font-medium">● Live</span>
            : <span className="text-xs text-slate-600">○ Reconnecting…</span>
          }
        </div>
        {alertCount > 0 && (
          <span className="text-xs bg-red-500/15 text-red-400 border border-red-500/20 px-2 py-0.5 rounded-full font-semibold">
            {alertCount} alert{alertCount !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {/* Feed list */}
      <div ref={listRef} className="flex-1 overflow-y-auto space-y-1.5 min-h-0">
        {items.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-slate-600 text-xs gap-2 py-8">
            <Activity size={20} />
            <p>Waiting for live events from the agent…</p>
            <p className="text-slate-700">Start the log agent on the target VM</p>
          </div>
        ) : (
          items.map(item => (
            item._kind === 'alert'
              ? <AlertRow key={item._id} item={item} />
              : <EventRow key={item._id} item={item} />
          ))
        )}
      </div>
    </div>
  )
}

function AlertRow({ item }) {
  const sev = item.severity || 'medium'
  const color = SEVERITY_COLORS[sev] || SEVERITY_COLORS.medium
  return (
    <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 ${color} text-xs`}>
      <ShieldAlert size={12} className="mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-semibold uppercase">{sev}</span>
          <span className="font-mono opacity-80">{item.rule_name?.replace(/_/g, ' ')}</span>
          <span className="ml-auto opacity-60 shrink-0">{fmtTime(item.timestamp)}</span>
        </div>
        <div className="opacity-70 truncate mt-0.5">
          {item.source_ip && <span className="font-mono mr-2">{item.source_ip}</span>}
          {item.username  && <span className="mr-2">/ {item.username}</span>}
          <span>score: {item.risk_score}</span>
        </div>
      </div>
    </div>
  )
}

function EventRow({ item }) {
  const typeColor = EVENT_TYPE_COLORS[item.event_type] || 'text-slate-400'
  return (
    <div className="flex items-start gap-2 rounded-lg border border-[#30363d] bg-[#1c2128]/60 px-3 py-1.5 text-xs">
      <Activity size={10} className={`mt-0.5 shrink-0 ${typeColor}`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`font-mono font-semibold ${typeColor}`}>{item.event_type}</span>
          {item.source_ip && <span className="text-slate-500 font-mono">{item.source_ip}</span>}
          {item.username  && <span className="text-slate-500">/ {item.username}</span>}
          <span className="ml-auto text-slate-600 shrink-0">{fmtTime(item.timestamp)}</span>
        </div>
        {item.message && (
          <p className="text-slate-600 truncate mt-0.5">{item.message}</p>
        )}
      </div>
    </div>
  )
}
