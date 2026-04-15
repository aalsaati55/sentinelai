import { LayoutDashboard, AlertTriangle, Bell, FileText, Shield, Users, Settings, ClipboardList, Globe, ShieldOff, SlidersHorizontal } from 'lucide-react'

const NAV = [
  { id: 'overview',   label: 'Overview',    Icon: LayoutDashboard },
  { id: 'incidents',  label: 'Incidents',   Icon: AlertTriangle },
  { id: 'alerts',     label: 'Alerts',      Icon: Bell },
  { id: 'events',     label: 'Events',      Icon: FileText },
  { id: 'attackmap',  label: 'Attack Map',  Icon: Globe },
  { id: 'watchlist',  label: 'Watchlist',   Icon: ShieldOff },
]

const ADMIN_NAV = [
  { id: 'users',  label: 'Users',         Icon: Users },
  { id: 'tuning', label: 'Alert Tuning',  Icon: SlidersHorizontal },
]

const ALL_USERS_NAV = [
  { id: 'audit',    label: 'Audit Log', Icon: ClipboardList },
  { id: 'settings', label: 'Settings',  Icon: Settings },
]

export function Sidebar({ page, setPage, userRole }) {
  return (
    <aside className="w-56 shrink-0 bg-[#161b22] border-r border-[#30363d] flex flex-col">
      <div className="px-5 py-5 border-b border-[#30363d]">
        <div className="flex items-center gap-2">
          <Shield size={20} className="text-blue-400" />
          <span className="text-base font-bold text-white tracking-tight">SentinelAI</span>
        </div>
        <p className="text-xs text-slate-500 mt-1 ml-7">SIEM Prototype v1.0</p>
      </div>

      <nav className="flex-1 px-2 py-3 space-y-0.5">
        {NAV.map(({ id, label, Icon }) => {
          const active = page === id
          return (
            <button
              key={id}
              onClick={() => setPage(id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all
                ${active
                  ? 'bg-blue-500/15 text-blue-400 border border-blue-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                }`}
            >
              <Icon size={16} />
              {label}
            </button>
          )
        })}

        <p className="text-xs font-semibold uppercase tracking-wider text-slate-700 px-3 pt-4 pb-1">Account</p>
        {ALL_USERS_NAV.map(({ id, label, Icon }) => {
          const active = page === id
          return (
            <button
              key={id}
              onClick={() => setPage(id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all
                ${active
                  ? 'bg-purple-500/15 text-purple-400 border border-purple-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                }`}
            >
              <Icon size={16} />
              {label}
            </button>
          )
        })}

        {userRole === 'admin' && (
          <>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-700 px-3 pt-4 pb-1">Admin</p>
            {ADMIN_NAV.map(({ id, label, Icon }) => {
              const active = page === id
              return (
                <button
                  key={id}
                  onClick={() => setPage(id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all
                    ${active
                      ? 'bg-purple-500/15 text-purple-400 border border-purple-500/20'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                    }`}
                >
                  <Icon size={16} />
                  {label}
                </button>
              )
            })}
          </>
        )}
      </nav>

      <div className="px-5 py-4 border-t border-[#30363d]">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-xs text-slate-500">API Connected</span>
        </div>
      </div>
    </aside>
  )
}
