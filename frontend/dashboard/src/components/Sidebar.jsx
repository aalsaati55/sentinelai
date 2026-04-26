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

function NavBtn({ id, label, Icon, active, onClick, accent = 'blue' }) {
  const activeStyles = accent === 'purple'
    ? 'bg-purple-500/10 text-purple-300 border border-purple-500/20 shadow-[inset_0_0_12px_rgba(163,113,247,0.08)]'
    : 'bg-blue-500/10 text-blue-300 border border-blue-500/20 shadow-[inset_0_0_12px_rgba(56,139,253,0.08)]'
  const activeBar = accent === 'purple'
    ? 'from-purple-500 to-pink-400'
    : 'from-blue-500 to-cyan-400'

  return (
    <button
      key={id}
      onClick={onClick}
      className={`relative w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 overflow-hidden
        ${active
          ? `${activeStyles}`
          : 'text-slate-500 hover:text-slate-200 hover:bg-white/[0.04] border border-transparent'
        }`}
    >
      {active && (
        <span className={`absolute left-0 top-2 bottom-2 w-[3px] rounded-r-full bg-gradient-to-b ${activeBar}`} />
      )}
      <Icon size={15} className={active ? '' : 'opacity-60'} />
      <span className="truncate">{label}</span>
    </button>
  )
}

export function Sidebar({ page, setPage, userRole }) {
  return (
    <aside className="w-56 shrink-0 flex flex-col relative" style={{ background: 'linear-gradient(180deg, #0a1020 0%, #060b14 100%)', borderRight: '1px solid rgba(255,255,255,0.06)' }}>
      {/* Subtle grid lines */}
      <div className="absolute inset-0 grid-bg opacity-30 pointer-events-none" />

      {/* Logo */}
      <div className="relative px-4 py-5" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        <div className="flex items-center gap-2.5">
          <div className="relative p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20">
            <Shield size={16} className="text-blue-400" />
            <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 bg-blue-400 rounded-full shadow-[0_0_4px_#388bfd]" />
          </div>
          <div>
            <span className="text-sm font-bold gradient-text-blue tracking-tight">SentinelAI</span>
          </div>
        </div>
        <p className="text-[10px] text-slate-600 mt-1.5 ml-9 font-medium tracking-widest uppercase">SIEM Dashboard</p>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2.5 py-3 space-y-0.5 overflow-y-auto">
        <p className="text-[10px] font-bold uppercase tracking-widest text-slate-700 px-3 pt-1 pb-2">Monitor</p>
        {NAV.map(({ id, label, Icon }) => (
          <NavBtn key={id} id={id} label={label} Icon={Icon} active={page === id} onClick={() => setPage(id)} />
        ))}

        <p className="text-[10px] font-bold uppercase tracking-widest text-slate-700 px-3 pt-4 pb-2">Account</p>
        {ALL_USERS_NAV.map(({ id, label, Icon }) => (
          <NavBtn key={id} id={id} label={label} Icon={Icon} active={page === id} onClick={() => setPage(id)} accent="purple" />
        ))}

        {userRole === 'admin' && (
          <>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-700 px-3 pt-4 pb-2">Admin</p>
            {ADMIN_NAV.map(({ id, label, Icon }) => (
              <NavBtn key={id} id={id} label={label} Icon={Icon} active={page === id} onClick={() => setPage(id)} accent="purple" />
            ))}
          </>
        )}
      </nav>

      {/* Status footer */}
      <div className="px-4 py-3.5 relative" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
        <div className="flex items-center gap-2.5">
          <span className="neon-dot-green animate-pulse" />
          <div>
            <p className="text-xs text-slate-400 font-medium">Live Feed Active</p>
            <p className="text-[10px] text-slate-700">v1.0 · SentinelAI</p>
          </div>
        </div>
      </div>
    </aside>
  )
}
