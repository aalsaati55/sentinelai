export function StatCard({ label, value, icon: Icon, color = 'blue', sub }) {
  const colors = {
    blue:   {
      bar: 'from-blue-500 to-cyan-400',
      bg: 'bg-blue-500/[0.05]',
      border: 'border-blue-500/20',
      text: 'text-blue-300',
      icon: 'text-blue-400',
      iconBg: 'bg-blue-500/10',
      glow: 'hover:shadow-[0_0_30px_rgba(56,139,253,0.12)]',
    },
    red:    {
      bar: 'from-red-500 to-orange-400',
      bg: 'bg-red-500/[0.05]',
      border: 'border-red-500/20',
      text: 'text-red-300',
      icon: 'text-red-400',
      iconBg: 'bg-red-500/10',
      glow: 'hover:shadow-[0_0_30px_rgba(248,81,73,0.12)]',
    },
    orange: {
      bar: 'from-orange-500 to-yellow-400',
      bg: 'bg-orange-500/[0.05]',
      border: 'border-orange-500/20',
      text: 'text-orange-300',
      icon: 'text-orange-400',
      iconBg: 'bg-orange-500/10',
      glow: 'hover:shadow-[0_0_30px_rgba(219,109,40,0.12)]',
    },
    yellow: {
      bar: 'from-yellow-500 to-amber-300',
      bg: 'bg-yellow-500/[0.05]',
      border: 'border-yellow-500/20',
      text: 'text-yellow-300',
      icon: 'text-yellow-400',
      iconBg: 'bg-yellow-500/10',
      glow: 'hover:shadow-[0_0_30px_rgba(210,153,34,0.12)]',
    },
    green:  {
      bar: 'from-green-500 to-emerald-400',
      bg: 'bg-green-500/[0.05]',
      border: 'border-green-500/20',
      text: 'text-green-300',
      icon: 'text-green-400',
      iconBg: 'bg-green-500/10',
      glow: 'hover:shadow-[0_0_30px_rgba(63,185,80,0.12)]',
    },
    purple: {
      bar: 'from-purple-500 to-pink-400',
      bg: 'bg-purple-500/[0.05]',
      border: 'border-purple-500/20',
      text: 'text-purple-300',
      icon: 'text-purple-400',
      iconBg: 'bg-purple-500/10',
      glow: 'hover:shadow-[0_0_30px_rgba(163,113,247,0.12)]',
    },
  }
  const c = colors[color] || colors.blue
  return (
    <div className={`
      relative rounded-2xl border ${c.border} ${c.bg}
      p-5 flex flex-col gap-3 overflow-hidden
      shadow-[0_4px_20px_rgba(0,0,0,0.35)]
      transition-all duration-300 ${c.glow}
      animate-fade-in-up
    `}>
      {/* Top accent bar */}
      <div className={`absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r ${c.bar} opacity-70`} />
      {/* Subtle corner glow */}
      <div className={`absolute -top-6 -right-6 w-20 h-20 rounded-full bg-gradient-to-br ${c.bar} opacity-10 blur-2xl pointer-events-none`} />

      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">{label}</span>
        {Icon && (
          <div className={`p-2 rounded-lg ${c.iconBg}`}>
            <Icon size={15} className={c.icon} />
          </div>
        )}
      </div>
      <div className={`text-3xl font-bold ${c.text} animate-count-up`}>{value ?? '—'}</div>
      {sub && <div className="text-xs text-slate-600">{sub}</div>}
    </div>
  )
}
