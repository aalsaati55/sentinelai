export function Panel({ title, children, className = '', action, glow, fixed }) {
  const glowClass = glow === 'red' ? 'hover:shadow-[0_0_30px_rgba(248,81,73,0.08)]'
    : glow === 'green' ? 'hover:shadow-[0_0_30px_rgba(63,185,80,0.08)]'
    : glow === 'purple' ? 'hover:shadow-[0_0_30px_rgba(163,113,247,0.08)]'
    : 'hover:shadow-[0_0_30px_rgba(56,139,253,0.08)]'

  // fixed=true enables flex-col layout so children fill the panel height
  const isFixed = fixed || /\bh-\d+\b/.test(className)

  return (
    <div className={`
      relative bg-[#0d1421] border border-white/[0.07] rounded-2xl p-5
      shadow-[0_4px_24px_rgba(0,0,0,0.4)]
      transition-all duration-300 overflow-hidden
      ${isFixed ? 'flex flex-col' : ''}
      ${glowClass}
      ${className}
    `}>
      <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-white/[0.02] to-transparent pointer-events-none" />
      {title && (
        <div className={`flex items-center justify-between mb-4 relative ${isFixed ? 'shrink-0' : ''}`}>
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
            <span className="w-1 h-3.5 rounded-full bg-gradient-to-b from-blue-400 to-blue-600 inline-block" />
            {title}
          </h3>
          {action}
        </div>
      )}
      <div className={`relative ${isFixed ? 'flex-1 min-h-0' : ''}`}>{children}</div>
    </div>
  )
}
