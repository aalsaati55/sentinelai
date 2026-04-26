const STYLES = {
  critical:      { cls: 'bg-red-500/10 text-red-300 border border-red-500/25 shadow-[0_0_8px_rgba(248,81,73,0.15)]',    dot: 'bg-red-400 shadow-[0_0_4px_#f85149]' },
  high:          { cls: 'bg-orange-500/10 text-orange-300 border border-orange-500/25 shadow-[0_0_8px_rgba(249,115,22,0.12)]', dot: 'bg-orange-400 shadow-[0_0_4px_#f97316]' },
  medium:        { cls: 'bg-yellow-500/10 text-yellow-300 border border-yellow-500/25',                                  dot: 'bg-yellow-400' },
  low:           { cls: 'bg-green-500/10 text-green-300 border border-green-500/25',                                    dot: 'bg-green-400' },
  open:          { cls: 'bg-red-500/10 text-red-300 border border-red-500/25 shadow-[0_0_6px_rgba(248,81,73,0.12)]',   dot: 'bg-red-400 shadow-[0_0_4px_#f85149]' },
  investigating: { cls: 'bg-amber-500/10 text-amber-300 border border-amber-500/25',                                    dot: 'bg-amber-400' },
  closed:        { cls: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',                                    dot: 'bg-slate-500' },
  success:       { cls: 'bg-green-500/10 text-green-300 border border-green-500/25 shadow-[0_0_6px_rgba(63,185,80,0.1)]', dot: 'bg-green-400 shadow-[0_0_4px_#3fb950]' },
  failure:       { cls: 'bg-red-500/10 text-red-300 border border-red-500/25',                                          dot: 'bg-red-400' },
  info:          { cls: 'bg-blue-500/10 text-blue-300 border border-blue-500/25',                                       dot: 'bg-blue-400' },
  unknown:       { cls: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',                                    dot: 'bg-slate-500' },
}

export function Badge({ value, override }) {
  const key = (override || value || '').toLowerCase()
  const style = STYLES[key] || { cls: 'bg-slate-500/10 text-slate-400 border border-slate-500/20', dot: 'bg-slate-500' }
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide ${style.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${style.dot}`} />
      {value}
    </span>
  )
}

export function severityFromScore(score) {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}
