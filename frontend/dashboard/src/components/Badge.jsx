const COLORS = {
  critical:     'bg-red-500/15 text-red-400 border border-red-500/30',
  high:         'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  medium:       'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  low:          'bg-green-500/15 text-green-400 border border-green-500/30',
  open:         'bg-red-500/15 text-red-400 border border-red-500/30',
  investigating:'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  closed:       'bg-green-500/15 text-green-400 border border-green-500/30',
  success:      'bg-green-500/15 text-green-400 border border-green-500/30',
  failure:      'bg-red-500/15 text-red-400 border border-red-500/30',
  info:         'bg-blue-500/15 text-blue-400 border border-blue-500/30',
}

export function Badge({ value, override }) {
  const key = (override || value || '').toLowerCase()
  const cls = COLORS[key] || 'bg-slate-500/15 text-slate-400 border border-slate-500/30'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide ${cls}`}>
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
