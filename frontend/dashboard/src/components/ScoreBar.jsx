export function ScoreBar({ score }) {
  const pct = Math.min(score, 100)
  const gradient =
    pct >= 80 ? 'from-red-500 to-orange-400' :
    pct >= 60 ? 'from-orange-500 to-yellow-400' :
    pct >= 30 ? 'from-yellow-500 to-amber-300' : 'from-green-500 to-emerald-400'
  const textColor =
    pct >= 80 ? 'text-red-300' :
    pct >= 60 ? 'text-orange-300' :
    pct >= 30 ? 'text-yellow-300' : 'text-green-300'
  const glow =
    pct >= 80 ? 'shadow-[0_0_6px_rgba(248,81,73,0.5)]' :
    pct >= 60 ? 'shadow-[0_0_6px_rgba(249,115,22,0.4)]' :
    pct >= 30 ? 'shadow-[0_0_6px_rgba(234,179,8,0.3)]' : ''

  return (
    <div className="flex items-center gap-2.5 min-w-[110px]">
      <span className={`text-xs font-bold w-7 tabular-nums ${textColor}`}>{score}</span>
      <div className="flex-1 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full bg-gradient-to-r ${gradient} ${glow} transition-all duration-500`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  )
}
