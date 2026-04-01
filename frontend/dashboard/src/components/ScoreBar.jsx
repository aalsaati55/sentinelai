export function ScoreBar({ score }) {
  const pct = Math.min(score, 100)
  const color =
    pct >= 80 ? 'bg-red-500' :
    pct >= 60 ? 'bg-orange-500' :
    pct >= 30 ? 'bg-yellow-500' : 'bg-green-500'
  const textColor =
    pct >= 80 ? 'text-red-400' :
    pct >= 60 ? 'text-orange-400' :
    pct >= 30 ? 'text-yellow-400' : 'text-green-400'

  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <span className={`text-sm font-bold w-7 ${textColor}`}>{score}</span>
      <div className="flex-1 h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}
