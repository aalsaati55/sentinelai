export function Panel({ title, children, className = '', action }) {
  return (
    <div className={`bg-[#161b22] border border-[#30363d] rounded-xl p-5 ${className}`}>
      {title && (
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">{title}</h3>
          {action}
        </div>
      )}
      {children}
    </div>
  )
}
