import { useEffect, useState, useCallback } from 'react'
import { SlidersHorizontal, RotateCcw, Plus, Trash2, CheckCircle, XCircle, VolumeX, Volume2, Info } from 'lucide-react'
import { api } from '../api'
import { Panel } from '../components/Panel'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

export function AlertTuning() {
  const [rules, setRules]           = useState([])
  const [suppressed, setSuppressed] = useState([])
  const [loading, setLoading]       = useState(true)
  const [editing, setEditing]       = useState({})     // { rule_name: draft_value }
  const [saving, setSaving]         = useState('')
  const [msg, setMsg]               = useState(null)
  const [suppressing, setSuppressing] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [r, s] = await Promise.all([api.tuningRules(), api.suppressedRules()])
      setRules(r)
      setSuppressed(s)
    } catch (_) {}
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  function flash(type, text) {
    setMsg({ type, text })
    setTimeout(() => setMsg(null), 3500)
  }

  async function saveThreshold(rule_name, value) {
    const n = parseInt(value, 10)
    if (isNaN(n) || n < 1) return flash('error', 'Threshold must be a positive integer')
    setSaving(rule_name)
    try {
      await api.tuningSetThreshold(rule_name, n)
      setRules(prev => prev.map(r => r.rule_name === rule_name ? { ...r, threshold: n, overridden: true } : r))
      setEditing(e => { const n2 = { ...e }; delete n2[rule_name]; return n2 })
      flash('success', `Threshold for "${rule_name}" updated to ${n}`)
    } catch (err) {
      flash('error', err.message)
    } finally { setSaving('') }
  }

  async function resetThreshold(rule_name, defaultVal) {
    setSaving(rule_name)
    try {
      await api.tuningResetThreshold(rule_name)
      setRules(prev => prev.map(r => r.rule_name === rule_name ? { ...r, threshold: defaultVal, overridden: false } : r))
      setEditing(e => { const n = { ...e }; delete n[rule_name]; return n })
      flash('success', `"${rule_name}" reset to default (${defaultVal})`)
    } catch (err) {
      flash('error', err.message)
    } finally { setSaving('') }
  }

  async function toggleSuppress(rule_name) {
    const isSuppressed = suppressed.some(s => s.rule_name === rule_name)
    setSuppressing(rule_name)
    try {
      if (isSuppressed) {
        await api.unsuppressRule(rule_name)
        setSuppressed(prev => prev.filter(s => s.rule_name !== rule_name))
      } else {
        const result = await api.suppressRule(rule_name, 'Suppressed via Tuning UI')
        setSuppressed(prev => [...prev, result])
      }
    } catch (err) {
      flash('error', err.message)
    } finally { setSuppressing('') }
  }

  const suppressedSet = new Set(suppressed.map(s => s.rule_name))
  const tunableRules = rules.filter(r => r.tunable)
  const eventRules   = rules.filter(r => !r.tunable)

  function RuleCard({ r }) {
    const draft = editing[r.rule_name]
    const currentVal = draft !== undefined ? draft : (r.threshold !== null ? String(r.threshold) : '')
    const isDirty = r.tunable && draft !== undefined && parseInt(draft, 10) !== r.threshold
    const isSuppressed = suppressedSet.has(r.rule_name)
    return (
      <div className={`flex items-start gap-4 p-4 rounded-xl border transition-colors ${
        isSuppressed
          ? 'border-red-500/20 bg-red-500/5 opacity-60'
          : r.overridden
          ? 'border-blue-500/30 bg-blue-500/5'
          : 'border-[#30363d] bg-[#1c2128]/50'
      }`}>
        {/* Rule info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <code className="text-xs font-mono text-slate-300 font-semibold">{r.rule_name}</code>
            {r.overridden && (
              <span className="text-[10px] px-1.5 py-0.5 rounded border bg-blue-500/10 border-blue-500/30 text-blue-400 font-semibold">CUSTOM</span>
            )}
            {isSuppressed && (
              <span className="text-[10px] px-1.5 py-0.5 rounded border bg-red-500/10 border-red-500/30 text-red-400 font-semibold">SUPPRESSED</span>
            )}
            {!r.tunable && (
              <span className="text-[10px] px-1.5 py-0.5 rounded border bg-slate-500/10 border-slate-500/20 text-slate-500">event-based</span>
            )}
          </div>
          <p className="text-xs text-slate-400 font-medium">{r.label}</p>
          <p className="text-xs text-slate-500 mt-0.5">{r.description}</p>
          {r.tunable && <p className="text-[10px] text-slate-600 mt-1">Default: <span className="text-slate-500">{r.default}</span></p>}
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2 shrink-0">
          {r.tunable && (
            <div className="flex items-center gap-1.5">
              <label className="text-xs text-slate-500 whitespace-nowrap">Threshold</label>
              <input
                type="number"
                min={1}
                max={9999}
                value={currentVal}
                onChange={e => setEditing(prev => ({ ...prev, [r.rule_name]: e.target.value }))}
                className="w-20 bg-[#161b22] border border-[#30363d] focus:border-blue-500 text-slate-200 text-sm text-center rounded-lg px-2 py-1.5 outline-none transition-colors"
              />
            </div>
          )}

          {isDirty && (
            <button
              onClick={() => saveThreshold(r.rule_name, draft)}
              disabled={saving === r.rule_name}
              className="flex items-center gap-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap"
            >
              <Plus size={11} />
              {saving === r.rule_name ? 'Saving…' : 'Apply'}
            </button>
          )}

          {r.tunable && r.overridden && !isDirty && (
            <button
              onClick={() => resetThreshold(r.rule_name, r.default)}
              disabled={saving === r.rule_name}
              title="Reset to default"
              className="flex items-center gap-1 text-slate-500 hover:text-slate-300 text-xs px-2 py-1.5 rounded-lg hover:bg-white/5 transition-colors"
            >
              <RotateCcw size={11} />
              Reset
            </button>
          )}

          {/* Suppress toggle */}
          <button
            onClick={() => toggleSuppress(r.rule_name)}
            disabled={suppressing === r.rule_name}
            title={isSuppressed ? 'Unsuppress — re-enable this rule' : 'Suppress — silence all alerts from this rule'}
            className={`p-1.5 rounded-lg transition-colors ${
              isSuppressed
                ? 'text-red-400 bg-red-500/10 hover:bg-red-500/20'
                : 'text-slate-500 hover:text-red-400 hover:bg-red-500/10'
            }`}
          >
            {isSuppressed ? <Volume2 size={14} /> : <VolumeX size={14} />}
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Alert Tuning</h2>
        <p className="text-sm text-slate-500">All {rules.length} detection rules — adjust thresholds and suppress noisy rules without touching code</p>
      </div>

      {msg && (
        <div className={`flex items-center gap-2 rounded-lg px-4 py-3 text-sm ${
          msg.type === 'success'
            ? 'bg-green-500/10 border border-green-500/20 text-green-400'
            : 'bg-red-500/10 border border-red-500/20 text-red-400'
        }`}>
          {msg.type === 'success' ? <CheckCircle size={14} /> : <XCircle size={14} />}
          {msg.text}
        </div>
      )}

      {/* Threshold-tunable rules */}
      <Panel title={`Threshold-Tunable Rules (${tunableRules.length})`}>
        <p className="text-xs text-slate-500 mb-5 flex items-center gap-1.5">
          <Info size={12} />
          Changes take effect on the next detection cycle. Reset to restore the original default.
        </p>
        {loading ? (
          <div className="text-slate-500 text-sm py-6 text-center">Loading…</div>
        ) : (
          <div className="space-y-3">
            {tunableRules.map(r => <RuleCard key={r.rule_name} r={r} />)}
          </div>
        )}
      </Panel>

      {/* Event-based rules */}
      <Panel title={`Event-Based Rules (${eventRules.length}) — Suppress Only`}>
        <p className="text-xs text-slate-500 mb-5 flex items-center gap-1.5">
          <Info size={12} />
          These rules fire on specific event patterns — no numeric threshold. You can suppress them to silence false positives.
        </p>
        {loading ? (
          <div className="text-slate-500 text-sm py-6 text-center">Loading…</div>
        ) : (
          <div className="space-y-3">
            {eventRules.map(r => <RuleCard key={r.rule_name} r={r} />)}
          </div>
        )}
      </Panel>

      {/* Suppression log */}
      <Panel title="Suppressed Rules">
        {suppressed.length === 0 ? (
          <p className="text-sm text-slate-600 py-4 text-center">No rules are currently suppressed.</p>
        ) : (
          <div className="space-y-2">
            {suppressed.map(s => (
              <div key={s.rule_name} className="flex items-center justify-between p-3 rounded-xl bg-red-500/5 border border-red-500/20">
                <div>
                  <code className="text-xs font-mono text-red-400 font-semibold">{s.rule_name}</code>
                  {s.reason && <p className="text-xs text-slate-500 mt-0.5">{s.reason}</p>}
                  <p className="text-[10px] text-slate-600 mt-0.5">By {s.suppressed_by} · {fmtTs(s.created_at)}</p>
                </div>
                <button
                  onClick={() => toggleSuppress(s.rule_name)}
                  disabled={suppressing === s.rule_name}
                  className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-green-400 hover:bg-green-500/10 px-3 py-1.5 rounded-lg border border-[#30363d] transition-colors"
                >
                  <Volume2 size={12} />
                  Unsuppress
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}
