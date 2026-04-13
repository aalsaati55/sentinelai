import { useEffect, useState, useMemo, useCallback, useRef } from 'react'
import { RefreshCw, X, ChevronDown, MessageSquare, Send, Download, Search, FileText, ShieldAlert, ShieldCheck, ShieldOff, CheckSquare, Square, Copy, Check, Zap, AlertTriangle, Play, Loader2 } from 'lucide-react'
import { api, token } from '../api'
import { Panel } from '../components/Panel'
import { Badge, severityFromScore } from '../components/Badge'
import { ScoreBar } from '../components/ScoreBar'
import { IncidentReport } from './IncidentReport'

function countryFlag(code) {
  if (!code || code.length !== 2) return null
  if (code === '--') return '🏠'
  const o = 0x1F1E6 - 65
  return String.fromCodePoint(code.toUpperCase().charCodeAt(0) + o) +
         String.fromCodePoint(code.toUpperCase().charCodeAt(1) + o)
}

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

function slaAge(createdAt, status) {
  if (!createdAt || status === 'closed') return null
  const diffMs = Date.now() - new Date(createdAt.replace(' ', 'T')).getTime()
  const h = Math.floor(diffMs / 3600000)
  const m = Math.floor((diffMs % 3600000) / 60000)
  const overdue = h >= 24
  const label = h >= 48 ? `${Math.floor(h/24)}d ${h%24}h` : h > 0 ? `${h}h ${m}m` : `${m}m`
  return { label, overdue }
}

const CATEGORY_COLORS = {
  contain:     'bg-red-500/10 text-red-400 border-red-500/20',
  block:       'bg-orange-500/10 text-orange-400 border-orange-500/20',
  investigate: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  remediate:   'bg-purple-500/10 text-purple-400 border-purple-500/20',
  monitor:     'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  escalate:    'bg-slate-500/10 text-slate-400 border-slate-500/20',
}

function CopyIpButton({ ip }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={e => { e.stopPropagation(); navigator.clipboard.writeText(ip).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) }) }}
      title="Copy IP"
      className="p-0.5 rounded text-slate-600 hover:text-slate-300 transition-colors"
    >
      {copied ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
    </button>
  )
}

function IncidentModal({ id, onClose, watchlistedIps = new Set(), onWatchlistChange, onNoteAdded }) {
  const [inc, setInc]         = useState(null)
  const [status, setStatus]   = useState('')
  const [saving, setSaving]   = useState(false)
  const [events, setEvents]   = useState([])
  const [notes, setNotes]         = useState([])
  const [newNote, setNewNote]     = useState('')
  const [addingNote, setAddingNote] = useState(false)
  const [analysts, setAnalysts]   = useState([])
  const [assignedTo, setAssignedTo] = useState('')
  const [assigning, setAssigning] = useState(false)
  const [showReport, setShowReport] = useState(false)
  const noteInputRef = useRef(null)
  const [mentionQuery, setMentionQuery] = useState(null) // null = closed, string = filter text
  const [mentionStart, setMentionStart] = useState(-1)  // caret position of the '@'
  const [playbook, setPlaybook]   = useState(null)
  const [checkedSteps, setCheckedSteps] = useState({})
  const [showPlaybook, setShowPlaybook] = useState(false)
  const [watchlisting, setWatchlisting] = useState(false)
  const [threatIntel, setThreatIntel]   = useState(null)
  const [tiLoading, setTiLoading]       = useState(false)
  const [soar, setSoar]                 = useState(null)
  const [showSoar, setShowSoar]         = useState(false)
  const [copiedCmd, setCopiedCmd]       = useState(null)
  const [loggedCmds, setLoggedCmds]     = useState(new Set())
  const [runningCmd, setRunningCmd]     = useState(null)
  const [runResult, setRunResult]       = useState(null)
  const me = token.user()

  useEffect(() => {
    if (!id) return
    Promise.all([
      api.incident(id),
      api.incidentEvents(id),
      api.incidentNotes(id),
      api.users().catch(() => []),
      api.incidentPlaybook(id).catch(() => null),
    ]).then(([i, evts, nts, users, pb]) => {
      setInc(i)
      setStatus(i.status)
      setAssignedTo(i.assigned_to || '')
      setEvents(evts)
      setNotes(nts)
      setAnalysts(users)
      if (pb) setPlaybook(pb)
      // Fetch threat intel for the source IP
      if (i.source_ip) {
        setTiLoading(true)
        api.threatIntel(i.source_ip)
          .then(d => setThreatIntel(d))
          .catch(() => {})
          .finally(() => setTiLoading(false))
      }
      api.incidentSoar(id).then(d => setSoar(d)).catch(() => {})
    })
  }, [id])

  function copyCmd(cmd, idx) {
    navigator.clipboard.writeText(cmd)
    setCopiedCmd(idx)
    setTimeout(() => setCopiedCmd(null), 1500)
  }

  function copyAllCmds() {
    if (!soar) return
    navigator.clipboard.writeText(soar.commands.map(c => c.cmd).join('\n'))
    setCopiedCmd('all')
    setTimeout(() => setCopiedCmd(null), 1500)
  }

  async function logExecuted(label, idx) {
    await api.logSoarExecuted(id, label)
    setLoggedCmds(prev => new Set([...prev, idx]))
  }

  async function runCmd(cmd, label, idx) {
    setRunningCmd(idx)
    try {
      const result = await api.soarExecute(cmd, id, label)
      setRunResult({ label, ...result })
      if (result.exit_code === 0) {
        setLoggedCmds(prev => new Set([...prev, idx]))
      }
    } catch (err) {
      setRunResult({ label, stdout: '', stderr: err.message || 'Execution failed', exit_code: -1, success: false })
    } finally {
      setRunningCmd(null)
    }
  }

  async function toggleWatchlist() {
    if (!inc?.source_ip) return
    setWatchlisting(true)
    try {
      if (watchlistedIps.has(inc.source_ip)) {
        await api.watchlistRemove(inc.source_ip)
      } else {
        await api.watchlistAdd(inc.source_ip, `Manually watchlisted from incident #${id}`)
      }
      onWatchlistChange?.()
    } finally { setWatchlisting(false) }
  }

  async function saveAssign() {
    setAssigning(true)
    try {
      const updated = await api.assignIncident(id, assignedTo || null)
      setAssignedTo(updated.assigned_to || '')
      setInc(updated)
      onClose(true)
    } finally { setAssigning(false) }
  }

  async function submitNote(e) {
    e.preventDefault()
    if (!newNote.trim()) return
    setAddingNote(true)
    try {
      const note = await api.addNote(id, newNote.trim())
      setNotes(prev => [...prev, note])
      setNewNote('')
      setMentionQuery(null)
      onNoteAdded?.(id)
    } finally { setAddingNote(false) }
  }

  function handleNoteChange(e) {
    const val = e.target.value
    setNewNote(val)
    const pos = e.target.selectionStart
    // Find the start of the current @word
    const textBefore = val.slice(0, pos)
    const match = textBefore.match(/@([a-zA-Z0-9_\-]*)$/)
    if (match) {
      setMentionQuery(match[1].toLowerCase())
      setMentionStart(pos - match[0].length)
    } else {
      setMentionQuery(null)
    }
  }

  function handleNoteKeyDown(e) {
    if (mentionQuery !== null && e.key === 'Escape') {
      setMentionQuery(null)
      e.preventDefault()
    }
  }

  function insertMention(username) {
    const input = noteInputRef.current
    const pos = input.selectionStart
    const before = newNote.slice(0, mentionStart)
    const after = newNote.slice(pos)
    const inserted = `@${username} `
    const next = before + inserted + after
    setNewNote(next)
    setMentionQuery(null)
    // Restore focus + move caret after inserted text
    setTimeout(() => {
      input.focus()
      const newPos = mentionStart + inserted.length
      input.setSelectionRange(newPos, newPos)
    }, 0)
  }

  const mentionSuggestions = mentionQuery !== null
    ? analysts.filter(u =>
        u.username !== me?.username &&
        u.username.toLowerCase().startsWith(mentionQuery)
      ).slice(0, 6)
    : []

  async function save() {
    setSaving(true)
    try {
      await api.updateStatus(id, status)
      onClose(true)
    } finally { setSaving(false) }
  }

  if (!inc) return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center">
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-8 text-slate-400">Loading…</div>
    </div>
  )

  const sev = severityFromScore(inc.risk_score)

  return (
    <>
      {showReport && <IncidentReport id={id} onClose={() => setShowReport(false)} />}
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b border-[#30363d]">
          <div>
            <h3 className="text-base font-semibold text-white mb-1">{inc.title}</h3>
            <div className="flex items-center gap-2 flex-wrap">
              <Badge value={sev} />
              <Badge value={inc.status} />
              {inc.anomaly_level && <Badge value={inc.anomaly_level} override={inc.anomaly_level} />}
            </div>
          </div>
          <div className="flex items-center gap-2 ml-4 mt-0.5">
            {inc?.source_ip && (
              <button
                onClick={toggleWatchlist}
                disabled={watchlisting}
                title={watchlistedIps.has(inc.source_ip) ? 'Remove from watchlist' : 'Add IP to watchlist'}
                className={`flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg border transition-colors disabled:opacity-50 ${
                  watchlistedIps.has(inc.source_ip)
                    ? 'bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20'
                    : 'bg-[#1c2128] border-[#30363d] text-slate-400 hover:text-orange-400 hover:border-orange-500'
                }`}
              >
                <ShieldOff size={13} />
                {watchlistedIps.has(inc.source_ip) ? 'Watchlisted' : 'Watchlist'}
              </button>
            )}
            <button
              onClick={() => setShowReport(true)}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-blue-400 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 px-2.5 py-1.5 rounded-lg transition-colors"
              title="Export PDF Report"
            >
              <FileText size={13} />
              Report
            </button>
            <button onClick={() => onClose()} className="text-slate-500 hover:text-slate-300 transition-colors">
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 space-y-6">
          {/* KV grid */}
          <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            {[
              ['Incident ID', `#${inc.id}`],
              ['Source IP',   inc.source_ip  || '—'],
              ['Username',    inc.username   || '—'],
              ['Anomaly',     inc.anomaly_level || '—'],
              ['Created',     fmtTs(inc.created_at)],
            ].map(([k, v]) => (
              <div key={k} className="flex flex-col gap-0.5">
                <span className="text-xs text-slate-500 uppercase tracking-wider">{k}</span>
                <span className="text-slate-200 font-mono text-xs">{v}</span>
              </div>
            ))}
            <div className="flex flex-col gap-0.5">
              <span className="text-xs text-slate-500 uppercase tracking-wider">Risk Score</span>
              <ScoreBar score={inc.risk_score} />
            </div>
          </div>

          {/* Threat Intelligence */}
          {inc.source_ip && (
            <div className="bg-[#1c2128] border rounded-lg p-4 border-[#30363d]" style={threatIntel?.abuse_score >= 25 ? {borderColor:'rgba(239,68,68,0.4)', background:'rgba(239,68,68,0.05)'} : {}}>
              <div className="flex items-center gap-2 mb-3">
                <Zap size={12} className={threatIntel?.abuse_score >= 75 ? 'text-red-400' : threatIntel?.abuse_score >= 25 ? 'text-orange-400' : 'text-slate-500'} />
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Threat Intelligence</span>
                {tiLoading && <span className="text-xs text-slate-600">Checking AbuseIPDB…</span>}
                {threatIntel?.abuse_score >= 75 && (
                  <span className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30">🔴 KNOWN THREAT</span>
                )}
                {threatIntel?.abuse_score >= 25 && threatIntel?.abuse_score < 75 && (
                  <span className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/30">⚠ SUSPICIOUS</span>
                )}
                {threatIntel && threatIntel.abuse_score < 25 && !tiLoading && (
                  <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-green-500/10 text-green-500 border border-green-500/20">✓ Clean</span>
                )}
              </div>
              {threatIntel && !threatIntel.error ? (
                <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
                  <div><span className="text-slate-500">Abuse Score: </span><span className={`font-bold ${ threatIntel.abuse_score >= 75 ? 'text-red-400' : threatIntel.abuse_score >= 25 ? 'text-orange-400' : 'text-green-400'}`}>{threatIntel.abuse_score}%</span></div>
                  <div><span className="text-slate-500">Reports: </span><span className="text-slate-200">{threatIntel.total_reports}</span></div>
                  <div><span className="text-slate-500">ISP: </span><span className="text-slate-200">{threatIntel.isp || '—'}</span></div>
                  <div><span className="text-slate-500">TOR Exit: </span><span className={threatIntel.is_tor ? 'text-red-400 font-semibold' : 'text-slate-200'}>{threatIntel.is_tor ? 'YES' : 'No'}</span></div>
                  {threatIntel.categories?.length > 0 && (
                    <div className="col-span-2">
                      <span className="text-slate-500">Reported for: </span>
                      <span className="text-slate-200">{threatIntel.categories.join(', ')}</span>
                    </div>
                  )}
                  {threatIntel.last_reported_at && (
                    <div className="col-span-2"><span className="text-slate-500">Last reported: </span><span className="text-slate-400">{threatIntel.last_reported_at?.slice(0,10)}</span></div>
                  )}
                </div>
              ) : !tiLoading && (
                <p className="text-xs text-slate-600">No threat data available for {inc.source_ip}</p>
              )}
            </div>
          )}

          {/* Description */}
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Description</p>
            <div className="bg-[#1c2128] border border-[#30363d] rounded-lg p-4 text-sm text-slate-300 leading-relaxed">
              {inc.description}
            </div>
          </div>

          {/* Linked events */}
          {events.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Linked Events ({events.length})</p>
              <div className="bg-[#1c2128] border border-[#30363d] rounded-lg overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[#30363d]">
                      {['Time', 'Type', 'IP', 'User', 'Status'].map(h => (
                        <th key={h} className="px-3 py-2 text-left text-slate-500 font-semibold uppercase tracking-wider">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {events.map(e => (
                      <tr key={e.id} className="border-t border-[#30363d]/50 hover:bg-white/[0.02]">
                        <td className="px-3 py-2 text-slate-400 whitespace-nowrap">{fmtTs(e.timestamp)}</td>
                        <td className="px-3 py-2 font-mono text-slate-300">{e.event_type}</td>
                        <td className="px-3 py-2 text-slate-400">{e.source_ip || '—'}</td>
                        <td className="px-3 py-2 text-slate-400">{e.username || '—'}</td>
                        <td className="px-3 py-2"><Badge value={e.status} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Response Playbook */}
          {playbook && playbook.steps.length > 0 && (
            <div>
              <button
                onClick={() => setShowPlaybook(v => !v)}
                className="flex items-center gap-2 text-xs text-slate-400 uppercase tracking-wider mb-3 hover:text-slate-200 transition-colors w-full text-left"
              >
                <ShieldAlert size={11} className="text-orange-400" />
                Response Playbook
                <span className="ml-auto text-slate-600 text-xs">{showPlaybook ? '▲ hide' : '▼ show'}</span>
                <span className="bg-orange-500/10 text-orange-400 border border-orange-500/20 text-xs px-1.5 py-0.5 rounded-full font-semibold">
                  {playbook.steps.length} steps
                </span>
              </button>
              {showPlaybook && (
                <div className="space-y-1.5">
                  {playbook.steps.map((step, i) => (
                    <div
                      key={i}
                      onClick={() => setCheckedSteps(p => ({ ...p, [i]: !p[i] }))}
                      className={`flex items-start gap-3 rounded-lg border px-3 py-2.5 cursor-pointer transition-colors ${
                        checkedSteps[i]
                          ? 'bg-green-500/5 border-green-500/20 opacity-60'
                          : `border ${CATEGORY_COLORS[step.category] || 'border-[#30363d] text-slate-300'} bg-[#1c2128]/40`
                      }`}
                    >
                      {checkedSteps[i]
                        ? <CheckSquare size={14} className="text-green-400 mt-0.5 shrink-0" />
                        : <Square size={14} className="mt-0.5 shrink-0 opacity-50" />
                      }
                      <div className="flex-1 min-w-0">
                        <p className={`text-xs leading-relaxed ${ checkedSteps[i] ? 'line-through text-slate-500' : '' }`}>
                          {step.step}
                        </p>
                      </div>
                      <span className={`text-[10px] border rounded px-1.5 py-0.5 shrink-0 font-semibold uppercase ${
                        CATEGORY_COLORS[step.category] || 'border-slate-600 text-slate-500'
                      }`}>
                        {step.category_meta?.label || step.category}
                      </span>
                    </div>
                  ))}
                  <p className="text-xs text-slate-600 text-right pt-1">
                    {Object.values(checkedSteps).filter(Boolean).length} / {playbook.steps.length} completed
                  </p>
                </div>
              )}
            </div>
          )}

          {/* SOAR Remediation Commands */}
          {soar && soar.commands.length > 0 && (
            <div>
              <button
                onClick={() => setShowSoar(v => !v)}
                className="flex items-center gap-2 text-xs text-slate-400 uppercase tracking-wider mb-3 hover:text-slate-200 transition-colors w-full text-left"
              >
                <Zap size={11} className="text-yellow-400" />
                SOAR Remediation Commands
                <span className="ml-auto text-slate-600 text-xs">{showSoar ? '▲ hide' : '▼ show'}</span>
                <span className="bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 text-xs px-1.5 py-0.5 rounded-full font-semibold">
                  {soar.commands.length} commands
                </span>
              </button>
              {showSoar && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-[11px] text-slate-600">Target: <code className="text-slate-400 font-mono">{soar.source_ip}</code></p>
                    <button
                      onClick={copyAllCmds}
                      className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-[#30363d] text-slate-500 hover:text-slate-200 hover:border-slate-500 transition-colors"
                    >
                      {copiedCmd === 'all' ? <Check size={10} className="text-green-400" /> : <Copy size={10} />}
                      {copiedCmd === 'all' ? 'Copied!' : 'Copy all'}
                    </button>
                  </div>
                  {soar.commands.map((c, i) => (
                    <div key={i} className={`rounded-lg border transition-colors ${loggedCmds.has(i) ? 'border-green-500/30 bg-green-500/5' : 'border-[#30363d] bg-[#0d1117]'}`}>
                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-[#30363d]/50">
                        <span className={`text-[11px] font-medium ${loggedCmds.has(i) ? 'text-green-400' : 'text-slate-400'}`}>
                          {loggedCmds.has(i) ? '✓ ' : ''}{c.label}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={() => copyCmd(c.cmd, i)}
                            title="Copy command"
                            className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-[#30363d] text-slate-600 hover:text-slate-200 hover:border-slate-500 transition-colors"
                          >
                            {copiedCmd === i ? <Check size={9} className="text-green-400" /> : <Copy size={9} />}
                            {copiedCmd === i ? 'Copied' : 'Copy'}
                          </button>
                          <button
                            onClick={() => runCmd(c.cmd, c.label, i)}
                            disabled={runningCmd !== null}
                            title="Auto-execute via SSH"
                            className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-blue-500/30 text-blue-400 hover:bg-blue-500/10 hover:border-blue-400 disabled:opacity-40 transition-colors"
                          >
                            {runningCmd === i ? <Loader2 size={9} className="animate-spin" /> : <Play size={9} />}
                            {runningCmd === i ? 'Running…' : 'Run'}
                          </button>
                          {!loggedCmds.has(i) && (
                            <button
                              onClick={() => logExecuted(c.label, i)}
                              title="Mark as executed"
                              className="text-[10px] px-1.5 py-0.5 rounded border border-[#30363d] text-slate-600 hover:text-green-400 hover:border-green-500/40 transition-colors"
                            >
                              ✓ Executed
                            </button>
                          )}
                        </div>
                      </div>
                      <pre className="px-3 py-2 text-[11px] font-mono text-green-300 overflow-x-auto whitespace-pre-wrap break-all">{c.cmd}</pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* SOAR Run Result Modal */}
          {runResult && (
            <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4" onClick={() => setRunResult(null)}>
              <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-lg shadow-2xl" onClick={e => e.stopPropagation()}>
                <div className="flex items-center justify-between px-5 py-3 border-b border-[#30363d]">
                  <div className="flex items-center gap-2">
                    {runResult.success
                      ? <Check size={14} className="text-green-400" />
                      : <X size={14} className="text-red-400" />}
                    <span className="text-sm font-semibold text-white">Command Result</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-mono ${
                      runResult.exit_code === 0
                        ? 'bg-green-500/10 border-green-500/20 text-green-400'
                        : 'bg-red-500/10 border-red-500/20 text-red-400'
                    }`}>exit {runResult.exit_code}</span>
                  </div>
                  <button onClick={() => setRunResult(null)} className="text-slate-500 hover:text-slate-300"><X size={14} /></button>
                </div>
                <div className="px-5 py-3">
                  <p className="text-xs text-slate-500 mb-2 font-mono">{runResult.label}</p>
                  {runResult.stdout && (
                    <div className="mb-3">
                      <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">stdout</p>
                      <pre className="bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-xs font-mono text-green-300 overflow-x-auto whitespace-pre-wrap max-h-48 overflow-y-auto">{runResult.stdout}</pre>
                    </div>
                  )}
                  {runResult.stderr && (
                    <div>
                      <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">stderr</p>
                      <pre className="bg-[#0d1117] border border-[#30363d] rounded-lg px-3 py-2 text-xs font-mono text-red-300 overflow-x-auto whitespace-pre-wrap max-h-32 overflow-y-auto">{runResult.stderr}</pre>
                    </div>
                  )}
                  {!runResult.stdout && !runResult.stderr && (
                    <p className="text-xs text-slate-500 italic">No output</p>
                  )}
                </div>
                <div className="px-5 py-3 border-t border-[#30363d] flex justify-end">
                  <button onClick={() => setRunResult(null)} className="text-sm text-slate-400 hover:text-slate-200 transition-colors">Close</button>
                </div>
              </div>
            </div>
          )}

          {/* Investigation Notes */}
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <MessageSquare size={11} /> Investigation Notes ({notes.length})
            </p>

            {/* Existing notes */}
            {notes.length > 0 && (
              <div className="space-y-2 mb-3">
                {notes.map(n => (
                  <div key={n.id} className="bg-[#1c2128] border border-[#30363d] rounded-lg px-4 py-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-blue-400">{n.username}</span>
                      <span className="text-xs text-slate-600">{fmtTs(n.created_at)}</span>
                    </div>
                    <p className="text-sm text-slate-300 leading-relaxed">{n.note}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Add note form */}
            <form onSubmit={submitNote} className="flex gap-2 relative">
              <div className="flex-1 relative">
                <input
                  ref={noteInputRef}
                  type="text"
                  value={newNote}
                  onChange={handleNoteChange}
                  onKeyDown={handleNoteKeyDown}
                  placeholder="Add investigation note… (type @ to mention)"
                  className="w-full bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 outline-none focus:border-blue-500 placeholder-slate-600"
                />
                {mentionSuggestions.length > 0 && (
                  <div className="absolute bottom-full mb-1 left-0 w-56 bg-[#1c2128] border border-[#30363d] rounded-lg shadow-2xl z-50 overflow-hidden">
                    {mentionSuggestions.map(u => (
                      <button
                        key={u.id}
                        type="button"
                        onMouseDown={e => { e.preventDefault(); insertMention(u.username) }}
                        className="w-full flex items-center gap-2.5 px-3 py-2 text-left hover:bg-white/5 transition-colors"
                      >
                        <span className="w-6 h-6 rounded-full bg-blue-600/30 flex items-center justify-center text-[10px] font-bold text-blue-400 shrink-0">
                          {u.username[0].toUpperCase()}
                        </span>
                        <span className="text-sm text-slate-200 font-medium">@{u.username}</span>
                        <span className="ml-auto text-[10px] text-slate-500 capitalize">{u.role}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={addingNote || !newNote.trim()}
                className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-sm font-semibold px-3 py-2 rounded-lg transition-colors"
              >
                <Send size={13} />
                {addingNote ? '…' : 'Add'}
              </button>
            </form>
          </div>

          {/* Status + Assignment */}
          <div className="space-y-3 pt-2 border-t border-[#30363d]">
            {/* Status */}
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-xs text-slate-500 uppercase tracking-wider w-24">Status</span>
              <div className="relative">
                <select
                  value={status}
                  onChange={e => setStatus(e.target.value)}
                  className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 pr-8 outline-none focus:border-blue-500 cursor-pointer"
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="closed">Closed</option>
                </select>
                <ChevronDown size={14} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
              </div>
              <button
                onClick={save}
                disabled={saving}
                className="bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
              >
                {saving ? 'Saving…' : 'Save'}
              </button>
            </div>

            {/* Assignment — admin only */}
            {me?.role === 'admin' && (
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-xs text-slate-500 uppercase tracking-wider w-24">Assign To</span>
                <div className="relative">
                  <select
                    value={assignedTo}
                    onChange={e => setAssignedTo(e.target.value)}
                    className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 pr-8 outline-none focus:border-blue-500 cursor-pointer"
                  >
                    <option value="">— Unassigned —</option>
                    {analysts.map(u => (
                      <option key={u.id} value={u.username}>{u.username} ({u.role})</option>
                    ))}
                  </select>
                  <ChevronDown size={14} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                </div>
                <button
                  onClick={saveAssign}
                  disabled={assigning}
                  className="bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
                >
                  {assigning ? 'Assigning…' : 'Assign'}
                </button>
                {inc?.assigned_to && (
                  <span className="text-xs text-slate-500">
                    Currently: <span className="text-blue-400 font-semibold">{inc.assigned_to}</span>
                  </span>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
    </>
  )
}

export function Incidents() {
  const [incidents, setIncidents]     = useState([])
  const [selected, setSelected]       = useState(null)
  const [filter, setFilter]           = useState('')
  const [search, setSearch]           = useState('')
  const [loading, setLoading]         = useState(true)
  const [geoMap, setGeoMap]           = useState({})
  const [watchlistedIps, setWatchlistedIps] = useState(new Set())
  const [tiMap, setTiMap]             = useState({})

  async function loadWatchlist() {
    try {
      const wl = await api.watchlist()
      setWatchlistedIps(new Set(wl.map(w => w.source_ip)))
    } catch (_) {}
  }

  const loadRef = useRef(null)

  async function load() {
    setLoading(true)
    const params = filter ? { status: filter } : {}
    try {
      const data = await api.incidents(params)
      setIncidents(data)
      const ips = [...new Set(data.map(i => i.source_ip).filter(Boolean))]
      if (ips.length > 0) {
        try { const geo = await api.geoBulk(ips); setGeoMap(geo) } catch (_) {}
        try { const ti = await api.threatIntelBulk(ips); setTiMap(ti) } catch (_) {}
      }
    } finally { setLoading(false) }
  }

  loadRef.current = load

  useEffect(() => { load(); loadWatchlist() }, [filter])

  useEffect(() => {
    let ws
    let dead = false
    let pingTimer

    function connect() {
      if (dead) return
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      ws = new WebSocket(`${proto}://${window.location.hostname}:8000/api/live/ws`)
      ws.onopen = () => {
        pingTimer = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send('ping')
        }, 20000)
      }
      let debounceTimer = null
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'incident') {
            clearTimeout(debounceTimer)
            debounceTimer = setTimeout(() => loadRef.current?.(), 2000)
          }
        } catch (_) {}
      }
      ws.onclose = () => {
        clearInterval(pingTimer)
        if (!dead) setTimeout(connect, 3000)
      }
      ws.onerror = () => ws.close()
    }

    connect()
    return () => {
      dead = true
      clearInterval(pingTimer)
      ws?.close()
    }
  }, [])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return incidents
    return incidents.filter(i =>
      (i.title      || '').toLowerCase().includes(q) ||
      (i.source_ip  || '').toLowerCase().includes(q) ||
      (i.username   || '').toLowerCase().includes(q)
    )
  }, [incidents, search])

  function handleModalClose(refresh) {
    setSelected(null)
    if (refresh) load()
  }

  return (
    <div className="space-y-5">
      {selected && <IncidentModal id={selected} onClose={handleModalClose} watchlistedIps={watchlistedIps} onWatchlistChange={loadWatchlist} onNoteAdded={incId => setIncidents(prev => prev.map(i => i.id === incId ? { ...i, note_count: (i.note_count || 0) + 1 } : i))} />}

      <div>
        <h2 className="text-xl font-bold text-white mb-1">Incidents</h2>
        <p className="text-sm text-slate-500">Correlated security incidents grouped from alerts</p>
      </div>

      <Panel>
        {/* Toolbar */}
        <div className="flex items-center gap-3 mb-5 flex-wrap">
          <div className="relative">
            <select
              value={filter}
              onChange={e => setFilter(e.target.value)}
              className="appearance-none bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2 pr-8 outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="closed">Closed</option>
            </select>
            <ChevronDown size={14} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
          </div>
          <div className="relative">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
            <input
              type="text"
              placeholder="Search title, IP, user…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg pl-8 pr-3 py-2 w-52 outline-none focus:border-blue-500 placeholder-slate-600"
            />
          </div>
          <button
            onClick={load}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button
            onClick={() => api.exportIncidentsCsv(filter)}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-green-500 text-slate-300 text-sm px-3 py-2 rounded-lg transition-colors ml-auto"
          >
            <Download size={13} />
            Export CSV
          </button>
          <span className="text-xs text-slate-500">{filtered.length} incident{filtered.length !== 1 ? 's' : ''}</span>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['#', 'Title', 'Source IP', 'User', 'Risk Score', 'Severity', 'Status', 'SLA', 'Assigned', 'Created', ''].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} className="py-10 text-center text-slate-500">Loading…</td></tr>
              ) : filtered.length ? filtered.map(i => (
                <tr key={i.id} className="border-t border-[#30363d] hover:bg-white/[0.02] transition-colors cursor-pointer"
                    onClick={() => setSelected(i.id)}>
                  <td className="py-3 pr-4 text-slate-500 text-xs">{i.id}</td>
                  <td className="py-3 pr-4 text-slate-200 max-w-[220px]">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate block">{i.title}</span>
                      {i.note_count > 0 && (
                        <span title={`${i.note_count} investigation note${i.note_count !== 1 ? 's' : ''}`}
                          className="shrink-0 flex items-center gap-0.5 text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-blue-500/15 text-blue-400 border border-blue-500/20">
                          <MessageSquare size={9} />{i.note_count}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 pr-4 whitespace-nowrap">
                    {i.source_ip ? (
                      <div className="flex items-center gap-1">
                        {geoMap[i.source_ip]?.country_code && (
                          <span className="text-sm leading-none" title={geoMap[i.source_ip]?.country}>
                            {countryFlag(geoMap[i.source_ip].country_code)}
                          </span>
                        )}
                        <code className="text-[11px] font-mono text-slate-300">{i.source_ip}</code>
                        {watchlistedIps.has(i.source_ip) && (
                          <span title="Watchlisted IP" className="text-red-400 text-xs">🚫</span>
                        )}
                        {tiMap[i.source_ip]?.abuse_score >= 75 && (
                          <span title={`AbuseIPDB: ${tiMap[i.source_ip].abuse_score}% confidence`} className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 whitespace-nowrap">🔴 Threat</span>
                        )}
                        {tiMap[i.source_ip]?.abuse_score >= 25 && tiMap[i.source_ip]?.abuse_score < 75 && (
                          <span title={`AbuseIPDB: ${tiMap[i.source_ip].abuse_score}% confidence`} className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/30 whitespace-nowrap">⚠ Suspicious</span>
                        )}
                        <CopyIpButton ip={i.source_ip} />
                      </div>
                    ) : <span className="text-slate-600 text-xs">—</span>}
                  </td>
                  <td className="py-3 pr-4 text-slate-400">{i.username || '—'}</td>
                  <td className="py-3 pr-4"><ScoreBar score={i.risk_score} /></td>
                  <td className="py-3 pr-4">
                    <Badge value={i.anomaly_level || severityFromScore(i.risk_score)} />
                  </td>
                  <td className="py-3 pr-4"><Badge value={i.status} /></td>
                  <td className="py-3 pr-4">
                    {(() => { const s = slaAge(i.created_at, i.status); return s ? (
                      <span className={`text-xs font-mono font-semibold ${s.overdue ? 'text-red-400' : 'text-slate-400'}`}>
                        {s.overdue ? '⚠ ' : ''}{s.label}
                      </span>
                    ) : <span className="text-slate-600 text-xs">closed</span> })()}
                  </td>
                  <td className="py-3 pr-4 text-slate-400 text-xs">{i.assigned_to || <span className="text-slate-700">—</span>}</td>
                  <td className="py-3 pr-4 text-slate-500 text-xs whitespace-nowrap">{fmtTs(i.created_at)}</td>
                  <td className="py-3">
                    <button
                      onClick={e => { e.stopPropagation(); setSelected(i.id) }}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      Details
                    </button>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan={11} className="py-10 text-center text-slate-500 text-sm">
                  {search ? `No incidents match "${search}"` : 'No incidents found. Run the pipeline to generate data.'}
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
