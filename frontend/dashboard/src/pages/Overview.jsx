import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { Activity, AlertTriangle, Bell, Globe, Radio, ShieldAlert, ShieldOff, TrendingUp, Zap, RefreshCw } from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  LineChart, Line, CartesianGrid, Area, AreaChart,
} from 'recharts'
import { api } from '../api'
import { StatCard } from '../components/StatCard'
import { Panel } from '../components/Panel'
import { Badge, severityFromScore } from '../components/Badge'
import { ScoreBar } from '../components/ScoreBar'
import { LiveFeed } from '../components/LiveFeed'

const PIE_COLORS = { critical: '#f85149', high: '#ff7b72', medium: '#e3b341', low: '#3fb950' }
const BAR_COLOR = '#58a6ff'

function fmtTs(ts) {
  if (!ts) return '—'
  return ts.replace('T', ' ').slice(0, 16)
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-[#1c2128] border border-[#30363d] rounded-lg px-3 py-2 text-xs text-slate-300 shadow-xl">
      <p className="font-semibold mb-1">{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  )
}

export function Overview({ onGoToIncidents }) {
  const [summary, setSummary]     = useState(null)
  const [topIps, setTopIps]       = useState([])
  const [severity, setSeverity]   = useState([])
  const [etypes, setEtypes]       = useState([])
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading]     = useState(true)
  const [liveEvents, setLiveEvents]         = useState(0)
  const [liveAlerts, setLiveAlerts]         = useState(0)
  const [incidentTrend, setIncidentTrend]   = useState([])
  const [alertTrend, setAlertTrend]         = useState([])
  const [countryData, setCountryData]       = useState([])
  const [riskTrend, setRiskTrend]           = useState([])
  const [mttdMttr, setMttdMttr]             = useState(null)
  const [teamActivity, setTeamActivity]     = useState([])
  const [fpStats, setFpStats]               = useState(null)
  const [days, setDays]                     = useState(30)
  const [lastRefresh, setLastRefresh]       = useState(null)
  const [secondsAgo, setSecondsAgo]         = useState(0)
  const [refreshing, setRefreshing]         = useState(false)
  const intervalRef                         = useRef(null)
  const tickRef                             = useRef(null)

  const refreshSummary = useCallback((silent = false) => {
    if (!silent) setRefreshing(true)
    Promise.all([api.summary(), api.incidents({ limit: 8 })])
      .then(([s, inc]) => {
        setSummary(s)
        setIncidents(inc)
        setLastRefresh(new Date())
      })
      .catch(() => {})
      .finally(() => { if (!silent) setRefreshing(false) })
  }, [])

  useEffect(() => {
    Promise.all([
      api.summary(),
      api.topIps(8),
      api.severity(),
      api.eventTypes(),
      api.incidents({ limit: 8 }),
      api.incidentTimeline(days),
      api.alertTimeline(days),
      api.geoMap(),
      api.riskTrend(7),
      api.mttdMttr(),
      api.teamActivity(),
      api.fpStats(),
    ]).then(([s, ips, sev, et, inc, itl, atl, geo, rt, mm, ta, fp]) => {
      if (mm) setMttdMttr(mm)
      if (ta) setTeamActivity(ta)
      if (fp) setFpStats(fp)
      setSummary(s)
      setTopIps(ips)
      setSeverity(sev.map(d => ({ name: d.severity, value: d.count })))
      setEtypes(et.slice(0, 10).map(d => ({ name: d.event_type.replace('_', ' '), value: d.count })))
      setIncidents(inc)
      setIncidentTrend(itl.map(d => ({ day: d.day.slice(5), count: d.count })))
      // Pivot alert timeline: [{day, critical, high, medium, low}]
      const amap = {}
      atl.forEach(({ day, severity, count }) => {
        const k = day.slice(5)
        if (!amap[k]) amap[k] = { day: k, critical: 0, high: 0, medium: 0, low: 0 }
        amap[k][severity] = count
      })
      setAlertTrend(Object.values(amap))
      // Build country attack counts from GeoIP map data
      const geoPoints = geo?.points || []
      if (geoPoints.length > 0) {
        const cmap = {}
        geoPoints.forEach(({ country, alert_count }) => {
          const c = country || 'Unknown'
          cmap[c] = (cmap[c] || 0) + (alert_count || 1)
        })
        const sorted = Object.entries(cmap)
          .map(([country, count]) => ({ country, count }))
          .sort((a, b) => b.count - a.count)
          .slice(0, 10)
        setCountryData(sorted)
      }
      setRiskTrend(rt.map(d => ({ day: d.day.slice(5), avg: d.avg_risk, max: d.max_risk, alerts: d.alert_count })))
      setLoading(false)
      setLastRefresh(new Date())
      setSecondsAgo(0)
    }).catch(() => setLoading(false))
  }, [days])

  // Auto-refresh summary every 30 seconds
  useEffect(() => {
    intervalRef.current = setInterval(() => {
      refreshSummary(true)
      setSecondsAgo(0)
    }, 30000)
    return () => clearInterval(intervalRef.current)
  }, [refreshSummary])

  // Tick seconds-ago counter every second
  useEffect(() => {
    tickRef.current = setInterval(() => setSecondsAgo(s => s + 1), 1000)
    return () => clearInterval(tickRef.current)
  }, [])

  function handleNewEvent() {
    setLiveEvents(c => c + 1)
    refreshSummary()
  }

  function handleNewAlert() {
    setLiveAlerts(c => c + 1)
    refreshSummary()
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="flex flex-col items-center gap-3">
        <div className="relative">
          <div className="w-10 h-10 rounded-full border-2 border-blue-500/20 border-t-blue-500 animate-spin" />
          <div className="absolute inset-2 rounded-full bg-blue-500/10" />
        </div>
        <span className="text-sm text-slate-500">Loading dashboard…</span>
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="flex items-center gap-1.5">
              <span className="neon-dot-green" />
              <span className="text-[10px] font-bold uppercase tracking-widest text-green-400">Live</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">SOC Overview</h2>
          </div>
          <p className="text-sm text-slate-600">Real-time security posture · {lastRefresh && (
            <span>{secondsAgo < 5 ? 'just updated' : `updated ${secondsAgo}s ago`}</span>
          )}</p>
        </div>
        <button
          onClick={() => refreshSummary(false)}
          disabled={refreshing}
          className="btn-ghost flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg disabled:opacity-50"
        >
          <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Events"   value={summary?.total_events}   icon={Activity}     color="blue" />
        <StatCard label="Total Alerts"   value={summary?.total_alerts}   icon={Bell}         color="yellow" />
        <StatCard label="Open Incidents" value={summary?.open_incidents} icon={AlertTriangle} color="red" />
        <StatCard label="Unique IPs"     value={summary?.unique_source_ips} icon={Globe}     color="purple" />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Critical" value={summary?.critical_alerts} icon={ShieldAlert} color="red"    sub="alerts" />
        <StatCard label="High"     value={summary?.high_alerts}     icon={Zap}         color="orange" sub="alerts" />
        <StatCard label="Medium"   value={summary?.medium_alerts}   icon={TrendingUp}  color="yellow" sub="alerts" />
        <StatCard label="Low"      value={summary?.low_alerts}      icon={Activity}    color="green"  sub="alerts" />
      </div>

      {/* MTTD / MTTR */}
      {mttdMttr && (
        <div className="grid grid-cols-2 gap-4">
          <div className="relative overflow-hidden rounded-2xl border border-blue-500/15 bg-blue-500/[0.04] p-4 shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-blue-500 to-cyan-400 opacity-60" />
            <div className="absolute -top-6 -right-6 w-20 h-20 rounded-full bg-blue-500/10 blur-2xl pointer-events-none" />
            <div className="flex items-center gap-2 mb-2">
              <div className="p-1.5 rounded-lg bg-blue-500/10"><Zap size={12} className="text-blue-400" /></div>
              <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Mean Time to Detect</span>
            </div>
            <p className="text-3xl font-bold text-blue-300">
              {mttdMttr.mttd_minutes < 1 ? '<1m' : mttdMttr.mttd_minutes < 60
                ? `${Math.round(mttdMttr.mttd_minutes)}m`
                : `${(mttdMttr.mttd_minutes / 60).toFixed(1)}h`}
            </p>
            <p className="text-xs text-slate-600 mt-1">First alert → incident creation</p>
          </div>
          <div className="relative overflow-hidden rounded-2xl border border-green-500/15 bg-green-500/[0.04] p-4 shadow-[0_4px_20px_rgba(0,0,0,0.3)]">
            <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-green-500 to-emerald-400 opacity-60" />
            <div className="absolute -top-6 -right-6 w-20 h-20 rounded-full bg-green-500/10 blur-2xl pointer-events-none" />
            <div className="flex items-center gap-2 mb-2">
              <div className="p-1.5 rounded-lg bg-green-500/10"><ShieldAlert size={12} className="text-green-400" /></div>
              <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Mean Time to Respond</span>
            </div>
            <p className="text-3xl font-bold text-green-300">
              {mttdMttr.mttr_minutes === 0 ? 'N/A' : mttdMttr.mttr_minutes < 60
                ? `${Math.round(mttdMttr.mttr_minutes)}m`
                : `${(mttdMttr.mttr_minutes / 60).toFixed(1)}h`}
            </p>
            <p className="text-xs text-slate-600 mt-1">Incident creation → close</p>
          </div>
        </div>
      )}

      {/* False Positive Rate Panel */}
      {fpStats && (
        <Panel>
          <div className="flex items-center gap-2 mb-4">
            <div className="p-1.5 rounded-lg bg-yellow-500/10"><ShieldOff size={12} className="text-yellow-400" /></div>
            <span className="text-xs font-bold uppercase tracking-widest text-slate-500">False Positive Rate</span>
            {fpStats.fp_this_week > 0 && (
              <span className="ml-auto text-[10px] font-semibold px-2.5 py-0.5 rounded-full bg-yellow-500/10 border border-yellow-500/20 text-yellow-300">
                {fpStats.fp_this_week} FP this week
              </span>
            )}
          </div>
          <div className="grid grid-cols-2 gap-4 mb-4">
            {[['Alert FP Rate', fpStats.alert_fp_rate, fpStats.alert_fp, fpStats.alert_total],
              ['Incident FP Rate', fpStats.inc_fp_rate, fpStats.inc_fp, fpStats.inc_total]].map(([label, rate, fp, total]) => (
              <div key={label} className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-3">
                <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">{label}</p>
                <p className="text-2xl font-bold text-yellow-300">{rate}<span className="text-base text-slate-500">%</span></p>
                <p className="text-xs text-slate-600 mt-1">{fp} of {total} marked FP</p>
                <div className="mt-2 h-1 bg-white/[0.05] rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-gradient-to-r from-yellow-500 to-amber-300" style={{ width: `${Math.min(rate, 100)}%` }} />
                </div>
              </div>
            ))}
          </div>
          {fpStats.top_fp_rules.length > 0 && (
            <div>
              <p className="text-[10px] text-slate-700 uppercase tracking-widest mb-2">Top FP rules</p>
              <div className="space-y-2">
                {fpStats.top_fp_rules.map(r => (
                  <div key={r.rule_name} className="flex items-center gap-3">
                    <code className="text-xs font-mono text-slate-500 w-52 truncate">{r.rule_name}</code>
                    <div className="flex-1 h-1 bg-white/[0.04] rounded-full overflow-hidden">
                      <div className="h-full rounded-full bg-gradient-to-r from-yellow-500/60 to-amber-400/60"
                        style={{ width: `${Math.min((r.fp_count / fpStats.alert_fp) * 100, 100)}%` }} />
                    </div>
                    <span className="text-xs text-slate-500 w-6 text-right tabular-nums">{r.fp_count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Panel>
      )}

      {liveEvents > 0 && (
        <div className="flex items-center gap-3 bg-blue-500/[0.05] border border-blue-500/20 rounded-2xl px-4 py-3 shadow-[0_0_20px_rgba(56,139,253,0.08)]">
          <span className="neon-dot-blue animate-pulse shrink-0" />
          <span className="text-sm text-blue-300 font-semibold">{liveEvents} live event{liveEvents !== 1 ? 's' : ''}</span>
          {liveAlerts > 0 && (
            <span className="flex items-center gap-1.5 text-sm text-red-300 font-semibold">
              <span className="neon-dot-red" />
              {liveAlerts} new alert{liveAlerts !== 1 ? 's' : ''}
            </span>
          )}
          <span className="text-xs text-slate-600 ml-auto">stats auto-updated</span>
        </div>
      )}

      {/* Risk Trend Sparkline */}
      {riskTrend.length > 0 && (
        <Panel title="Risk Score Trend — Last 7 Days">
          <div className="flex items-center gap-6 mb-3">
            <div>
              <p className="text-2xl font-bold text-white">{riskTrend[riskTrend.length - 1]?.avg ?? '—'}</p>
              <p className="text-xs text-slate-500">avg risk score today</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-red-400">{riskTrend[riskTrend.length - 1]?.max ?? '—'}</p>
              <p className="text-xs text-slate-500">peak risk score today</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-orange-400">{riskTrend.reduce((s, d) => s + d.alerts, 0)}</p>
              <p className="text-xs text-slate-500">total alerts (7d)</p>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={110}>
            <AreaChart data={riskTrend} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
              <defs>
                <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f85149" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f85149" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#8b949e' }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: '#8b949e' }} axisLine={false} tickLine={false} width={28} />
              <Tooltip content={<CustomTooltip />} cursor={{ stroke: '#f85149', strokeWidth: 1 }} />
              <Area type="monotone" dataKey="avg" stroke="#f85149" strokeWidth={2} fill="url(#riskGrad)" name="avg risk" dot={{ r: 3, fill: '#f85149' }} />
              <Area type="monotone" dataKey="max" stroke="#ff7b72" strokeWidth={1} fill="none" strokeDasharray="4 2" name="peak risk" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>
      )}

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <Panel title="Top Source IPs">
          {topIps.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={topIps} layout="vertical" margin={{ left: 0, right: 16 }}>
                <XAxis type="number" tick={{ fontSize: 11, fill: '#8b949e' }} axisLine={false} tickLine={false} />
                <YAxis dataKey="source_ip" type="category" tick={{ fontSize: 11, fill: '#8b949e' }} width={100} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                <Bar dataKey="count" fill={BAR_COLOR} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-slate-500 text-sm text-center py-8">No data</p>}
        </Panel>

        <Panel title="Alert Severity">
          {severity.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={severity} dataKey="value" nameKey="name" cx="50%" cy="50%"
                     innerRadius={55} outerRadius={85} paddingAngle={3}>
                  {severity.map((entry) => (
                    <Cell key={entry.name} fill={PIE_COLORS[entry.name] || '#8b949e'} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend formatter={(v) => <span style={{ color: '#8b949e', fontSize: 12 }}>{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          ) : <p className="text-slate-500 text-sm text-center py-8">No alerts yet</p>}
        </Panel>
      </div>

      {/* Attacks by Country */}
      {countryData.length > 0 && (
        <Panel title="Attacks by Country">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={countryData} layout="vertical" margin={{ left: 8, right: 16 }}>
              <XAxis type="number" tick={{ fontSize: 11, fill: '#8b949e' }} axisLine={false} tickLine={false} />
              <YAxis dataKey="country" type="category" tick={{ fontSize: 11, fill: '#8b949e' }} width={130} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="count" name="alerts" fill="#f85149" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      )}

      {/* Live feed */}
      <Panel title="Live Event Feed" className="h-80">
        <LiveFeed onNewEvent={handleNewEvent} onNewAlert={handleNewAlert} />
      </Panel>

      {/* Event type distribution */}
      <Panel title="Event Type Distribution">
        {etypes.length ? (
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={etypes} margin={{ left: 0, right: 16, bottom: 20 }}>
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#8b949e' }} axisLine={false} tickLine={false} angle={-30} textAnchor="end" />
              <YAxis tick={{ fontSize: 11, fill: '#8b949e' }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="value" fill="#7c3aed" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : <p className="text-slate-500 text-sm text-center py-8">No events yet</p>}
      </Panel>

      {/* Timeline charts */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-400 flex items-center gap-2">
          <span className="w-1 h-3.5 rounded-full bg-gradient-to-b from-blue-400 to-blue-600 inline-block" />
          Trend Charts
        </h3>
        <div className="flex items-center gap-1 bg-white/[0.03] border border-white/[0.07] rounded-xl p-1">
          {[7, 30, 90].map(d => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`text-xs px-3 py-1 rounded-lg transition-all ${
                days === d
                  ? 'bg-gradient-to-r from-blue-600 to-blue-500 text-white font-semibold shadow-[0_0_10px_rgba(56,139,253,0.3)]'
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <Panel title={`Incidents — Last ${days} Days`}>
          {incidentTrend.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={incidentTrend} margin={{ left: 0, right: 16, top: 4, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#8b949e' }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#8b949e' }} axisLine={false} tickLine={false} width={28} />
                <Tooltip content={<CustomTooltip />} cursor={{ stroke: '#58a6ff', strokeWidth: 1 }} />
                <Line type="monotone" dataKey="count" stroke="#f85149" strokeWidth={2} dot={{ r: 3, fill: '#f85149' }} name="incidents" />
              </LineChart>
            </ResponsiveContainer>
          ) : <p className="text-slate-500 text-sm text-center py-8">No incidents in the last 30 days</p>}
        </Panel>

        <Panel title={`Alerts by Severity — Last ${days} Days`}>
          {alertTrend.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={alertTrend} margin={{ left: 0, right: 16, top: 4, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                <XAxis dataKey="day" tick={{ fontSize: 10, fill: '#8b949e' }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: '#8b949e' }} axisLine={false} tickLine={false} width={28} />
                <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                <Bar dataKey="critical" stackId="a" fill="#f85149" name="critical" />
                <Bar dataKey="high"     stackId="a" fill="#ff7b72" name="high" />
                <Bar dataKey="medium"   stackId="a" fill="#e3b341" name="medium" />
                <Bar dataKey="low"      stackId="a" fill="#3fb950" name="low" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-slate-500 text-sm text-center py-8">No alerts in the last 30 days</p>}
        </Panel>
      </div>

      {/* Team Activity Metrics */}
      {teamActivity.length > 0 && (
        <Panel title="Team Activity">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left">
                  {['Analyst', 'Incidents Closed', 'Assigned', 'Notes Added', 'SOAR Executed', 'Avg Resolution'].map(h => (
                    <th key={h} className="pb-3 pr-4 text-[10px] font-bold uppercase tracking-widest text-slate-600 whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {teamActivity.map((a, i) => (
                  <tr key={a.username} className="table-row-hover border-t border-white/[0.04]">
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2.5">
                        <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center text-[11px] font-bold text-white shrink-0 shadow-[0_0_8px_rgba(56,139,253,0.3)]">
                          {a.username[0]?.toUpperCase()}
                        </div>
                        <span className="text-slate-200 text-xs font-semibold">{a.username}</span>
                        {i === 0 && <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-yellow-500/10 text-yellow-300 border border-yellow-500/20 font-bold tracking-wide">MVP</span>}
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`text-sm font-bold tabular-nums ${a.incidents_closed > 0 ? 'text-green-300' : 'text-slate-700'}`}>
                        {a.incidents_closed}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-slate-500 text-xs tabular-nums">{a.incidents_assigned}</td>
                    <td className="py-3 pr-4 text-slate-500 text-xs tabular-nums">{a.notes_added}</td>
                    <td className="py-3 pr-4">
                      <span className={`text-xs tabular-nums ${a.soar_executed > 0 ? 'text-yellow-300 font-bold' : 'text-slate-700'}`}>
                        {a.soar_executed > 0 ? `⚡ ${a.soar_executed}` : '—'}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-xs text-slate-500 tabular-nums">
                      {a.avg_resolution_minutes == null ? (
                        <span className="text-slate-700">—</span>
                      ) : a.avg_resolution_minutes < 60 ? (
                        `${Math.round(a.avg_resolution_minutes)}m`
                      ) : (
                        `${(a.avg_resolution_minutes / 60).toFixed(1)}h`
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {/* Recent incidents */}
      <Panel
        title="Recent Incidents"
        action={
          <button onClick={onGoToIncidents}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1">
            View all <span className="opacity-60">→</span>
          </button>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['#', 'Title', 'Source IP', 'User', 'Risk', 'Status', 'Created'].map(h => (
                  <th key={h} className="pb-3 pr-4 text-[10px] font-bold uppercase tracking-widest text-slate-600 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {incidents.length ? incidents.map(i => (
                <tr key={i.id} className="table-row-hover border-t border-white/[0.04]">
                  <td className="py-3 pr-4 text-slate-600 text-xs tabular-nums">#{i.id}</td>
                  <td className="py-3 pr-4 text-slate-200 text-xs font-medium max-w-[200px] truncate">{i.title}</td>
                  <td className="py-3 pr-4 text-slate-500 font-mono text-xs">{i.source_ip || '—'}</td>
                  <td className="py-3 pr-4 text-slate-500 text-xs">{i.username || '—'}</td>
                  <td className="py-3 pr-4"><ScoreBar score={i.risk_score} /></td>
                  <td className="py-3 pr-4"><Badge value={i.status} /></td>
                  <td className="py-3 text-slate-600 text-xs whitespace-nowrap tabular-nums">{fmtTs(i.created_at)}</td>
                </tr>
              )) : (
                <tr><td colSpan={7} className="py-12 text-center text-slate-600 text-sm">
                  No incidents yet
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
