import { useEffect, useState, useCallback, useRef } from 'react'
import { Activity, AlertTriangle, Bell, Globe, Radio, ShieldAlert, TrendingUp, Zap, RefreshCw } from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  LineChart, Line, CartesianGrid,
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
  const [days, setDays]                     = useState(30)
  const [lastRefresh, setLastRefresh]       = useState(null)
  const [refreshing, setRefreshing]         = useState(false)
  const intervalRef                         = useRef(null)

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
    ]).then(([s, ips, sev, et, inc, itl, atl]) => {
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
      setLoading(false)
      setLastRefresh(new Date())
    }).catch(() => setLoading(false))
  }, [days])

  // Auto-refresh summary every 30 seconds
  useEffect(() => {
    intervalRef.current = setInterval(() => refreshSummary(true), 30000)
    return () => clearInterval(intervalRef.current)
  }, [refreshSummary])

  function handleNewEvent() {
    setLiveEvents(c => c + 1)
    refreshSummary()
  }

  function handleNewAlert() {
    setLiveAlerts(c => c + 1)
    refreshSummary()
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-slate-500">
      <Activity size={24} className="animate-spin mr-2" /> Loading…
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-xl font-bold text-white mb-1">SOC Overview</h2>
          <p className="text-sm text-slate-500">Real-time security posture dashboard</p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-xs text-slate-600">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={() => refreshSummary(false)}
            disabled={refreshing}
            className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 text-slate-400 hover:text-slate-200 text-xs px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
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

      {liveEvents > 0 && (
        <div className="flex items-center gap-3 bg-blue-500/5 border border-blue-500/20 rounded-lg px-4 py-2.5 text-sm">
          <Radio size={13} className="text-blue-400 shrink-0" />
          <span className="text-blue-300 font-medium">{liveEvents} live event{liveEvents !== 1 ? 's' : ''}</span>
          {liveAlerts > 0 && (
            <span className="text-red-400 font-medium">· {liveAlerts} new alert{liveAlerts !== 1 ? 's' : ''} detected</span>
          )}
          <span className="text-slate-500">— stats auto-updated</span>
        </div>
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
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-sm font-semibold text-slate-400">Trend Charts</h3>
        <div className="flex items-center gap-1 bg-[#1c2128] border border-[#30363d] rounded-lg p-1">
          {[7, 30, 90].map(d => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`text-xs px-3 py-1 rounded-md transition-colors ${
                days === d
                  ? 'bg-blue-600 text-white font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
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

      {/* Recent incidents */}
      <Panel
        title="Recent Incidents"
        action={
          <button onClick={onGoToIncidents}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
            View all →
          </button>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left">
                {['#', 'Title', 'Source IP', 'User', 'Risk', 'Status', 'Created'].map(h => (
                  <th key={h} className="pb-3 pr-4 text-xs font-semibold uppercase tracking-wider text-slate-500 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {incidents.length ? incidents.map(i => (
                <tr key={i.id} className="border-t border-[#30363d] hover:bg-white/[0.02] transition-colors">
                  <td className="py-2.5 pr-4 text-slate-500 text-xs">{i.id}</td>
                  <td className="py-2.5 pr-4 text-slate-200 max-w-[200px] truncate">{i.title}</td>
                  <td className="py-2.5 pr-4 text-slate-400 font-mono text-xs">{i.source_ip || '—'}</td>
                  <td className="py-2.5 pr-4 text-slate-400">{i.username || '—'}</td>
                  <td className="py-2.5 pr-4"><ScoreBar score={i.risk_score} /></td>
                  <td className="py-2.5 pr-4"><Badge value={i.status} /></td>
                  <td className="py-2.5 text-slate-500 text-xs whitespace-nowrap">{fmtTs(i.created_at)}</td>
                </tr>
              )) : (
                <tr><td colSpan={7} className="py-10 text-center text-slate-500 text-sm">
                  No incidents yet — run the pipeline first.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
