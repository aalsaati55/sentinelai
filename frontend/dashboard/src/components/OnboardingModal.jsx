import { useState } from 'react'
import {
  X, LayoutDashboard, ShieldAlert, Bell, Radio,
  Map, List, ClipboardList, Users, Settings, ChevronRight, ChevronLeft, Zap, Globe
} from 'lucide-react'

const PAGES = [
  {
    icon: LayoutDashboard,
    color: 'text-blue-400',
    bg: 'bg-blue-500/10 border-blue-500/20',
    title: 'Overview',
    description: 'Your SOC command centre. See live event/alert counts, risk trend sparkline, MTTD/MTTR metrics, and the Team Activity leaderboard — all auto-refreshing every 30 seconds.',
    tips: ['Watch the Live Event Feed in real time as Kali attacks Ubuntu', 'MTTD shows how fast threats are detected; MTTR shows how fast they\'re resolved', 'Team Activity tracks each analyst\'s incidents closed, notes, and SOAR actions'],
  },
  {
    icon: ShieldAlert,
    color: 'text-red-400',
    bg: 'bg-red-500/10 border-red-500/20',
    title: 'Incidents',
    description: 'Correlated attack incidents grouped by source IP and attack type. Each incident has a full modal with Playbook, SOAR Commands, Threat Intelligence, and Investigation Notes.',
    tips: ['Open an incident → SOAR tab to get ready-to-run remediation commands', 'The Threat Intel panel shows AbuseIPDB reputation data for the attacker IP', 'Add notes to document your investigation — they\'re timestamped and audited'],
  },
  {
    icon: Bell,
    color: 'text-yellow-400',
    bg: 'bg-yellow-500/10 border-yellow-500/20',
    title: 'Alerts',
    description: 'Every individual detection rule firing is shown here. Filter by severity, rule name, or search free-text. MITRE ATT&CK technique badges link to the official MITRE site.',
    tips: ['Use the Rule filter to see only brute_force_ssh or port_scan alerts', 'Suppress noisy rules as admin to reduce false positives', 'Known Threat badges (red) appear next to IPs confirmed by AbuseIPDB'],
  },
  {
    icon: Radio,
    color: 'text-green-400',
    bg: 'bg-green-500/10 border-green-500/20',
    title: 'Events',
    description: 'Raw parsed and normalised log events from auth.log, syslog, and custom logs. Filter by source, event type, or source IP to drill into exactly what happened.',
    tips: ['Filter by "login_failure" to see all failed SSH attempts', 'The Type dropdown shows every event type actually in your database', 'Use IP filter to trace all activity from a specific attacker'],
  },
  {
    icon: Map,
    color: 'text-purple-400',
    bg: 'bg-purple-500/10 border-purple-500/20',
    title: 'Attack Map',
    description: 'Live SVG world map showing attacker source IPs as colour-coded dots. Red = Critical, Orange = High, Yellow = Medium, Green = Low. Private LAN IPs show a home icon.',
    tips: ['Each dot on the map is a distinct attacker IP', 'The table below the map shows country, city, and alert counts', 'Great for demonstrating geographic threat distribution'],
  },
  {
    icon: List,
    color: 'text-orange-400',
    bg: 'bg-orange-500/10 border-orange-500/20',
    title: 'Watchlist',
    description: 'Tracked attacker IPs with reasons. IPs are auto-added when they trigger Critical alerts or score ≥75% on AbuseIPDB. Admins can manually add or remove IPs.',
    tips: ['A 🚫 badge appears next to watchlisted IPs across all pages', 'Manual removals are remembered — threat intel won\'t re-add them', 'New live attacks from a removed IP will re-trigger watchlisting'],
  },
  {
    icon: ClipboardList,
    color: 'text-cyan-400',
    bg: 'bg-cyan-500/10 border-cyan-500/20',
    title: 'Audit Log',
    description: 'Complete record of every action taken in the SIEM — status changes, assignments, notes, watchlist edits, and SOAR commands executed. Filter by action type, export to CSV.',
    tips: ['Filter by "SOAR Executed" to see which commands analysts ran', 'Every action is timestamped with the username who did it', 'Export to CSV for compliance reporting'],
  },
  {
    icon: Zap,
    color: 'text-indigo-400',
    bg: 'bg-indigo-500/10 border-indigo-500/20',
    title: 'SOAR Commands',
    description: 'Inside each incident modal, the SOAR section gives you ready-to-run Ubuntu shell commands tailored to the attack type — with the real attacker IP already filled in.',
    tips: ['Click Copy to copy a single command, or Copy All for the full block', 'Click ✓ Executed to mark a command as done — it logs to the Audit Log', 'After blocking an IP with UFW, undo with: sudo ufw delete deny from <IP>'],
  },
]

export function OnboardingModal({ onClose }) {
  const [step, setStep] = useState(0)
  const page = PAGES[step]
  const Icon = page.icon
  const isLast = step === PAGES.length - 1

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#161b22] border border-[#30363d] rounded-2xl w-full max-w-lg shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-[#30363d]">
          <div>
            <h2 className="text-white font-bold text-base">Welcome to SentinelAI</h2>
            <p className="text-xs text-slate-500 mt-0.5">A quick tour of the platform</p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
            <X size={18} />
          </button>
        </div>

        {/* Step indicator */}
        <div className="flex items-center gap-1.5 px-6 pt-4">
          {PAGES.map((_, i) => (
            <button
              key={i}
              onClick={() => setStep(i)}
              className={`h-1.5 rounded-full transition-all ${i === step ? 'w-6 bg-blue-400' : 'w-1.5 bg-[#30363d] hover:bg-slate-500'}`}
            />
          ))}
          <span className="ml-auto text-xs text-slate-600">{step + 1} / {PAGES.length}</span>
        </div>

        {/* Content */}
        <div className="px-6 py-5 flex-1">
          <div className={`inline-flex items-center justify-center w-12 h-12 rounded-xl border ${page.bg} mb-4`}>
            <Icon size={22} className={page.color} />
          </div>
          <h3 className="text-white font-bold text-lg mb-2">{page.title}</h3>
          <p className="text-slate-400 text-sm leading-relaxed mb-4">{page.description}</p>
          <ul className="space-y-2">
            {page.tips.map((tip, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-slate-500">
                <span className="text-blue-500 mt-0.5 shrink-0">›</span>
                {tip}
              </li>
            ))}
          </ul>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-[#30363d]">
          <button
            onClick={() => setStep(s => s - 1)}
            disabled={step === 0}
            className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft size={15} /> Back
          </button>
          {isLast ? (
            <button
              onClick={onClose}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold px-5 py-2 rounded-lg transition-colors"
            >
              Get started
            </button>
          ) : (
            <button
              onClick={() => setStep(s => s + 1)}
              className="flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300 transition-colors font-medium"
            >
              Next <ChevronRight size={15} />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
