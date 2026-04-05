import { useEffect, useState } from 'react'
import { Mail, Save, Send, CheckCircle, XCircle, Settings as SettingsIcon } from 'lucide-react'
import { Panel } from '../components/Panel'

const BASE = '/api'

function authHeaders() {
  const t = localStorage.getItem('sentinel_token')
  return t ? { Authorization: `Bearer ${t}` } : {}
}

async function apiFetch(path, options = {}) {
  const r = await fetch(BASE + path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...options.headers },
  })
  if (!r.ok) {
    const e = await r.json().catch(() => ({}))
    throw new Error(e.detail || `${r.status} ${r.statusText}`)
  }
  if (r.status === 204) return null
  return r.json()
}

export function Settings() {
  const [config, setConfig] = useState({
    smtp_host: '', smtp_port: 587, smtp_user: '',
    smtp_password: '', alert_email: '', enabled: true,
  })
  const [loading, setLoading]   = useState(true)
  const [saving, setSaving]     = useState(false)
  const [testing, setTesting]   = useState(false)
  const [msg, setMsg]           = useState(null)   // { type: 'success'|'error', text }
  const [configured, setConfigured] = useState(false)

  useEffect(() => {
    apiFetch('/settings/email')
      .then(data => {
        setConfig(c => ({ ...c, ...data, smtp_password: '' }))
        setConfigured(data.configured)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    setMsg(null)
    try {
      await apiFetch('/settings/email', {
        method: 'POST',
        body: JSON.stringify(config),
      })
      setMsg({ type: 'success', text: 'Email settings saved successfully.' })
      setConfigured(true)
    } catch (err) {
      setMsg({ type: 'error', text: err.message })
    } finally { setSaving(false) }
  }

  async function handleTest() {
    setTesting(true)
    setMsg(null)
    try {
      await apiFetch('/settings/email/test', { method: 'POST' })
      setMsg({ type: 'success', text: 'Test email sent! Check your inbox.' })
    } catch (err) {
      setMsg({ type: 'error', text: err.message })
    } finally { setTesting(false) }
  }

  function field(label, key, type = 'text', placeholder = '') {
    return (
      <div key={key}>
        <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1.5">{label}</label>
        <input
          type={type}
          value={config[key]}
          onChange={e => setConfig(c => ({ ...c, [key]: type === 'number' ? Number(e.target.value) : e.target.value }))}
          placeholder={placeholder}
          className="w-full bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2.5 outline-none focus:border-blue-500 placeholder-slate-600"
        />
      </div>
    )
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-slate-500">
      <SettingsIcon size={24} className="animate-spin mr-2" /> Loading…
    </div>
  )

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white mb-1">Settings</h2>
        <p className="text-sm text-slate-500">Configure email alerts and system preferences — admin only</p>
      </div>

      <Panel title="Email Alert Settings">
        <div className="flex items-center gap-2 mb-5">
          <Mail size={14} className={configured ? 'text-green-400' : 'text-slate-600'} />
          <span className="text-xs text-slate-500">
            {configured
              ? <span className="text-green-400 font-medium">Email configured — alerts active for Critical & High incidents</span>
              : <span className="text-slate-600">Not configured — fill in SMTP details below</span>
            }
          </span>
        </div>

        <form onSubmit={handleSave} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {field('SMTP Host', 'smtp_host', 'text', 'smtp.gmail.com')}
            {field('SMTP Port', 'smtp_port', 'number', '587')}
            {field('Sender Email (SMTP User)', 'smtp_user', 'email', 'alerts@example.com')}
            {field('App Password', 'smtp_password', 'password', '••••••••••••')}
            {field('Alert Recipient Email(s)', 'alert_email', 'text', 'soc@example.com, admin@example.com')}
          </div>

          {/* Enable toggle */}
          <div className="flex items-center gap-3 pt-1">
            <button
              type="button"
              onClick={() => setConfig(c => ({ ...c, enabled: !c.enabled }))}
              className={`relative w-10 h-5 rounded-full transition-colors ${config.enabled ? 'bg-blue-600' : 'bg-slate-700'}`}
            >
              <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${config.enabled ? 'translate-x-5' : 'translate-x-0.5'}`} />
            </button>
            <span className="text-sm text-slate-400">
              {config.enabled ? 'Email alerts enabled' : 'Email alerts disabled'}
            </span>
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

          <div className="flex gap-3 pt-2">
            <button
              type="submit"
              disabled={saving}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-semibold px-5 py-2.5 rounded-lg transition-colors"
            >
              <Save size={14} />
              {saving ? 'Saving…' : 'Save Settings'}
            </button>
            <button
              type="button"
              onClick={handleTest}
              disabled={testing || !configured}
              className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-blue-500 disabled:opacity-40 text-slate-300 text-sm font-semibold px-5 py-2.5 rounded-lg transition-colors"
            >
              <Send size={14} />
              {testing ? 'Sending…' : 'Send Test Email'}
            </button>
          </div>
        </form>

        <div className="mt-6 border-t border-[#30363d] pt-4">
          <p className="text-xs text-slate-600 mb-2">Using Gmail? You need an <span className="text-slate-500">App Password</span> (not your regular password):</p>
          <ol className="text-xs text-slate-600 space-y-1 list-decimal list-inside">
            <li>Go to Google Account → Security → 2-Step Verification → App passwords</li>
            <li>Create an app password for "Mail"</li>
            <li>Use that 16-character password above, not your Gmail password</li>
          </ol>
        </div>
      </Panel>
    </div>
  )
}
