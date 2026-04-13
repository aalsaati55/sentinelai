import { useEffect, useState } from 'react'
import { Mail, Save, Send, CheckCircle, XCircle, Settings as SettingsIcon, Terminal, Wifi, WifiOff, ShieldCheck, ShieldOff, KeyRound, QrCode, Lock, Eye, EyeOff } from 'lucide-react'
import { Panel } from '../components/Panel'
import { api, token } from '../api'

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

  const me = token.user()
  const isAdmin = me?.role === 'admin'

  const [ssh, setSsh]               = useState({ host: '', port: 22, username: '', key_path: '' })
  const [sshSaving, setSshSaving]   = useState(false)
  const [sshTesting, setSshTesting] = useState(false)
  const [sshMsg, setSshMsg]         = useState(null)
  const [sshConfigured, setSshConfigured] = useState(false)

  // Password change state
  const [pwForm, setPwForm]         = useState({ current: '', next: '', confirm: '' })
  const [showPw, setShowPw]         = useState({ current: false, next: false, confirm: false })
  const [pwLoading, setPwLoading]   = useState(false)
  const [pwMsg, setPwMsg]           = useState(null)

  async function handleChangePassword(e) {
    e.preventDefault()
    setPwMsg(null)
    if (pwForm.next !== pwForm.confirm)
      return setPwMsg({ type: 'error', text: 'New passwords do not match' })
    setPwLoading(true)
    try {
      await api.changePassword(pwForm.current, pwForm.next)
      setPwMsg({ type: 'success', text: 'Password changed successfully.' })
      setPwForm({ current: '', next: '', confirm: '' })
    } catch (err) {
      setPwMsg({ type: 'error', text: err.message })
    } finally { setPwLoading(false) }
  }

  // MFA state
  const [mfaEnabled, setMfaEnabled]   = useState(false)
  const [mfaSetupUri, setMfaSetupUri] = useState(null)
  const [mfaSecret, setMfaSecret]     = useState('')
  const [mfaCode, setMfaCode]         = useState('')
  const [mfaLoading, setMfaLoading]   = useState(false)
  const [mfaMsg, setMfaMsg]           = useState(null)
  const [mfaStep, setMfaStep]         = useState('idle') // idle | setup | disable

  useEffect(() => {
    if (isAdmin) {
      apiFetch('/settings/email')
        .then(data => {
          setConfig(c => ({ ...c, ...data, smtp_password: '' }))
          setConfigured(data.configured)
        })
        .catch(() => {})
        .finally(() => setLoading(false))
    } else {
      setLoading(false)
    }

    if (isAdmin) {
      api.sshConfigGet()
        .then(data => {
          setSsh(s => ({ ...s, ...data }))
          setSshConfigured(!!(data.host && data.username))
        })
        .catch(() => {})
    }
    api.mfaStatus().then(d => setMfaEnabled(d.mfa_enabled)).catch(() => {})
  }, [])

  async function handleMfaSetup() {
    setMfaLoading(true); setMfaMsg(null)
    try {
      const d = await api.mfaSetup()
      setMfaSetupUri(d.uri)
      setMfaSecret(d.secret)
      setMfaStep('setup')
    } catch (err) { setMfaMsg({ type: 'error', text: err.message }) }
    finally { setMfaLoading(false) }
  }

  async function handleMfaEnable(e) {
    e.preventDefault()
    setMfaLoading(true); setMfaMsg(null)
    try {
      await api.mfaEnable(mfaCode.trim())
      setMfaEnabled(true); setMfaStep('idle'); setMfaCode(''); setMfaSetupUri(null)
      setMfaMsg({ type: 'success', text: 'MFA enabled! Your account is now protected.' })
    } catch (err) { setMfaMsg({ type: 'error', text: err.message }); setMfaCode('') }
    finally { setMfaLoading(false) }
  }

  async function handleMfaDisable(e) {
    e.preventDefault()
    setMfaLoading(true); setMfaMsg(null)
    try {
      await api.mfaDisable(mfaCode.trim())
      setMfaEnabled(false); setMfaStep('idle'); setMfaCode('')
      setMfaMsg({ type: 'success', text: 'MFA disabled.' })
    } catch (err) { setMfaMsg({ type: 'error', text: err.message }); setMfaCode('') }
    finally { setMfaLoading(false) }
  }

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

  async function handleSshSave(e) {
    e.preventDefault()
    setSshSaving(true)
    setSshMsg(null)
    try {
      await api.sshConfigSave(ssh)
      setSshMsg({ type: 'success', text: 'SSH config saved.' })
      setSshConfigured(!!(ssh.host && ssh.username))
    } catch (err) {
      setSshMsg({ type: 'error', text: err.message })
    } finally { setSshSaving(false) }
  }

  async function handleSshTest() {
    setSshTesting(true)
    setSshMsg(null)
    try {
      const res = await api.sshConfigTest()
      setSshMsg({ type: 'success', text: `Connected! ${res.output ? res.output : 'SSH OK'}` })
    } catch (err) {
      setSshMsg({ type: 'error', text: err.message || 'Connection failed' })
    } finally { setSshTesting(false) }
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
        <p className="text-sm text-slate-500">{isAdmin ? 'Configure email alerts and system preferences' : 'Manage your account security'}</p>
      </div>

      {isAdmin && (
        <Panel title="SOAR Auto-Execute — SSH Config">
          <div className="flex items-center gap-2 mb-5">
            {sshConfigured
              ? <><Wifi size={14} className="text-green-400" /><span className="text-xs text-green-400 font-medium">SSH configured — SOAR auto-execute enabled</span></>
              : <><WifiOff size={14} className="text-slate-600" /><span className="text-xs text-slate-600">Not configured — fill in SSH details to enable auto-execute</span></>
            }
          </div>
          <form onSubmit={handleSshSave} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1.5">Target Host (Ubuntu IP)</label>
                <input type="text" value={ssh.host} onChange={e => setSsh(s => ({ ...s, host: e.target.value }))} placeholder="192.168.56.130"
                  className="w-full bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2.5 outline-none focus:border-blue-500 placeholder-slate-600" />
              </div>
              <div>
                <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1.5">SSH Port</label>
                <input type="number" value={ssh.port} onChange={e => setSsh(s => ({ ...s, port: Number(e.target.value) }))} placeholder="22"
                  className="w-full bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2.5 outline-none focus:border-blue-500 placeholder-slate-600" />
              </div>
              <div>
                <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1.5">Username</label>
                <input type="text" value={ssh.username} onChange={e => setSsh(s => ({ ...s, username: e.target.value }))} placeholder="majeed"
                  className="w-full bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2.5 outline-none focus:border-blue-500 placeholder-slate-600" />
              </div>
              <div>
                <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1.5">SSH Private Key Path (on SIEM server)</label>
                <input type="text" value={ssh.key_path} onChange={e => setSsh(s => ({ ...s, key_path: e.target.value }))} placeholder="~/.ssh/id_rsa (leave blank to use SSH agent)"
                  className="w-full bg-[#1c2128] border border-[#30363d] text-slate-200 text-sm rounded-lg px-3 py-2.5 outline-none focus:border-blue-500 placeholder-slate-600" />
              </div>
            </div>

            {sshMsg && (
              <div className={`flex items-start gap-2 rounded-lg px-4 py-3 text-sm ${
                sshMsg.type === 'success'
                  ? 'bg-green-500/10 border border-green-500/20 text-green-400'
                  : 'bg-red-500/10 border border-red-500/20 text-red-400'
              }`}>
                {sshMsg.type === 'success' ? <CheckCircle size={14} className="mt-0.5 shrink-0" /> : <XCircle size={14} className="mt-0.5 shrink-0" />}
                <span className="break-all">{sshMsg.text}</span>
              </div>
            )}

            <div className="flex gap-3 pt-2">
              <button type="submit" disabled={sshSaving}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-semibold px-5 py-2.5 rounded-lg transition-colors">
                <Save size={14} />{sshSaving ? 'Saving…' : 'Save SSH Config'}
              </button>
              <button type="button" onClick={handleSshTest} disabled={sshTesting || !sshConfigured}
                className="flex items-center gap-2 bg-[#1c2128] border border-[#30363d] hover:border-green-500 disabled:opacity-40 text-slate-300 text-sm font-semibold px-5 py-2.5 rounded-lg transition-colors">
                <Terminal size={14} />{sshTesting ? 'Testing…' : 'Test Connection'}
              </button>
            </div>
          </form>
          <div className="mt-5 border-t border-[#30363d] pt-4">
            <p className="text-xs text-slate-600 mb-2">Setup passwordless SSH from the SIEM server to Ubuntu:</p>
            <ol className="text-xs text-slate-600 space-y-1 list-decimal list-inside">
              <li>On Windows SIEM: <code className="text-slate-400">ssh-keygen -t rsa -b 4096</code></li>
              <li>Copy key to Ubuntu: <code className="text-slate-400">ssh-copy-id majeed@192.168.56.130</code></li>
              <li>Set key path above to <code className="text-slate-400">~/.ssh/id_rsa</code> (or full Windows path)</li>
              <li>Click Test Connection to verify</li>
            </ol>
          </div>
        </Panel>
      )}

      {/* Password Change Panel — available to all users */}
      <Panel title="Change Password">
        <form onSubmit={handleChangePassword} className="space-y-4 max-w-md">
          {(['current', 'next', 'confirm']).map(field => {
            const labels = { current: 'Current Password', next: 'New Password', confirm: 'Confirm New Password' }
            return (
              <div key={field}>
                <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1.5">{labels[field]}</label>
                <div className="relative">
                  <input
                    type={showPw[field] ? 'text' : 'password'}
                    value={pwForm[field]}
                    onChange={e => setPwForm(f => ({ ...f, [field]: e.target.value }))}
                    required
                    placeholder="••••••••"
                    className="w-full bg-[#1c2128] border border-[#30363d] focus:border-blue-500 text-slate-200 placeholder:text-slate-600 text-sm rounded-lg px-3 py-2.5 pr-10 outline-none transition-colors"
                  />
                  <button type="button" onClick={() => setShowPw(s => ({ ...s, [field]: !s[field] }))}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors">
                    {showPw[field] ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>
            )
          })}

          {pwMsg && (
            <div className={`flex items-center gap-2 rounded-lg px-4 py-3 text-sm ${
              pwMsg.type === 'success'
                ? 'bg-green-500/10 border border-green-500/20 text-green-400'
                : 'bg-red-500/10 border border-red-500/20 text-red-400'
            }`}>
              {pwMsg.type === 'success' ? <CheckCircle size={14} /> : <XCircle size={14} />}
              {pwMsg.text}
            </div>
          )}

          <button type="submit" disabled={pwLoading || !pwForm.current || !pwForm.next || !pwForm.confirm}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-semibold px-5 py-2.5 rounded-lg transition-colors">
            <Lock size={14} />{pwLoading ? 'Saving…' : 'Change Password'}
          </button>
        </form>
      </Panel>

      {/* MFA Panel — available to all users */}
      <Panel title="Two-Factor Authentication (MFA)">
        <div className="flex items-center gap-2 mb-5">
          {mfaEnabled
            ? <><ShieldCheck size={14} className="text-green-400" /><span className="text-xs text-green-400 font-medium">MFA is enabled — your account is protected with TOTP</span></>
            : <><ShieldOff size={14} className="text-slate-600" /><span className="text-xs text-slate-500">MFA is disabled — enable it for extra login security</span></>
          }
        </div>

        {mfaMsg && (
          <div className={`flex items-center gap-2 rounded-lg px-4 py-3 text-sm mb-4 ${
            mfaMsg.type === 'success'
              ? 'bg-green-500/10 border border-green-500/20 text-green-400'
              : 'bg-red-500/10 border border-red-500/20 text-red-400'
          }`}>
            {mfaMsg.type === 'success' ? <CheckCircle size={14} /> : <XCircle size={14} />}
            {mfaMsg.text}
          </div>
        )}

        {/* Idle state */}
        {mfaStep === 'idle' && (
          <div className="flex gap-3">
            {!mfaEnabled && (
              <button onClick={handleMfaSetup} disabled={mfaLoading}
                className="flex items-center gap-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-sm font-semibold px-5 py-2.5 rounded-lg transition-colors">
                <QrCode size={14} />{mfaLoading ? 'Generating…' : 'Set Up MFA'}
              </button>
            )}
            {mfaEnabled && (
              <button onClick={() => { setMfaStep('disable'); setMfaMsg(null) }}
                className="flex items-center gap-2 bg-red-600/20 hover:bg-red-600/30 border border-red-500/30 text-red-400 text-sm font-semibold px-5 py-2.5 rounded-lg transition-colors">
                <ShieldOff size={14} />Disable MFA
              </button>
            )}
          </div>
        )}

        {/* Setup step — show QR code */}
        {mfaStep === 'setup' && mfaSetupUri && (
          <div className="space-y-4">
            <div className="bg-[#1c2128] border border-[#30363d] rounded-xl p-5">
              <p className="text-sm text-slate-300 font-semibold mb-1">1. Scan this QR code with your authenticator app</p>
              <p className="text-xs text-slate-500 mb-4">Use <span className="text-slate-400">Google Authenticator</span>, <span className="text-slate-400">Authy</span>, or any TOTP app</p>
              <div className="flex justify-center mb-4">
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(mfaSetupUri)}&bgcolor=1c2128&color=e2e8f0&margin=2`}
                  alt="MFA QR Code"
                  className="rounded-lg border border-[#30363d]"
                  width={180} height={180}
                />
              </div>
              <p className="text-xs text-slate-500 text-center">Can't scan? Manual key: <code className="text-purple-400 font-mono text-xs break-all">{mfaSecret}</code></p>
            </div>

            <form onSubmit={handleMfaEnable} className="space-y-3">
              <p className="text-sm text-slate-300 font-semibold">2. Enter the 6-digit code from your app to activate MFA</p>
              <div className="flex gap-3 items-center">
                <input
                  type="text" inputMode="numeric" pattern="[0-9]*" maxLength={6}
                  value={mfaCode} onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="000000" autoComplete="one-time-code"
                  className="w-40 bg-[#1c2128] border border-[#30363d] focus:border-purple-500 text-slate-200 placeholder:text-slate-600 text-xl text-center font-mono tracking-[0.4em] rounded-lg px-3 py-3 outline-none transition-colors"
                />
                <button type="submit" disabled={mfaLoading || mfaCode.length !== 6}
                  className="flex items-center gap-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-sm font-semibold px-5 py-3 rounded-lg transition-colors">
                  <KeyRound size={14} />{mfaLoading ? 'Verifying…' : 'Activate MFA'}
                </button>
                <button type="button" onClick={() => { setMfaStep('idle'); setMfaCode(''); setMfaSetupUri(null) }}
                  className="text-sm text-slate-500 hover:text-slate-300 transition-colors">Cancel</button>
              </div>
            </form>
          </div>
        )}

        {/* Disable step */}
        {mfaStep === 'disable' && (
          <form onSubmit={handleMfaDisable} className="space-y-3">
            <p className="text-sm text-slate-300">Enter your current authenticator code to disable MFA</p>
            <div className="flex gap-3 items-center">
              <input
                type="text" inputMode="numeric" pattern="[0-9]*" maxLength={6}
                value={mfaCode} onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000" autoFocus
                className="w-40 bg-[#1c2128] border border-[#30363d] focus:border-red-500 text-slate-200 placeholder:text-slate-600 text-xl text-center font-mono tracking-[0.4em] rounded-lg px-3 py-3 outline-none transition-colors"
              />
              <button type="submit" disabled={mfaLoading || mfaCode.length !== 6}
                className="flex items-center gap-2 bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white text-sm font-semibold px-5 py-3 rounded-lg transition-colors">
                <ShieldOff size={14} />{mfaLoading ? 'Disabling…' : 'Confirm Disable'}
              </button>
              <button type="button" onClick={() => { setMfaStep('idle'); setMfaCode('') }}
                className="text-sm text-slate-500 hover:text-slate-300 transition-colors">Cancel</button>
            </div>
          </form>
        )}
      </Panel>

      {isAdmin && (
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
      )}
    </div>
  )
}
