import { useEffect, useState } from 'react'
import { Mail, Save, Send, CheckCircle, XCircle, Settings as SettingsIcon, Terminal, Wifi, WifiOff, ShieldCheck, ShieldOff, KeyRound, QrCode, Lock, Eye, EyeOff, Calendar, PlayCircle } from 'lucide-react'
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

  const [report, setReport]             = useState({ enabled: false, period: 'daily', time: '08:00', day: 0 })
  const [reportSaving, setReportSaving]   = useState(false)
  const [reportSending, setReportSending] = useState(false)
  const [reportMsg, setReportMsg]         = useState(null)

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
    if (isAdmin) {
      api.reportConfigGet().then(data => setReport(data)).catch(() => {})
    }
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

  async function handleReportSave(e) {
    e.preventDefault()
    setReportSaving(true); setReportMsg(null)
    try {
      await api.reportConfigSave(report)
      setReportMsg({ type: 'success', text: 'Report schedule saved.' })
    } catch (err) {
      setReportMsg({ type: 'error', text: err.message })
    } finally { setReportSaving(false) }
  }

  async function handleReportSendNow() {
    setReportSending(true); setReportMsg(null)
    try {
      const res = await api.reportSendNow()
      setReportMsg({ type: 'success', text: res.message || 'Report sent!' })
    } catch (err) {
      setReportMsg({ type: 'error', text: err.message })
    } finally { setReportSending(false) }
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

  const inputCls = "w-full bg-white/[0.04] border border-white/[0.08] focus:border-blue-500/60 focus:shadow-[0_0_0_3px_rgba(56,139,253,0.1)] text-slate-200 placeholder:text-slate-600 text-sm rounded-xl px-3 py-2.5 outline-none transition-all"
  const labelCls = "block text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-1.5"
  const flashCls = (type) => `flex items-center gap-2 rounded-xl px-4 py-3 text-xs font-medium ${
    type === 'success' ? 'bg-green-500/8 border border-green-500/20 text-green-400' : 'bg-red-500/8 border border-red-500/20 text-red-400'
  }`
  const actionBtnCls = "flex items-center gap-2 text-white text-xs font-bold px-5 py-2.5 rounded-xl transition-all disabled:opacity-40"
  const ghostBtnCls = "btn-ghost flex items-center gap-2 text-xs font-semibold px-5 py-2.5 rounded-xl"

  function field(label, key, type = 'text', placeholder = '') {
    return (
      <div key={key}>
        <label className={labelCls}>{label}</label>
        <input
          type={type}
          value={config[key]}
          onChange={e => setConfig(c => ({ ...c, [key]: type === 'number' ? Number(e.target.value) : e.target.value }))}
          placeholder={placeholder}
          className={inputCls}
        />
      </div>
    )
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64 text-slate-600">
      <SettingsIcon size={18} className="animate-spin mr-2" /> Loading…
    </div>
  )

  return (
    <div className="space-y-6">
      <div>
        <h2 className="page-title">Settings</h2>
        <p className="page-sub">{isAdmin ? 'Configure email alerts and system preferences' : 'Manage your account security'}</p>
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
                <label className={labelCls}>Target Host (Ubuntu IP)</label>
                <input type="text" value={ssh.host} onChange={e => setSsh(s => ({ ...s, host: e.target.value }))} placeholder="192.168.56.130" className={inputCls} />
              </div>
              <div>
                <label className={labelCls}>SSH Port</label>
                <input type="number" value={ssh.port} onChange={e => setSsh(s => ({ ...s, port: Number(e.target.value) }))} placeholder="22" className={inputCls} />
              </div>
              <div>
                <label className={labelCls}>Username</label>
                <input type="text" value={ssh.username} onChange={e => setSsh(s => ({ ...s, username: e.target.value }))} placeholder="majeed" className={inputCls} />
              </div>
              <div>
                <label className={labelCls}>SSH Private Key Path (on SIEM server)</label>
                <input type="text" value={ssh.key_path} onChange={e => setSsh(s => ({ ...s, key_path: e.target.value }))} placeholder="~/.ssh/id_rsa" className={inputCls} />
              </div>
            </div>

            {sshMsg && (
              <div className={flashCls(sshMsg.type)}>
                {sshMsg.type === 'success' ? <CheckCircle size={13} className="shrink-0" /> : <XCircle size={13} className="shrink-0" />}
                <span className="break-all">{sshMsg.text}</span>
              </div>
            )}

            <div className="flex gap-3 pt-2">
              <button type="submit" disabled={sshSaving} className={actionBtnCls}
                style={{ background: 'linear-gradient(135deg,#1a6bcc,#388bfd)', boxShadow: '0 4px 14px rgba(56,139,253,0.25)' }}>
                <Save size={13} />{sshSaving ? 'Saving…' : 'Save SSH Config'}
              </button>
              <button type="button" onClick={handleSshTest} disabled={sshTesting || !sshConfigured} className={ghostBtnCls}>
                <Terminal size={13} />{sshTesting ? 'Testing…' : 'Test Connection'}
              </button>
            </div>
          </form>
          <div className="mt-5 border-t border-white/[0.06] pt-4">
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
          {(['current', 'next', 'confirm']).map(f => {
            const labels = { current: 'Current Password', next: 'New Password', confirm: 'Confirm New Password' }
            return (
              <div key={f}>
                <label className={labelCls}>{labels[f]}</label>
                <div className="relative">
                  <input
                    type={showPw[f] ? 'text' : 'password'}
                    value={pwForm[f]}
                    onChange={e => setPwForm(p => ({ ...p, [f]: e.target.value }))}
                    required placeholder="••••••••"
                    className={`${inputCls} pr-10`}
                  />
                  <button type="button" onClick={() => setShowPw(s => ({ ...s, [f]: !s[f] }))}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400 transition-colors">
                    {showPw[f] ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>
            )
          })}

          {pwMsg && (
            <div className={flashCls(pwMsg.type)}>
              {pwMsg.type === 'success' ? <CheckCircle size={13} /> : <XCircle size={13} />}
              {pwMsg.text}
            </div>
          )}

          <button type="submit" disabled={pwLoading || !pwForm.current || !pwForm.next || !pwForm.confirm}
            className={actionBtnCls} style={{ background: 'linear-gradient(135deg,#1a6bcc,#388bfd)', boxShadow: '0 4px 14px rgba(56,139,253,0.25)' }}>
            <Lock size={13} />{pwLoading ? 'Saving…' : 'Change Password'}
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
          <div className={`${flashCls(mfaMsg.type)} mb-4`}>
            {mfaMsg.type === 'success' ? <CheckCircle size={13} /> : <XCircle size={13} />}
            {mfaMsg.text}
          </div>
        )}

        {/* Idle state */}
        {mfaStep === 'idle' && (
          <div className="flex gap-3">
            {!mfaEnabled && (
              <button onClick={handleMfaSetup} disabled={mfaLoading} className={actionBtnCls}
                style={{ background: 'linear-gradient(135deg,#7c3aed,#a371f7)', boxShadow: '0 4px 14px rgba(163,113,247,0.25)' }}>
                <QrCode size={13} />{mfaLoading ? 'Generating…' : 'Set Up MFA'}
              </button>
            )}
            {mfaEnabled && (
              <button onClick={() => { setMfaStep('disable'); setMfaMsg(null) }}
                className="btn-danger flex items-center gap-2 text-xs font-semibold px-5 py-2.5 rounded-xl">
                <ShieldOff size={13} />Disable MFA
              </button>
            )}
          </div>
        )}

        {/* Setup step — show QR code */}
        {mfaStep === 'setup' && mfaSetupUri && (
          <div className="space-y-4">
            <div className="rounded-xl p-5" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
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
                  className="w-40 bg-white/[0.04] border border-white/[0.08] focus:border-purple-500/60 text-slate-200 placeholder:text-slate-600 text-xl text-center font-mono tracking-[0.4em] rounded-xl px-3 py-3 outline-none transition-all"
                />
                <button type="submit" disabled={mfaLoading || mfaCode.length !== 6} className={actionBtnCls}
                  style={{ background: 'linear-gradient(135deg,#7c3aed,#a371f7)', boxShadow: '0 4px 14px rgba(163,113,247,0.25)' }}>
                  <KeyRound size={13} />{mfaLoading ? 'Verifying…' : 'Activate MFA'}
                </button>
                <button type="button" onClick={() => { setMfaStep('idle'); setMfaCode(''); setMfaSetupUri(null) }}
                  className="text-xs text-slate-600 hover:text-slate-400 transition-colors">Cancel</button>
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
                className="w-40 bg-white/[0.04] border border-white/[0.08] focus:border-red-500/60 text-slate-200 placeholder:text-slate-600 text-xl text-center font-mono tracking-[0.4em] rounded-xl px-3 py-3 outline-none transition-all"
              />
              <button type="submit" disabled={mfaLoading || mfaCode.length !== 6}
                className="btn-danger flex items-center gap-2 text-xs font-bold px-5 py-3 rounded-xl disabled:opacity-40">
                <ShieldOff size={13} />{mfaLoading ? 'Disabling…' : 'Confirm Disable'}
              </button>
              <button type="button" onClick={() => { setMfaStep('idle'); setMfaCode('') }}
                className="text-xs text-slate-600 hover:text-slate-400 transition-colors">Cancel</button>
            </div>
          </form>
        )}
      </Panel>

      {isAdmin && (
        <Panel title="Scheduled Reports">
          <div className="flex items-center gap-2 mb-5">
            <Calendar size={14} className={report.enabled ? 'text-green-400' : 'text-slate-600'} />
            <span className="text-xs">
              {report.enabled
                ? <span className="text-green-400 font-medium">
                    Active — {report.period === 'daily' ? 'Daily' : `Weekly (${['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][report.day]})`} at {report.time} UTC
                  </span>
                : <span className="text-slate-600">Disabled — configure below to auto-email reports</span>
              }
            </span>
          </div>

          <form onSubmit={handleReportSave} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className={labelCls}>Frequency</label>
                <select value={report.period} onChange={e => setReport(r => ({ ...r, period: e.target.value }))} className="ctrl-select w-full">
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                </select>
              </div>
              <div>
                <label className={labelCls}>Send Time (UTC)</label>
                <input type="time" value={report.time} onChange={e => setReport(r => ({ ...r, time: e.target.value }))} className={inputCls} />
              </div>
              {report.period === 'weekly' && (
                <div>
                  <label className={labelCls}>Day of Week</label>
                  <select value={report.day} onChange={e => setReport(r => ({ ...r, day: Number(e.target.value) }))} className="ctrl-select w-full">
                    {['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'].map((d, i) => (
                      <option key={i} value={i}>{d}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div className="flex items-center gap-3">
              <button type="button" onClick={() => setReport(r => ({ ...r, enabled: !r.enabled }))}
                className={`relative w-10 h-5 rounded-full transition-colors ${report.enabled ? 'bg-green-600' : 'bg-slate-700'}`}>
                <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${report.enabled ? 'translate-x-5' : 'translate-x-0.5'}`} />
              </button>
              <span className="text-sm text-slate-400">{report.enabled ? 'Scheduled reports enabled' : 'Scheduled reports disabled'}</span>
            </div>

            {reportMsg && <div className={flashCls(reportMsg.type)}>{reportMsg.type === 'success' ? <CheckCircle size={13} /> : <XCircle size={13} />}{reportMsg.text}</div>}

            <div className="flex gap-3 pt-2">
              <button type="submit" disabled={reportSaving} className={actionBtnCls}
                style={{ background: 'linear-gradient(135deg,#1a6bcc,#388bfd)', boxShadow: '0 4px 14px rgba(56,139,253,0.25)' }}>
                <Save size={13} />{reportSaving ? 'Saving…' : 'Save Schedule'}
              </button>
              <button type="button" onClick={handleReportSendNow} disabled={reportSending} className={ghostBtnCls}>
                <PlayCircle size={13} />{reportSending ? 'Sending…' : 'Send Now'}
              </button>
            </div>
          </form>

          <div className="mt-5 border-t border-white/[0.06] pt-4">
            <p className="text-xs text-slate-600">The report includes: total alerts by severity, new incidents, top attacking IPs, and team activity for the report period. Requires SMTP to be configured above.</p>
          </div>
        </Panel>
      )}

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

            {msg && <div className={flashCls(msg.type)}>{msg.type === 'success' ? <CheckCircle size={13} /> : <XCircle size={13} />}{msg.text}</div>}

            <div className="flex gap-3 pt-2">
              <button type="submit" disabled={saving} className={actionBtnCls}
                style={{ background: 'linear-gradient(135deg,#1a6bcc,#388bfd)', boxShadow: '0 4px 14px rgba(56,139,253,0.25)' }}>
                <Save size={13} />{saving ? 'Saving…' : 'Save Settings'}
              </button>
              <button type="button" onClick={handleTest} disabled={testing || !configured} className={ghostBtnCls}>
                <Send size={13} />{testing ? 'Sending…' : 'Send Test Email'}
              </button>
            </div>
          </form>

          <div className="mt-6 border-t border-white/[0.06] pt-4">
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
