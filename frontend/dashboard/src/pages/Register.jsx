import { useState, useMemo } from 'react'
import { Shield, Eye, EyeOff, AlertCircle, CheckCircle, X } from 'lucide-react'
import { api } from '../api'

const DOMAIN = 'sentinelai.com'
// local part: starts with letter, letters/numbers/dots, ends with digit
const LOCAL_RE = /^[a-zA-Z][a-zA-Z0-9.]+[0-9]+$/

function isValidEmail(email) {
  if (!email.includes('@')) return false
  const [local, domain] = email.split('@')
  if (domain !== DOMAIN) return false
  return LOCAL_RE.test(local)
}

function pwChecks(pw) {
  return {
    length:  pw.length >= 8,
    upper:   /[A-Z]/.test(pw),
    digit:   /\d/.test(pw),
    special: /[!@#$%^&*()_+\-=\[\]{};'\\:"|,.<>\/?`~]/.test(pw),
  }
}

function CheckRow({ ok, label }) {
  return (
    <div className={`flex items-center gap-1.5 text-xs ${ok ? 'text-green-400' : 'text-slate-500'}`}>
      {ok ? <CheckCircle size={11} /> : <X size={11} />}
      {label}
    </div>
  )
}

export function Register({ onGoLogin }) {
  const [form, setForm]       = useState({ username: '', email: '', password: '', confirm: '' })
  const [showPw, setShowPw]   = useState(false)
  const [error, setError]     = useState('')
  const [success, setSuccess] = useState(false)
  const [createdRole, setCreatedRole] = useState('analyst')
  const [loading, setLoading] = useState(false)

  const checks = useMemo(() => pwChecks(form.password), [form.password])
  const allChecksPass = Object.values(checks).every(Boolean)
  const emailValid = form.email ? isValidEmail(form.email) : null

  function update(field) {
    return e => setForm(f => ({ ...f, [field]: e.target.value }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!isValidEmail(form.email)) {
      setError(`Email must be in format name1@${DOMAIN} (e.g. john.doe1@${DOMAIN})`)
      return
    }
    if (!allChecksPass) {
      setError('Password does not meet all requirements')
      return
    }
    if (form.password !== form.confirm) {
      setError('Passwords do not match')
      return
    }
    setLoading(true)
    try {
      const created = await api.register(form.username, form.email, form.password)
      setCreatedRole(created.role || 'analyst')
      setSuccess(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const inputBase = "w-full bg-white/[0.04] border border-white/[0.08] focus:border-blue-500/60 focus:shadow-[0_0_0_3px_rgba(56,139,253,0.12)] text-slate-200 placeholder:text-slate-600 text-sm rounded-xl px-4 py-3 outline-none transition-all"

  const Background = () => (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <div className="absolute inset-0 grid-bg opacity-40" />
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-blue-600/8 rounded-full blur-[120px]" />
      <div className="absolute bottom-0 right-1/4 w-[400px] h-[300px] bg-purple-600/6 rounded-full blur-[100px]" />
    </div>
  )

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 relative" style={{ background: 'var(--bg-base)' }}>
        <Background />
        <div className="w-full max-w-sm text-center relative animate-fade-in-up">
          <div className="relative rounded-2xl p-10 shadow-[0_24px_80px_rgba(0,0,0,0.6)]"
            style={{ background: 'rgba(13,20,33,0.85)', border: '1px solid rgba(255,255,255,0.08)', backdropFilter: 'blur(20px)' }}>
            <div className="absolute top-0 left-8 right-8 h-px bg-gradient-to-r from-transparent via-green-500/40 to-transparent" />
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-5"
              style={{ background: 'linear-gradient(135deg,rgba(63,185,80,0.15),rgba(63,185,80,0.05))', border: '1px solid rgba(63,185,80,0.25)', boxShadow: '0 0 24px rgba(63,185,80,0.15)' }}>
              <CheckCircle size={26} className="text-green-400" />
            </div>
            <h2 className="text-xl font-bold text-white mb-2">Account Created!</h2>
            <p className="text-slate-500 text-sm mb-6">
              Your <span className="text-blue-400 font-semibold">{createdRole}</span> account{' '}
              <span className="text-white font-semibold">{form.username}</span> is ready.
            </p>
            <button onClick={onGoLogin}
              className="w-full text-white font-bold text-sm py-3 rounded-xl transition-all"
              style={{ background: 'linear-gradient(135deg,#1a6bcc,#388bfd)', boxShadow: '0 4px 20px rgba(56,139,253,0.3)' }}>
              Sign In Now →
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative" style={{ background: 'var(--bg-base)' }}>
      <Background />

      <div className="w-full max-w-md relative animate-fade-in-up">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-5 relative animate-float"
            style={{ background: 'linear-gradient(135deg,rgba(56,139,253,0.15),rgba(56,139,253,0.05))', border: '1px solid rgba(56,139,253,0.3)', boxShadow: '0 0 30px rgba(56,139,253,0.2)' }}>
            <Shield size={26} className="text-blue-400" />
            <span className="absolute -top-1 -right-1 w-3 h-3 bg-blue-400 rounded-full shadow-[0_0_8px_#388bfd] animate-pulse" />
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight gradient-text-blue">SentinelAI</h1>
          <p className="text-xs text-slate-600 mt-2 font-medium tracking-widest uppercase">Create your SOC account</p>
        </div>

        {/* Card */}
        <div className="relative rounded-2xl p-8 shadow-[0_24px_80px_rgba(0,0,0,0.6)]"
          style={{ background: 'rgba(13,20,33,0.85)', border: '1px solid rgba(255,255,255,0.08)', backdropFilter: 'blur(20px)' }}>
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-blue-500/[0.03] to-transparent pointer-events-none" />
          <div className="absolute top-0 left-8 right-8 h-px bg-gradient-to-r from-transparent via-blue-500/50 to-transparent" />

          <div className="relative">
            <h2 className="text-lg font-bold text-white mb-0.5">Create an account</h2>
            <p className="text-xs text-slate-600 mb-6">Register as a SOC analyst to access the dashboard</p>

            {error && (
              <div className="flex items-center gap-2 bg-red-500/8 border border-red-500/20 text-red-300 text-xs rounded-xl px-4 py-3 mb-5">
                <AlertCircle size={14} className="shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-2">Username</label>
                <input type="text" value={form.username} onChange={update('username')} required autoFocus
                  placeholder="Choose a username" className={inputBase} />
              </div>

              <div>
                <label className="block text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-2">
                  Email <span className="normal-case font-normal text-slate-700">(@sentinelai.com only)</span>
                </label>
                <input type="text" value={form.email} onChange={update('email')} required
                  placeholder={`john.doe1@${DOMAIN}`}
                  className={`w-full bg-white/[0.04] border text-slate-200 placeholder:text-slate-600 text-sm rounded-xl px-4 py-3 outline-none transition-all
                    ${form.email
                      ? emailValid
                        ? 'border-green-500/50 focus:border-green-500/70 focus:shadow-[0_0_0_3px_rgba(63,185,80,0.1)]'
                        : 'border-red-500/50 focus:border-red-500/70 focus:shadow-[0_0_0_3px_rgba(248,81,73,0.1)]'
                      : 'border-white/[0.08] focus:border-blue-500/60 focus:shadow-[0_0_0_3px_rgba(56,139,253,0.12)]'}`}
                />
                {form.email && !emailValid && (
                  <p className="text-[11px] text-red-400/80 mt-1.5">Must be @{DOMAIN} with at least one number</p>
                )}
              </div>

              <div>
                <label className="block text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-2">Password</label>
                <div className="relative">
                  <input type={showPw ? 'text' : 'password'} value={form.password} onChange={update('password')} required
                    placeholder="Min 8 chars, uppercase, number, symbol"
                    className={`${inputBase} pr-11`} />
                  <button type="button" onClick={() => setShowPw(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400 transition-colors">
                    {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
                {form.password && (
                  <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 rounded-xl px-3 py-2.5"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <CheckRow ok={checks.length}  label="At least 8 characters" />
                    <CheckRow ok={checks.upper}   label="One uppercase letter" />
                    <CheckRow ok={checks.digit}   label="One number" />
                    <CheckRow ok={checks.special} label="One special character" />
                  </div>
                )}
              </div>

              <div>
                <label className="block text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-2">Confirm Password</label>
                <input type={showPw ? 'text' : 'password'} value={form.confirm} onChange={update('confirm')} required
                  placeholder="Repeat your password"
                  className={`w-full bg-white/[0.04] border text-slate-200 placeholder:text-slate-600 text-sm rounded-xl px-4 py-3 outline-none transition-all
                    ${form.confirm
                      ? form.confirm === form.password
                        ? 'border-green-500/50 focus:border-green-500/70 focus:shadow-[0_0_0_3px_rgba(63,185,80,0.1)]'
                        : 'border-red-500/50 focus:border-red-500/70 focus:shadow-[0_0_0_3px_rgba(248,81,73,0.1)]'
                      : 'border-white/[0.08] focus:border-blue-500/60 focus:shadow-[0_0_0_3px_rgba(56,139,253,0.12)]'}`}
                />
                {form.confirm && form.confirm !== form.password && (
                  <p className="text-[11px] text-red-400/80 mt-1.5">Passwords do not match</p>
                )}
              </div>

              <button type="submit"
                disabled={loading || !form.username || !emailValid || !allChecksPass || !form.confirm || form.password !== form.confirm}
                className="w-full text-white font-bold text-sm py-3 rounded-xl transition-all disabled:opacity-40 disabled:cursor-not-allowed mt-1"
                style={{ background: 'linear-gradient(135deg,#1a6bcc,#388bfd)', boxShadow: '0 4px 20px rgba(56,139,253,0.3)' }}>
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Creating account…
                  </span>
                ) : 'Create Account →'}
              </button>
            </form>

            <div className="flex items-center gap-3 my-5">
              <div className="flex-1 h-px bg-white/[0.05]" />
              <span className="text-[10px] text-slate-700 uppercase tracking-wider">or</span>
              <div className="flex-1 h-px bg-white/[0.05]" />
            </div>

            <p className="text-xs text-slate-600 text-center">
              Already have an account?{' '}
              <button onClick={onGoLogin} className="text-blue-400 hover:text-blue-300 font-semibold transition-colors">
                Sign in
              </button>
            </p>
          </div>
        </div>

        <p className="text-[10px] text-slate-700 text-center mt-6 tracking-wider uppercase">
          SentinelAI · Polytechnic CLP Project
        </p>
      </div>
    </div>
  )
}
