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

  if (success) {
    return (
      <div className="min-h-screen bg-[#0d1117] flex items-center justify-center p-4">
        <div className="w-full max-w-md text-center">
          <div className="bg-[#161b22] border border-[#30363d] rounded-2xl p-10 shadow-2xl">
            <div className="inline-flex items-center justify-center w-14 h-14 bg-green-500/10 border border-green-500/20 rounded-2xl mb-5">
              <CheckCircle size={28} className="text-green-400" />
            </div>
            <h2 className="text-xl font-bold text-white mb-2">Account Created!</h2>
            <p className="text-slate-400 text-sm mb-6">
              Your <span className="text-blue-400 font-semibold">{createdRole}</span> account{' '}
              <span className="text-white font-semibold">{form.username}</span> is ready.
            </p>
            <button
              onClick={onGoLogin}
              className="w-full bg-blue-500 hover:bg-blue-400 text-white font-semibold text-sm py-3 rounded-lg transition-colors"
            >
              Sign In Now
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#0d1117] flex items-center justify-center p-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[400px] bg-blue-500/5 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-md relative">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 bg-blue-500/10 border border-blue-500/20 rounded-2xl mb-4">
            <Shield size={28} className="text-blue-400" />
          </div>
          <h1 className="text-2xl font-bold text-white">SentinelAI</h1>
          <p className="text-sm text-slate-500 mt-1">Security Information & Event Management</p>
        </div>

        {/* Card */}
        <div className="bg-[#161b22] border border-[#30363d] rounded-2xl p-8 shadow-2xl">
          <h2 className="text-lg font-semibold text-white mb-1">Create an account</h2>
          <p className="text-sm text-slate-500 mb-6">Register as a SOC analyst to access the dashboard</p>

          {error && (
            <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-400 text-sm rounded-lg px-4 py-3 mb-5">
              <AlertCircle size={15} className="shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Username
              </label>
              <input
                type="text"
                value={form.username}
                onChange={update('username')}
                required
                autoFocus
                placeholder="Choose a username"
                className="w-full bg-[#1c2128] border border-[#30363d] focus:border-blue-500 text-slate-200 placeholder:text-slate-600 text-sm rounded-lg px-4 py-3 outline-none transition-colors"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Email <span className="normal-case text-slate-600 font-normal">(@sentinelai.com only)</span>
              </label>
              <input
                type="text"
                value={form.email}
                onChange={update('email')}
                required
                placeholder={`john.doe1@${DOMAIN}`}
                className={`w-full bg-[#1c2128] border text-slate-200 placeholder:text-slate-600 text-sm rounded-lg px-4 py-3 outline-none transition-colors
                  ${form.email
                    ? emailValid
                      ? 'border-green-500/60 focus:border-green-500'
                      : 'border-red-500/60 focus:border-red-500'
                    : 'border-[#30363d] focus:border-blue-500'}`}
              />
              {form.email && !emailValid && (
                <p className="text-xs text-red-400 mt-1.5">
                  Must be @{DOMAIN} with at least one number (e.g. john.doe1@{DOMAIN})
                </p>
              )}
            </div>


            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  value={form.password}
                  onChange={update('password')}
                  required
                  placeholder="Min 8 chars, uppercase, number, symbol"
                  className="w-full bg-[#1c2128] border border-[#30363d] focus:border-blue-500 text-slate-200 placeholder:text-slate-600 text-sm rounded-lg px-4 py-3 pr-11 outline-none transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {form.password && (
                <div className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 bg-[#1c2128] border border-[#30363d] rounded-lg px-3 py-2.5">
                  <CheckRow ok={checks.length}  label="At least 8 characters" />
                  <CheckRow ok={checks.upper}   label="One uppercase letter" />
                  <CheckRow ok={checks.digit}   label="One number" />
                  <CheckRow ok={checks.special} label="One special character" />
                </div>
              )}
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Confirm Password
              </label>
              <input
                type={showPw ? 'text' : 'password'}
                value={form.confirm}
                onChange={update('confirm')}
                required
                placeholder="Repeat your password"
                className={`w-full bg-[#1c2128] border text-slate-200 placeholder:text-slate-600 text-sm rounded-lg px-4 py-3 outline-none transition-colors
                  ${form.confirm
                    ? form.confirm === form.password
                      ? 'border-green-500/60 focus:border-green-500'
                      : 'border-red-500/60 focus:border-red-500'
                    : 'border-[#30363d] focus:border-blue-500'}`}
              />
              {form.confirm && form.confirm !== form.password && (
                <p className="text-xs text-red-400 mt-1.5">Passwords do not match</p>
              )}
            </div>

            <button
              type="submit"
              disabled={loading || !form.username || !emailValid || !allChecksPass || !form.confirm || form.password !== form.confirm}
              className="w-full bg-blue-500 hover:bg-blue-400 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm py-3 rounded-lg transition-colors mt-2"
            >
              {loading ? 'Creating account…' : 'Create Account'}
            </button>
          </form>

          <p className="text-sm text-slate-500 text-center mt-6">
            Already have an account?{' '}
            <button onClick={onGoLogin} className="text-blue-400 hover:text-blue-300 font-medium transition-colors">
              Sign in
            </button>
          </p>
        </div>
      </div>
    </div>
  )
}
