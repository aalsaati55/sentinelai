import { useState, useRef } from 'react'
import { Shield, Eye, EyeOff, AlertCircle, KeyRound } from 'lucide-react'
import { api, token } from '../api'

export function Login({ onLogin, onGoRegister }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw]     = useState(false)
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)

  // MFA step state
  const [mfaStep, setMfaStep]       = useState(false)
  const [mfaToken, setMfaToken]     = useState('')
  const [mfaUser, setMfaUser]       = useState(null)
  const [totpCode, setTotpCode]     = useState('')
  const totpRef = useRef(null)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const data = await api.login(username, password)
      if (data.mfa_required) {
        setMfaToken(data.mfa_token)
        setMfaUser({ username: data.username, role: data.role })
        setMfaStep(true)
        setTimeout(() => totpRef.current?.focus(), 100)
      } else {
        token.set(data.access_token)
        token.setUser({ username: data.username, role: data.role })
        onLogin({ username: data.username, role: data.role })
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleMfaSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const data = await api.mfaConfirm(mfaToken, totpCode.trim())
      token.set(data.access_token)
      token.setUser({ username: data.username, role: data.role })
      onLogin({ username: data.username, role: data.role })
    } catch (err) {
      setError(err.message)
      setTotpCode('')
      totpRef.current?.focus()
    } finally {
      setLoading(false)
    }
  }

  const bgGlow = (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[400px] bg-blue-500/5 rounded-full blur-3xl" />
    </div>
  )

  if (mfaStep) {
    return (
      <div className="min-h-screen bg-[#0d1117] flex items-center justify-center p-4">
        {bgGlow}
        <div className="w-full max-w-md relative">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-14 h-14 bg-purple-500/10 border border-purple-500/20 rounded-2xl mb-4">
              <KeyRound size={28} className="text-purple-400" />
            </div>
            <h1 className="text-2xl font-bold text-white">Two-Factor Authentication</h1>
            <p className="text-sm text-slate-500 mt-1">Signed in as <span className="text-slate-300 font-medium">{mfaUser?.username}</span></p>
          </div>

          <div className="bg-[#161b22] border border-[#30363d] rounded-2xl p-8 shadow-2xl">
            <h2 className="text-lg font-semibold text-white mb-1">Enter your authenticator code</h2>
            <p className="text-sm text-slate-500 mb-6">Open your authenticator app and enter the 6-digit code for SentinelAI</p>

            {error && (
              <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-400 text-sm rounded-lg px-4 py-3 mb-5">
                <AlertCircle size={15} className="shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleMfaSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                  Authenticator Code
                </label>
                <input
                  ref={totpRef}
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={totpCode}
                  onChange={e => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  required
                  autoComplete="one-time-code"
                  placeholder="000000"
                  className="w-full bg-[#1c2128] border border-[#30363d] focus:border-purple-500 text-slate-200 placeholder:text-slate-600 text-2xl text-center font-mono tracking-[0.5em] rounded-lg px-4 py-4 outline-none transition-colors"
                />
              </div>

              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm py-3 rounded-lg transition-colors mt-2"
              >
                {loading ? 'Verifying…' : 'Verify Code'}
              </button>
            </form>

            <button
              onClick={() => { setMfaStep(false); setError(''); setTotpCode('') }}
              className="w-full text-sm text-slate-500 hover:text-slate-300 text-center mt-4 transition-colors"
            >
              ← Back to login
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#0d1117] flex items-center justify-center p-4">
      {bgGlow}

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
          <h2 className="text-lg font-semibold text-white mb-1">Sign in to your account</h2>
          <p className="text-sm text-slate-500 mb-6">Enter your credentials to access the SOC dashboard</p>

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
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
                autoFocus
                placeholder="Enter your username"
                className="w-full bg-[#1c2128] border border-[#30363d] focus:border-blue-500 text-slate-200 placeholder:text-slate-600 text-sm rounded-lg px-4 py-3 outline-none transition-colors"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  placeholder="Enter your password"
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
            </div>

            <button
              type="submit"
              disabled={loading || !username || !password}
              className="w-full bg-blue-500 hover:bg-blue-400 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm py-3 rounded-lg transition-colors mt-2"
            >
              {loading ? 'Signing in…' : 'Sign In'}
            </button>
          </form>

          <p className="text-sm text-slate-500 text-center mt-6">
            Don't have an account?{' '}
            <button onClick={onGoRegister} className="text-blue-400 hover:text-blue-300 font-medium transition-colors">
              Create one
            </button>
          </p>
        </div>

        <p className="text-xs text-slate-600 text-center mt-6">
          SentinelAI SIEM Prototype — Polytechnic CLP Project
        </p>
      </div>
    </div>
  )
}
