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

  const Background = () => (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {/* Grid */}
      <div className="absolute inset-0 grid-bg opacity-40" />
      {/* Central blue orb */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-blue-600/8 rounded-full blur-[120px]" />
      {/* Bottom purple orb */}
      <div className="absolute bottom-0 right-1/4 w-[400px] h-[300px] bg-purple-600/6 rounded-full blur-[100px]" />
      {/* Top left accent */}
      <div className="absolute top-0 left-0 w-[300px] h-[200px] bg-cyan-500/4 rounded-full blur-[80px]" />
      {/* Scan line */}
      <div className="absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-blue-500/20 to-transparent" style={{ top: '30%' }} />
      <div className="absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-purple-500/10 to-transparent" style={{ top: '70%' }} />
    </div>
  )

  const inputCls = "w-full bg-white/[0.04] border border-white/[0.08] focus:border-blue-500/60 focus:shadow-[0_0_0_3px_rgba(56,139,253,0.12)] text-slate-200 placeholder:text-slate-600 text-sm rounded-xl px-4 py-3 outline-none transition-all"

  if (mfaStep) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 relative" style={{ background: 'var(--bg-base)' }}>
        <Background />
        <div className="w-full max-w-sm relative animate-fade-in-up">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4 relative"
              style={{ background: 'linear-gradient(135deg, rgba(163,113,247,0.15), rgba(163,113,247,0.05))', border: '1px solid rgba(163,113,247,0.25)' }}>
              <KeyRound size={26} className="text-purple-400" />
              <span className="absolute -top-1 -right-1 w-3 h-3 bg-purple-400 rounded-full shadow-[0_0_8px_#a371f7]" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Two-Factor Auth</h1>
            <p className="text-sm text-slate-600 mt-1">Signed in as <span className="text-slate-400 font-medium">{mfaUser?.username}</span></p>
          </div>

          <div className="relative rounded-2xl p-8 shadow-[0_24px_80px_rgba(0,0,0,0.6)]"
            style={{ background: 'rgba(13,20,33,0.85)', border: '1px solid rgba(255,255,255,0.08)', backdropFilter: 'blur(20px)' }}>
            <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-purple-500/[0.04] to-transparent pointer-events-none" />
            <div className="absolute top-0 left-8 right-8 h-px bg-gradient-to-r from-transparent via-purple-500/40 to-transparent" />

            <h2 className="text-base font-semibold text-slate-200 mb-1">Enter authenticator code</h2>
            <p className="text-xs text-slate-600 mb-6">Open your authenticator app and enter the 6-digit code</p>

            {error && (
              <div className="flex items-center gap-2 bg-red-500/8 border border-red-500/20 text-red-300 text-xs rounded-xl px-4 py-3 mb-5">
                <AlertCircle size={14} className="shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleMfaSubmit} className="space-y-4">
              <div>
                <label className="block text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-2">Authenticator Code</label>
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
                  className="w-full bg-white/[0.04] border border-white/[0.08] focus:border-purple-500/60 focus:shadow-[0_0_0_3px_rgba(163,113,247,0.12)] text-slate-200 placeholder:text-slate-700 text-2xl text-center font-mono tracking-[0.5em] rounded-xl px-4 py-4 outline-none transition-all"
                />
              </div>
              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="w-full text-white font-bold text-sm py-3 rounded-xl transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                style={{ background: 'linear-gradient(135deg, #7c3aed, #a371f7)', boxShadow: '0 4px 20px rgba(163,113,247,0.3)' }}
              >
                {loading ? 'Verifying…' : 'Verify & Sign In'}
              </button>
            </form>

            <button
              onClick={() => { setMfaStep(false); setError(''); setTotpCode('') }}
              className="w-full text-xs text-slate-600 hover:text-slate-400 text-center mt-5 transition-colors"
            >
              ← Back to login
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative" style={{ background: 'var(--bg-base)' }}>
      <Background />

      <div className="w-full max-w-sm relative animate-fade-in-up">
        {/* Logo block */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-5 relative animate-float"
            style={{ background: 'linear-gradient(135deg, rgba(56,139,253,0.15), rgba(56,139,253,0.05))', border: '1px solid rgba(56,139,253,0.3)', boxShadow: '0 0 30px rgba(56,139,253,0.2)' }}>
            <Shield size={26} className="text-blue-400" />
            <span className="absolute -top-1 -right-1 w-3 h-3 bg-blue-400 rounded-full shadow-[0_0_8px_#388bfd] animate-pulse" />
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight gradient-text-blue">SentinelAI</h1>
          <p className="text-xs text-slate-600 mt-2 font-medium tracking-widest uppercase">Security Operations Center</p>
        </div>

        {/* Card */}
        <div className="relative rounded-2xl p-8 shadow-[0_24px_80px_rgba(0,0,0,0.6)]"
          style={{ background: 'rgba(13,20,33,0.85)', border: '1px solid rgba(255,255,255,0.08)', backdropFilter: 'blur(20px)' }}>
          {/* Inner gradient overlay */}
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-blue-500/[0.04] to-transparent pointer-events-none" />
          {/* Top accent line */}
          <div className="absolute top-0 left-8 right-8 h-px bg-gradient-to-r from-transparent via-blue-500/50 to-transparent" />

          <div className="relative">
            <h2 className="text-lg font-bold text-white mb-0.5">Sign in</h2>
            <p className="text-xs text-slate-600 mb-6">Access the SOC dashboard</p>

            {error && (
              <div className="flex items-center gap-2 bg-red-500/8 border border-red-500/20 text-red-300 text-xs rounded-xl px-4 py-3 mb-5">
                <AlertCircle size={14} className="shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-2">Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  required
                  autoFocus
                  placeholder="Enter your username"
                  className={inputCls}
                />
              </div>

              <div>
                <label className="block text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-2">Password</label>
                <div className="relative">
                  <input
                    type={showPw ? 'text' : 'password'}
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    required
                    placeholder="Enter your password"
                    className={`${inputCls} pr-11`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400 transition-colors"
                  >
                    {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading || !username || !password}
                className="w-full text-white font-bold text-sm py-3 rounded-xl transition-all disabled:opacity-40 disabled:cursor-not-allowed mt-1"
                style={{ background: 'linear-gradient(135deg, #1a6bcc, #388bfd)', boxShadow: '0 4px 20px rgba(56,139,253,0.3)' }}
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Signing in…
                  </span>
                ) : 'Sign In →'}
              </button>
            </form>

            <div className="flex items-center gap-3 my-5">
              <div className="flex-1 h-px bg-white/[0.05]" />
              <span className="text-[10px] text-slate-700 uppercase tracking-wider">or</span>
              <div className="flex-1 h-px bg-white/[0.05]" />
            </div>

            <p className="text-xs text-slate-600 text-center">
              No account?{' '}
              <button onClick={onGoRegister} className="text-blue-400 hover:text-blue-300 font-semibold transition-colors">
                Create one
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
