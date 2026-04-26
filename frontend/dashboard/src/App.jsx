import { useState, useEffect } from 'react'
import { Sidebar } from './components/Sidebar'
import { Overview } from './pages/Overview'
import { Incidents } from './pages/Incidents'
import { Alerts } from './pages/Alerts'
import { Events } from './pages/Events'
import { Users } from './pages/Users'
import { Settings } from './pages/Settings'
import { AuditLog } from './pages/AuditLog'
import { AttackMap } from './pages/AttackMap'
import { Watchlist } from './pages/Watchlist'
import { AlertTuning } from './pages/AlertTuning'
import { Login } from './pages/Login'
import { Register } from './pages/Register'
import { token } from './api'
import { LogOut, User } from 'lucide-react'
import { NotificationBell } from './components/NotificationBell'
import { OnboardingModal } from './components/OnboardingModal'

function App() {
  const [page, setPage]   = useState('overview')
  const [view, setView]   = useState(() => token.get() ? 'app' : 'login')
  const [user, setUser]   = useState(() => token.user())
  const [showOnboarding, setShowOnboarding] = useState(false)
  // Verify stored token is still valid against the backend on first load
  useEffect(() => {
    if (!token.get()) return
    fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token.get()}` } })
      .then(r => {
        if (!r.ok) throw new Error('invalid')
        return r.json()
      })
      .then(u => {
        token.setUser({ username: u.username, role: u.role })
        setUser({ username: u.username, role: u.role })
      })
      .catch(() => {
        token.clear()
        setUser(null)
        setView('login')
      })
  }, [])

  function handleLogin(userData) {
    setUser(userData)
    setView('app')
    const key = `onboarding_done_${userData.username}`
    if (!localStorage.getItem(key)) {
      setShowOnboarding(true)
    }
  }

  function closeOnboarding() {
    if (user) localStorage.setItem(`onboarding_done_${user.username}`, '1')
    setShowOnboarding(false)
  }

  function handleLogout() {
    token.clear()
    setUser(null)
    setView('login')
  }

  if (view === 'login') {
    return <Login onLogin={handleLogin} onGoRegister={() => setView('register')} />
  }

  if (view === 'register') {
    return <Register onGoLogin={() => setView('login')} />
  }

  const pages = {
    overview:  <Overview onGoToIncidents={() => setPage('incidents')} />,
    incidents: <Incidents />,
    alerts:    <Alerts />,
    events:    <Events />,
    attackmap: <AttackMap />,
    watchlist: <Watchlist />,
    users:     <Users />,
    settings:  <Settings />,
    audit:     <AuditLog />,
    tuning:    <AlertTuning />,
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--bg-base)' }}>
      {showOnboarding && <OnboardingModal onClose={closeOnboarding} />}
      <Sidebar page={page} setPage={setPage} userRole={user?.role} />
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top header bar */}
        <header className="shrink-0 h-12 glass-strong flex items-center justify-end px-5 gap-3 relative"
          style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          {/* Subtle gradient accent on header bottom border */}
          <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-blue-500/20 to-transparent pointer-events-none" />

          <NotificationBell />

          <div className="flex items-center gap-1.5 pl-3" style={{ borderLeft: '1px solid rgba(255,255,255,0.07)' }}>
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-white/[0.03] border border-white/[0.07]">
              <div className="w-5 h-5 rounded-full bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center">
                <User size={11} className="text-white" />
              </div>
              <span className="text-sm font-medium text-slate-300">{user?.username}</span>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full uppercase tracking-wider
                ${user?.role === 'admin'
                  ? 'bg-purple-500/15 text-purple-300 border border-purple-500/25'
                  : 'bg-blue-500/15 text-blue-300 border border-blue-500/25'
                }`}>
                {user?.role}
              </span>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-1.5 text-xs text-slate-600 hover:text-red-400 transition-colors ml-1 px-2 py-1 rounded-lg hover:bg-red-500/5"
            >
              <LogOut size={12} />
              Sign out
            </button>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-6">
          <div className="animate-fade-in">
            {pages[page]}
          </div>
        </main>
      </div>
    </div>
  )
}

export default App
