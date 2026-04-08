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
  }

  return (
    <div className="flex h-screen overflow-hidden bg-[#0d1117]">
      {showOnboarding && <OnboardingModal onClose={closeOnboarding} />}
      <Sidebar page={page} setPage={setPage} userRole={user?.role} />
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top header bar */}
        <header className="shrink-0 h-12 bg-[#161b22] border-b border-[#30363d] flex items-center justify-end px-5 gap-3">
          <NotificationBell />
          <div className="flex items-center gap-2 text-sm text-slate-400">
            <User size={14} className="text-slate-500" />
            <span className="font-medium text-slate-300">{user?.username}</span>
            <span className="text-xs bg-blue-500/15 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded-full">
              {user?.role}
            </span>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-red-400 transition-colors ml-2"
          >
            <LogOut size={13} />
            Sign out
          </button>
        </header>
        <main className="flex-1 overflow-y-auto p-6">
          {pages[page]}
        </main>
      </div>
    </div>
  )
}

export default App
