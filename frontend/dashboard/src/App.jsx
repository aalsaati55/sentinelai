import { useState } from 'react'
import { Sidebar } from './components/Sidebar'
import { Overview } from './pages/Overview'
import { Incidents } from './pages/Incidents'
import { Alerts } from './pages/Alerts'
import { Events } from './pages/Events'

function App() {
  const [page, setPage] = useState('overview')

  const pages = {
    overview:  <Overview onGoToIncidents={() => setPage('incidents')} />,
    incidents: <Incidents />,
    alerts:    <Alerts />,
    events:    <Events />,
  }

  return (
    <div className="flex h-screen overflow-hidden bg-[#0d1117]">
      <Sidebar page={page} setPage={setPage} />
      <main className="flex-1 overflow-y-auto p-6">
        {pages[page]}
      </main>
    </div>
  )
}

export default App
