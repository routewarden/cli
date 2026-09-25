import { useState } from 'react'
import { Shield, BarChart2, Radio, Layers, type LucideIcon } from 'lucide-react'
import { useEventStream } from './hooks/useEventStream'
import LiveFeed from './pages/LiveFeed'
import Stats from './pages/Stats'
import Sources from './pages/Sources'

type Page = 'feed' | 'stats' | 'sources'

const NAV_ITEMS: { id: Page; label: string; Icon: LucideIcon }[] = [
  { id: 'feed',    label: 'Live Feed',  Icon: Radio },
  { id: 'stats',   label: 'Statistics', Icon: BarChart2 },
  { id: 'sources', label: 'Sources',    Icon: Layers },
]

export default function App() {
  const [page, setPage] = useState<Page>('feed')
  const [selectedContainer, setSelectedContainer] = useState<string>('all')
  const { events, sources, connected, paused, setPaused, clear, clearStoppedSources } = useEventStream()

  const handleSelectSource = (name: string) => {
    setSelectedContainer(name)
    setPage('feed')
  }

  return (
    <div className="layout">
      {/* ── Header bar ── */}
      <header className="header">
        <div className="header-logo">
          <Shield size={20} />
          RouteWarden
          <span className="header-badge">Dashboard</span>
        </div>

        <div className="header-right">
          <span className="header-stat-item" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {events.length.toLocaleString()} events
          </span>
          <span className="header-stat-item header-sources-item" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {sources.filter(s => s.status === 'live').length} live source{sources.filter(s => s.status === 'live').length !== 1 ? 's' : ''}
          </span>
          <div
            className={`connection-dot ${connected ? '' : 'disconnected'}`}
            title={connected ? 'Connected' : 'Reconnecting…'}
          />
          <span className="header-live-text" style={{ fontSize: 11, color: connected ? 'var(--green)' : 'var(--red)' }}>
            {connected ? 'Live' : 'Reconnecting…'}
          </span>
        </div>
      </header>

      {/* ── Desktop / Tablet Sidebar ── */}
      <nav className="sidebar">
        {NAV_ITEMS.map(({ id, label, Icon }) => (
          <button
            key={id}
            className={`nav-item ${page === id ? 'active' : ''}`}
            onClick={() => setPage(id)}
          >
            <Icon size={16} />
            <span className="nav-label">{label}</span>
            {id === 'sources' && sources.length > 0 && (
              <span className="nav-badge">
                {sources.length}
              </span>
            )}
          </button>
        ))}

        <div className="nav-divider" />

        <div className="sidebar-about" style={{ padding: '8px 12px', fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>
          <div style={{ fontWeight: 600, marginBottom: 4, color: 'var(--text-secondary)' }}>About</div>
          RouteWarden Dashboard<br />
          reads logs from Docker<br />
          containers or log files.
        </div>
      </nav>

      {/* ── Main content ── */}
      <main className="main">
        {page === 'feed' && (
          <LiveFeed
            events={events}
            sources={sources}
            selectedContainer={selectedContainer}
            onSelectContainer={setSelectedContainer}
            paused={paused}
            onPause={setPaused}
            onClear={clear}
          />
        )}
        {page === 'stats' && (
          <Stats
            sources={sources}
            selectedContainer={selectedContainer}
            onSelectContainer={setSelectedContainer}
          />
        )}
        {page === 'sources' && (
          <Sources
            sources={sources}
            onClearStopped={clearStoppedSources}
            onSelectSource={handleSelectSource}
          />
        )}
      </main>

      {/* ── Mobile / Tablet Bottom Navigation ── */}
      <nav className="bottom-nav">
        {NAV_ITEMS.map(({ id, label, Icon }) => (
          <button
            key={id}
            className={`bottom-nav-item ${page === id ? 'active' : ''}`}
            onClick={() => setPage(id)}
          >
            <div className="bottom-nav-icon-wrap">
              <Icon size={18} />
              {id === 'sources' && sources.length > 0 && (
                <span className="bottom-nav-badge">{sources.length}</span>
              )}
            </div>
            <span>{label}</span>
          </button>
        ))}
      </nav>
    </div>
  )
}
