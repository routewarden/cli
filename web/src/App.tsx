import { useState } from 'react'
import { Shield, BarChart2, Radio, Container, Globe, type LucideIcon } from 'lucide-react'
import { useEventStream } from './hooks/useEventStream'
import LiveFeed from './pages/LiveFeed'
import Stats from './pages/Stats'
import IPDetails from './pages/IPDetails'
import Sources from './pages/Sources'

type Page = 'feed' | 'services' | 'stats' | 'ip'

const NAV_ITEMS: { id: Page; label: string; Icon: LucideIcon }[] = [
  { id: 'feed',     label: 'Logs',        Icon: Radio },
  { id: 'services', label: 'Services',    Icon: Container },
  { id: 'stats',    label: 'Statistics',  Icon: BarChart2 },
  { id: 'ip',       label: 'IP Details',  Icon: Globe },
]

export default function App() {
  const [page, setPage] = useState<Page>(() => {
    if (typeof window !== 'undefined') {
      const hash = window.location.hash.replace('#', '').toLowerCase() as Page
      if (['services', 'stats', 'ip'].includes(hash)) return hash
      const params = new URLSearchParams(window.location.search)
      if (params.get('ip')) return 'ip'
      const p = params.get('page') as Page
      if (['services', 'stats', 'ip'].includes(p)) return p
    }
    return 'feed'
  })

  const [selectedContainer, setSelectedContainer] = useState<string>('all')
  const [selectedIP, setSelectedIP] = useState<string>(() => {
    if (typeof window !== 'undefined') {
      return new URLSearchParams(window.location.search).get('ip') ?? ''
    }
    return ''
  })
  const [feedFilter, setFeedFilter] = useState<string>('')

  const { events, sources, connected, paused, setPaused, clear, clearStoppedSources } = useEventStream()

  const navigateTo = (newPage: Page) => {
    setPage(newPage)
    if (typeof window !== 'undefined') {
      window.location.hash = newPage
    }
  }

  const handleSelectSource = (name: string) => {
    setSelectedContainer(name)
    navigateTo('feed')
  }

  const handleSelectIP = (ip: string) => {
    setSelectedIP(ip)
    navigateTo('ip')
  }

  const handleFilterInFeed = (filter: string) => {
    setFeedFilter(filter)
    navigateTo('feed')
  }

  const staleSourceCount = sources.filter(s => s.status !== 'live').length

  return (
    <div className="layout">
      {/* ── Header bar ── */}
      <header className="header">
        <div className="header-logo">
          <Shield size={20} />
          RouteWarden
          <span className="header-badge">View-Only</span>
        </div>

        <div className="header-right">
          <span className="header-stat-item" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {events.length.toLocaleString()} events
          </span>
          <button
            className="header-stat-item header-sources-item"
            onClick={() => navigateTo('services')}
            style={{
              fontSize: 12,
              color: staleSourceCount > 0 ? 'var(--yellow)' : 'var(--text-muted)',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              padding: 0,
            }}
            title="Click to view Services and clear stale containers"
          >
            <span>{sources.filter(s => s.status === 'live').length} live source{sources.filter(s => s.status === 'live').length !== 1 ? 's' : ''}</span>
            {staleSourceCount > 0 && (
              <span style={{ fontSize: 10, background: 'rgba(234, 179, 8, 0.2)', color: 'var(--yellow)', padding: '1px 5px', borderRadius: 999 }}>
                {staleSourceCount} stale
              </span>
            )}
          </button>
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
            onClick={() => navigateTo(id)}
          >
            <Icon size={16} />
            <span className="nav-label">{label}</span>
            {id === 'services' && staleSourceCount > 0 ? (
              <span className="nav-badge" style={{ background: 'var(--yellow)', color: '#000', fontWeight: 600 }}>
                {staleSourceCount}
              </span>
            ) : null}
          </button>
        ))}
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
            onSelectIP={handleSelectIP}
            filter={feedFilter}
            onFilterChange={setFeedFilter}
          />
        )}
        {page === 'services' && (
          <Sources
            sources={sources}
            onClearStopped={clearStoppedSources}
            onSelectSource={handleSelectSource}
          />
        )}
        {page === 'stats' && (
          <Stats
            sources={sources}
            selectedContainer={selectedContainer}
            onSelectContainer={setSelectedContainer}
            onSelectIP={handleSelectIP}
          />
        )}
        {page === 'ip' && (
          <IPDetails
            ip={selectedIP || events[0]?.client_ip || '127.0.0.1'}
            onBack={() => navigateTo('feed')}
            onSelectContainer={handleSelectSource}
            onFilterInFeed={handleFilterInFeed}
            recentEvents={events}
            onSelectIP={setSelectedIP}
          />
        )}
      </main>

      {/* ── Mobile / Tablet Bottom Navigation ── */}
      <nav className="bottom-nav">
        {NAV_ITEMS.map(({ id, label, Icon }) => (
          <button
            key={id}
            className={`bottom-nav-item ${page === id ? 'active' : ''}`}
            onClick={() => navigateTo(id)}
          >
            <div className="bottom-nav-icon-wrap">
              <Icon size={18} />
              {id === 'services' && staleSourceCount > 0 ? (
                <span className="bottom-nav-badge" style={{ background: 'var(--yellow)', color: '#000', fontWeight: 600 }}>{staleSourceCount}</span>
              ) : null}
            </div>
            <span>{label}</span>
          </button>
        ))}
      </nav>
    </div>
  )
}

