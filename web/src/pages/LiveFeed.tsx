import { useState, useMemo, useEffect, useRef } from 'react'
import {
  Pause, Play, Trash2, Search, Container,
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight
} from 'lucide-react'
import type { SecurityEvent, Source } from '../types'
import {
  relativeTime, methodBadgeClass, modeBadgeClass,
  pluginBadgeClass, pluginLabel, modeLabel, filterEvents
} from '../utils'

interface LiveFeedProps {
  events: SecurityEvent[]
  sources: Source[]
  selectedContainer: string
  onSelectContainer: (c: string) => void
  paused: boolean
  onPause: (p: boolean) => void
  onClear: () => void
}

export default function LiveFeed({
  events,
  sources,
  selectedContainer,
  onSelectContainer,
  paused,
  onPause,
  onClear,
}: LiveFeedProps) {
  const [filter, setFilter] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const eventListRef = useRef<HTMLDivElement>(null)

  // Build unique list of container/source options with count of events
  const containerOptions = useMemo(() => {
    const counts = new Map<string, number>()
    for (const e of events) {
      const src = e.source || 'unknown'
      counts.set(src, (counts.get(src) || 0) + 1)
    }
    // Also include any active discovered sources
    for (const s of sources) {
      if (s.name && !counts.has(s.name)) {
        counts.set(s.name, 0)
      }
    }
    return Array.from(counts.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
  }, [events, sources])

  // Filter events by container and search query
  const filtered = useMemo(() => {
    let list = events
    if (selectedContainer && selectedContainer !== 'all') {
      list = list.filter(e => e.source === selectedContainer || e.source_id === selectedContainer)
    }
    return filterEvents(list, filter)
  }, [events, selectedContainer, filter])

  // Reset to page 1 when filter or container filter changes
  useEffect(() => {
    setCurrentPage(1)
  }, [filter, selectedContainer])

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const safePage = Math.min(Math.max(1, currentPage), totalPages)

  // Sliced events for current page
  const paginatedEvents = useMemo(() => {
    const start = (safePage - 1) * pageSize
    return filtered.slice(start, start + pageSize)
  }, [filtered, safePage, pageSize])

  const startIndex = filtered.length === 0 ? 0 : (safePage - 1) * pageSize
  const endIndex = Math.min(startIndex + pageSize, filtered.length)

  // Scroll to top of table on page change
  useEffect(() => {
    if (eventListRef.current) {
      eventListRef.current.scrollTop = 0
    }
  }, [safePage])

  return (
    <div className="page page-fixed">
      <div className="page-header" style={{ flexShrink: 0 }}>
        <div>
          <div className="page-title">Live Event Feed</div>
          <div className="page-subtitle">Real-time security events from all sources</div>
        </div>
      </div>

      <div className="event-table-wrap">
        {/* Toolbar */}
        <div className="event-table-toolbar">
          <Search size={14} color="var(--text-muted)" style={{ flexShrink: 0 }} />
          <input
            className="filter-input"
            placeholder="Filter by IP, path, method, pattern…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
          />

          {/* Container filter dropdown */}
          <div className="container-filter-wrap">
            <Container size={13} color="var(--text-muted)" style={{ flexShrink: 0 }} />
            <select
              className="container-select"
              value={selectedContainer}
              onChange={e => onSelectContainer(e.target.value)}
              title="Filter logs by container"
            >
              <option value="all">All Containers ({events.length})</option>
              {containerOptions.map(c => (
                <option key={c.name} value={c.name}>
                  {c.name} ({c.count})
                </option>
              ))}
            </select>
            {selectedContainer !== 'all' && (
              <button
                className="clear-filter-btn"
                onClick={() => onSelectContainer('all')}
                title="Clear container filter"
              >
                ×
              </button>
            )}
          </div>

          <span className="event-count-badge">{filtered.length.toLocaleString()}</span>
          <button
            className={`toolbar-btn ${paused ? 'active' : ''}`}
            onClick={() => onPause(!paused)}
          >
            {paused ? <Play size={13} /> : <Pause size={13} />}
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button className="toolbar-btn" onClick={onClear}>
            <Trash2 size={13} /> Clear
          </button>
        </div>

        {/* Table content with horizontal scroll for small screens */}
        <div className="event-table-content">
          <div className="event-table-head">
            <span className="col-head">Time</span>
            <span className="col-head">IP</span>
            <span className="col-head">Method</span>
            <span className="col-head">Path</span>
            <span className="col-head">Pattern</span>
            <span className="col-head">Response</span>
            <span className="col-head">Container / Gateway</span>
          </div>

          {/* Events */}
          <div className="event-list" ref={eventListRef}>
            {filtered.length === 0 ? (
              <EmptyState filter={filter} container={selectedContainer} />
            ) : (
              paginatedEvents.map((e, i) => (
                <EventRow
                  key={`${e.timestamp}-${startIndex + i}`}
                  event={e}
                  onSelectContainer={onSelectContainer}
                />
              ))
            )}
          </div>
        </div>

        {/* Pagination Bar */}
        <div className="pagination-bar">
          <div className="pagination-info">
            <span>
              Showing <strong className="text-secondary">{filtered.length === 0 ? 0 : startIndex + 1}–{endIndex}</strong> of{' '}
              <strong className="text-secondary">{filtered.length.toLocaleString()}</strong> events
            </span>
            <div className="pagination-size-wrap">
              <span className="pagination-size-label">Per page:</span>
              <select
                className="pagination-select"
                value={pageSize}
                onChange={e => {
                  setPageSize(Number(e.target.value))
                  setCurrentPage(1)
                }}
                title="Number of events per page"
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={200}>200</option>
              </select>
            </div>
            {safePage > 1 && (
              <button
                className="pagination-jump-latest"
                onClick={() => setCurrentPage(1)}
                title="Jump to latest incoming events"
              >
                Jump to latest (Page 1)
              </button>
            )}
          </div>

          <div className="pagination-nav">
            <button
              className="pagination-btn"
              disabled={safePage <= 1}
              onClick={() => setCurrentPage(1)}
              title="First page"
            >
              <ChevronsLeft size={14} />
            </button>
            <button
              className="pagination-btn"
              disabled={safePage <= 1}
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              title="Previous page"
            >
              <ChevronLeft size={14} />
            </button>

            {totalPages <= 5 ? (
              <div className="pagination-page-pills">
                {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
                  <button
                    key={p}
                    className={`pagination-page-pill ${safePage === p ? 'active' : ''}`}
                    onClick={() => setCurrentPage(p)}
                  >
                    {p}
                  </button>
                ))}
              </div>
            ) : (
              <div className="pagination-page-indicator">
                Page <span className="pagination-page-current">{safePage}</span> of{' '}
                <span className="pagination-page-total">{totalPages}</span>
              </div>
            )}

            <button
              className="pagination-btn"
              disabled={safePage >= totalPages}
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              title="Next page"
            >
              <ChevronRight size={14} />
            </button>
            <button
              className="pagination-btn"
              disabled={safePage >= totalPages}
              onClick={() => setCurrentPage(totalPages)}
              title="Last page"
            >
              <ChevronsRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function EventRow({
  event: e,
  onSelectContainer,
}: {
  event: SecurityEvent
  onSelectContainer: (c: string) => void
}) {
  return (
    <div className="event-row">
      <span className="event-time" title={e.timestamp}>
        {relativeTime(e.timestamp)}
      </span>
      <span className="event-ip mono">{e.client_ip || '—'}</span>
      <span>
        <span className={methodBadgeClass(e.method)}>{e.method || '—'}</span>
      </span>
      <span className="event-path mono" title={e.path}>{e.path || '—'}</span>
      <span className="event-pattern mono" title={e.pattern}>{e.pattern || '—'}</span>
      <span>
        <span className={modeBadgeClass(e.response_mode || e.action)}>
          {modeLabel(e.response_mode, e.status)}
        </span>
      </span>
      <span className="event-source-cell">
        <button
          className="event-source-btn"
          onClick={(ev) => {
            ev.stopPropagation()
            if (e.source) onSelectContainer(e.source)
          }}
          title={e.source ? `Filter logs by container: ${e.source}` : 'Container name not recorded'}
        >
          {e.source || '—'}
        </button>
        <span className={pluginBadgeClass(e.plugin)}>
          {pluginLabel(e.plugin)}
        </span>
      </span>
    </div>
  )
}

function EmptyState({ filter, container }: { filter: string; container: string }) {
  const isFiltered = filter || (container && container !== 'all')
  return (
    <div className="empty-state">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
      {isFiltered ? (
        <p>
          No events match
          {container && container !== 'all' ? ` container "${container}"` : ''}
          {filter ? ` query "${filter}"` : ''}
        </p>
      ) : (
        <p>
          Waiting for security events…<br/>
          <span style={{ fontSize: 11 }}>Events will appear here as RouteWarden blocks requests.</span>
        </p>
      )}
    </div>
  )
}
