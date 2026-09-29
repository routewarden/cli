import { useState, useMemo, useEffect, useRef } from 'react'
import {
  Pause, Play, Trash2, Search, Container, Filter, Shield,
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight,
  ChevronDown, Copy, Check, ExternalLink, Code
} from 'lucide-react'
import type { SecurityEvent, Source } from '../types'
import {
  relativeTime, methodBadgeClass, modeBadgeClass,
  pluginBadgeClass, pluginLabel, modeLabel, filterEvents, formatBytes
} from '../utils'

interface LiveFeedProps {
  events: SecurityEvent[]
  sources: Source[]
  selectedContainer: string
  onSelectContainer: (c: string) => void
  paused: boolean
  onPause: (p: boolean) => void
  onClear: () => void
  onSelectIP?: (ip: string) => void
  filter?: string
  onFilterChange?: (f: string) => void
}

export default function LiveFeed({
  events,
  sources,
  selectedContainer,
  onSelectContainer,
  paused,
  onPause,
  onClear,
  onSelectIP,
  filter: controlledFilter,
  onFilterChange,
}: LiveFeedProps) {
  const [internalFilter, setInternalFilter] = useState('')
  const filter = controlledFilter !== undefined ? controlledFilter : internalFilter
  const handleFilterChange = (val: string) => {
    if (onFilterChange) onFilterChange(val)
    setInternalFilter(val)
  }
  const [selectedService, setSelectedService] = useState<string>('all')
  const [selectedProtocol, setSelectedProtocol] = useState<string>('all')
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const eventListRef = useRef<HTMLDivElement>(null)

  // Compute event counts per warden service
  const serviceCounts = useMemo(() => {
    const counts: Record<string, number> = {
      'all': events.length,
      'nginx-warden': 0,
      'traefik-warden': 0,
      'caddy-warden': 0,
      'tcp-warden': 0,
    }
    for (const e of events) {
      const p = (e.plugin || '').toLowerCase()
      if (p.includes('nginx')) counts['nginx-warden']++
      else if (p.includes('traefik')) counts['traefik-warden']++
      else if (p.includes('caddy')) counts['caddy-warden']++
      else if (p.includes('tcp') || e.event_kind === 'tcp' || Boolean(e.protocol)) counts['tcp-warden']++
    }
    return counts
  }, [events])

  // Build list of live container/source options with count of events
  const containerOptions = useMemo(() => {
    const liveSourceNames = new Set(sources.filter(s => s.status === 'live').map(s => s.name))
    const counts = new Map<string, number>()

    // Always include all currently known sources
    for (const s of sources) {
      if (s.name) {
        counts.set(s.name, 0)
      }
    }

    // Count events for all sources seen in event feed
    for (const e of events) {
      const src = e.source || 'unknown'
      counts.set(src, (counts.get(src) || 0) + 1)
    }

    return Array.from(counts.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
  }, [events, sources])

  // Collect available protocols
  const protocolOptions = useMemo(() => {
    const set = new Set<string>()
    for (const e of events) {
      if (e.protocol) set.add(e.protocol.toLowerCase())
      else if (e.method || e.path) set.add('http')
    }
    return Array.from(set).sort()
  }, [events])

  // Filter events by service, container, protocol, and search query
  const filtered = useMemo(() => {
    let list = events
    if (selectedService && selectedService !== 'all') {
      list = list.filter(e => {
        const p = (e.plugin || '').toLowerCase()
        if (selectedService === 'nginx-warden') return p.includes('nginx')
        if (selectedService === 'traefik-warden') return p.includes('traefik')
        if (selectedService === 'caddy-warden') return p.includes('caddy')
        if (selectedService === 'tcp-warden') return p.includes('tcp') || e.event_kind === 'tcp' || Boolean(e.protocol)
        return true
      })
    }
    if (selectedContainer && selectedContainer !== 'all') {
      list = list.filter(e => e.source === selectedContainer || e.source_id === selectedContainer)
    }
    if (selectedProtocol && selectedProtocol !== 'all') {
      if (selectedProtocol === 'http') {
        list = list.filter(e => e.event_kind === 'http' || e.method || (!e.protocol && !e.service))
      } else {
        list = list.filter(e => e.protocol?.toLowerCase() === selectedProtocol)
      }
    }
    return filterEvents(list, filter)
  }, [events, selectedService, selectedContainer, selectedProtocol, filter])

  // Reset to page 1 when filter, service, container, or protocol filter changes
  useEffect(() => {
    setCurrentPage(1)
  }, [filter, selectedService, selectedContainer, selectedProtocol])

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
          <div className="page-subtitle">Real-time security logs consolidated from NGINX, Traefik, Caddy &amp; TCP Warden</div>
        </div>
      </div>

      <div className="event-table-wrap">
        {/* Toolbar */}
        <div className="event-table-toolbar">
          <Search size={14} color="var(--text-muted)" style={{ flexShrink: 0 }} />
          <input
            className="filter-input"
            placeholder="Filter by IP, service, protocol, reason, path…"
            value={filter}
            onChange={e => handleFilterChange(e.target.value)}
          />

          {/* Service filter dropdown */}
          <div className="container-filter-wrap">
            <Shield size={13} color="var(--text-muted)" style={{ flexShrink: 0 }} />
            <select
              className="container-select"
              value={selectedService}
              onChange={e => setSelectedService(e.target.value)}
              title="Filter logs by service"
            >
              <option value="all">All Services ({serviceCounts['all']})</option>
              <option value="nginx-warden">NGINX Warden ({serviceCounts['nginx-warden']})</option>
              <option value="traefik-warden">Traefik Warden ({serviceCounts['traefik-warden']})</option>
              <option value="caddy-warden">Caddy Warden ({serviceCounts['caddy-warden']})</option>
              <option value="tcp-warden">TCP Warden ({serviceCounts['tcp-warden']})</option>
            </select>
            {selectedService !== 'all' && (
              <button
                className="clear-filter-btn"
                onClick={() => setSelectedService('all')}
                title="Clear service filter"
              >
                ×
              </button>
            )}
          </div>

          {/* Container filter dropdown */}
          <div className="container-filter-wrap">
            <Container size={13} color="var(--text-muted)" style={{ flexShrink: 0 }} />
            <select
              className="container-select"
              value={selectedContainer}
              onChange={e => onSelectContainer(e.target.value)}
              title="Filter logs by container"
            >
              <option value="all">All Sources ({events.length})</option>
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
                title="Clear source filter"
              >
                ×
              </button>
            )}
          </div>

          {/* Protocol filter dropdown */}
          {protocolOptions.length > 0 && (
            <div className="container-filter-wrap">
              <Filter size={13} color="var(--text-muted)" style={{ flexShrink: 0 }} />
              <select
                className="container-select"
                value={selectedProtocol}
                onChange={e => setSelectedProtocol(e.target.value)}
                title="Filter by protocol"
              >
                <option value="all">All Protocols</option>
                <option value="http">HTTP</option>
                {protocolOptions.filter(p => p !== 'http').map(p => (
                  <option key={p} value={p}>{p.toUpperCase()}</option>
                ))}
              </select>
              {selectedProtocol !== 'all' && (
                <button
                  className="clear-filter-btn"
                  onClick={() => setSelectedProtocol('all')}
                  title="Clear protocol filter"
                >
                  ×
                </button>
              )}
            </div>
          )}

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
            <span className="col-head">Client IP</span>
            <span className="col-head">Proto / Method</span>
            <span className="col-head">Service / Path</span>
            <span className="col-head">Details / Pattern / Reason</span>
            <span className="col-head">Action</span>
            <span className="col-head">Source / Gateway</span>
            <span className="col-head" style={{ textAlign: 'center' }}></span>
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
                  onSelectIP={onSelectIP}
                  onSelectService={setSelectedService}
                  onFilterByPath={(p) => handleFilterChange(p)}
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
  onSelectIP,
  onSelectService,
  onFilterByPath,
}: {
  event: SecurityEvent
  onSelectContainer: (c: string) => void
  onSelectIP?: (ip: string) => void
  onSelectService?: (s: string) => void
  onFilterByPath?: (p: string) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)
  const [showRawJson, setShowRawJson] = useState(false)

  const isTCP = e.event_kind === 'tcp' || (!e.method && (Boolean(e.service) || Boolean(e.protocol)))

  const handleCopyJSON = () => {
    navigator.clipboard.writeText(JSON.stringify(e, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const detailText = isTCP
    ? (e.reason ? e.reason : (
        (e.bytes_in !== undefined || e.bytes_out !== undefined)
          ? `↓${formatBytes(e.bytes_in || 0)} ↑${formatBytes(e.bytes_out || 0)}${e.duration_ms ? ` (${e.duration_ms}ms)` : ''}`
          : '—'
      ))
    : (e.pattern || '—')

  return (
    <div className={`event-row-container ${expanded ? 'expanded' : ''}`}>
      <div
        className="event-row"
        onClick={() => setExpanded(!expanded)}
        title="Click row to expand / view complete details"
      >
        {/* Col 1: Time */}
        <span className="event-time" title={e.timestamp}>
          {relativeTime(e.timestamp)}
        </span>

        {/* Col 2: Client IP */}
        <span className="event-ip mono" title={e.country_name ? `${e.client_ip} (${e.country_name})` : e.client_ip}>
          {e.flag_emoji && (
            <span className="event-flag" title={e.country_name || e.country_code}>
              {e.flag_emoji}
            </span>
          )}
          {onSelectIP && e.client_ip ? (
            <button
              className="event-ip-btn"
              onClick={(ev) => {
                ev.stopPropagation()
                onSelectIP(e.client_ip)
              }}
              title={`View complete intelligence for ${e.client_ip}`}
            >
              {e.client_ip}
            </button>
          ) : (
            <span className="event-ip-addr">{e.client_ip || '—'}</span>
          )}
        </span>

        {/* Col 3: Proto / Method */}
        <span>
          {isTCP ? (
            <span className="badge badge-plugin-tcp" style={{ textTransform: 'uppercase' }}>
              {e.protocol || 'TCP'}
            </span>
          ) : (
            <span className={methodBadgeClass(e.method)}>{e.method || '—'}</span>
          )}
        </span>

        {/* Col 4: Service / Path */}
        <span className="event-path mono" title={isTCP ? (e.service || '—') : (e.path || '—')}>
          {isTCP ? (e.service || '—') : (e.path || '—')}
        </span>

        {/* Col 5: Details / Pattern / Reason */}
        <span
          className={`event-pattern mono ${isTCP && e.reason ? 'text-red' : ''}`}
          title={detailText}
        >
          {detailText}
        </span>

        {/* Col 6: Action */}
        <span>
          <span className={modeBadgeClass(e.action || e.response_mode)}>
            {isTCP
              ? (e.action ? (e.action === 'blocked' ? 'Blocked' : e.action === 'allowed' ? 'Allowed' : e.action) : (e.response_mode || 'TCP'))
              : modeLabel(e.response_mode, e.status)
            }
          </span>
        </span>

        {/* Col 7: Source / Gateway */}
        <span className="event-source-cell">
          <button
            className="event-source-btn"
            onClick={(ev) => {
              ev.stopPropagation()
              if (e.source) onSelectContainer(e.source)
            }}
            title={e.source ? `Filter logs by container/source: ${e.source}` : 'Source not recorded'}
          >
            {e.source || '—'}
          </button>
          <button
            className={pluginBadgeClass(e.plugin)}
            style={{ cursor: onSelectService ? 'pointer' : 'default', border: 'none', font: 'inherit' }}
            onClick={(ev) => {
              if (!onSelectService) return
              ev.stopPropagation()
              const p = (e.plugin || '').toLowerCase()
              if (p.includes('nginx')) onSelectService('nginx-warden')
              else if (p.includes('traefik')) onSelectService('traefik-warden')
              else if (p.includes('caddy')) onSelectService('caddy-warden')
              else if (p.includes('tcp') || isTCP) onSelectService('tcp-warden')
            }}
            title={onSelectService ? `Filter logs by ${pluginLabel(e.plugin)}` : pluginLabel(e.plugin)}
          >
            {pluginLabel(e.plugin)}
          </button>
        </span>

        {/* Col 8: Expand toggle icon */}
        <span className="event-expand-cell">
          <ChevronDown size={14} className={`event-expand-icon ${expanded ? 'rotated' : ''}`} />
        </span>
      </div>

      {/* Expanded Details Drawer */}
      {expanded && (
        <div className="event-expanded-panel">
          <div className="event-expanded-header">
            <div className="event-expanded-title">
              <span className="event-expanded-tag">EVENT DETAILS</span>
              <span className="mono text-muted" style={{ fontSize: 11 }}>{e.timestamp}</span>
            </div>
            <div className="event-expanded-actions">
              {onSelectIP && e.client_ip && (
                <button
                  className="toolbar-btn btn-xs"
                  onClick={(ev) => {
                    ev.stopPropagation()
                    onSelectIP(e.client_ip)
                  }}
                  title="Open Deep IP Intelligence page for this IP"
                >
                  <ExternalLink size={12} />
                  <span>Inspect IP</span>
                </button>
              )}
              {onFilterByPath && (e.path || e.service) && (
                <button
                  className="toolbar-btn btn-xs"
                  onClick={(ev) => {
                    ev.stopPropagation()
                    onFilterByPath(isTCP ? (e.service || '') : (e.path || ''))
                  }}
                  title="Filter feed by this endpoint / service"
                >
                  <Filter size={12} />
                  <span>Filter by {isTCP ? 'Service' : 'Path'}</span>
                </button>
              )}
              <button
                className="toolbar-btn btn-xs"
                onClick={(ev) => {
                  ev.stopPropagation()
                  setShowRawJson(!showRawJson)
                }}
                title="Toggle raw JSON snippet"
              >
                <Code size={12} />
                <span>{showRawJson ? 'Hide JSON' : 'JSON'}</span>
              </button>
              <button
                className="toolbar-btn btn-xs"
                onClick={(ev) => {
                  ev.stopPropagation()
                  handleCopyJSON()
                }}
                title="Copy full event JSON to clipboard"
              >
                {copied ? <Check size={12} color="var(--green)" /> : <Copy size={12} />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          {/* Full Reason / Alert Banner */}
          {(e.reason || e.pattern) && (
            <div className={`event-expanded-alert ${isTCP ? 'alert-tcp' : 'alert-http'}`}>
              <div className="event-expanded-alert-label">
                {isTCP ? 'REASON / DIAGNOSTIC:' : 'MATCHED PATTERN / RULE:'}
              </div>
              <div className="event-expanded-alert-val mono select-all">
                {e.reason || e.pattern}
              </div>
            </div>
          )}

          {/* Detailed Metadata Grid */}
          <div className="event-expanded-grid">
            <div className="expanded-field">
              <span className="expanded-label">Client IP</span>
              <div className="expanded-val mono">
                <span>{e.flag_emoji || '🌐'} {e.client_ip || '—'}</span>
                {e.country_name && <span className="text-muted" style={{ fontSize: 11 }}>({e.country_name})</span>}
              </div>
            </div>

            <div className="expanded-field">
              <span className="expanded-label">Protocol / Kind</span>
              <div className="expanded-val">
                <span className="badge badge-plugin-tcp" style={{ textTransform: 'uppercase' }}>
                  {e.protocol || e.method || 'TCP'}
                </span>
                {e.event_kind && <span className="badge badge-method-other" style={{ textTransform: 'uppercase' }}>{e.event_kind}</span>}
              </div>
            </div>

            <div className="expanded-field">
              <span className="expanded-label">{isTCP ? 'Service Name' : 'Request URI / Path'}</span>
              <div className="expanded-val mono select-all text-break">
                {isTCP ? (e.service || '—') : (e.path || '—')}
              </div>
            </div>

            <div className="expanded-field">
              <span className="expanded-label">Enforcement Action</span>
              <div className="expanded-val">
                <span className={modeBadgeClass(e.action || e.response_mode)}>
                  {e.action || e.response_mode || 'blocked'}
                </span>
                {e.status && <span className="badge badge-method-other">HTTP {e.status}</span>}
              </div>
            </div>

            <div className="expanded-field">
              <span className="expanded-label">Network Traffic</span>
              <div className="expanded-val mono" style={{ fontSize: 11 }}>
                {e.bytes_in !== undefined || e.bytes_out !== undefined ? (
                  <span>↓ {formatBytes(e.bytes_in || 0)} &nbsp;|&nbsp; ↑ {formatBytes(e.bytes_out || 0)}</span>
                ) : '—'}
                {e.duration_ms ? <span className="text-muted" style={{ marginLeft: 6 }}>({e.duration_ms}ms latency)</span> : null}
              </div>
            </div>

            <div className="expanded-field">
              <span className="expanded-label">Source Container</span>
              <div className="expanded-val mono" style={{ fontSize: 11 }}>
                <span>{e.source || '—'}</span>
                {e.source_id && <span className="text-muted" style={{ marginLeft: 4 }} title={e.source_id}>({e.source_id.slice(0, 12)})</span>}
                {e.plugin && <span className={pluginBadgeClass(e.plugin)} style={{ marginLeft: 6 }}>{pluginLabel(e.plugin)}</span>}
              </div>
            </div>
          </div>

          {/* Raw JSON viewer */}
          {showRawJson && (
            <pre className="event-raw-json mono select-all">
              {JSON.stringify(e, null, 2)}
            </pre>
          )}
        </div>
      )}
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
