import { useState, useMemo, useEffect } from 'react'
import {
  Container, FileText, Trash2, Radio, Search, FileCode,
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight
} from 'lucide-react'
import type { Source } from '../types'
import { pluginLabel, pluginBadgeClass } from '../utils'

interface SourcesProps {
  sources: Source[]
  onClearStopped?: () => void
  onSelectSource?: (name: string) => void
  onOpenConfig?: (source: Source) => void
}

export default function Sources({ sources, onClearStopped, onSelectSource, onOpenConfig }: SourcesProps) {
  const [filter, setFilter] = useState('')
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)

  const hasInactive = sources.some(s => s.status !== 'live')

  const filtered = useMemo(() => {
    if (!filter.trim()) return sources
    const q = filter.toLowerCase().trim()
    return sources.filter(s =>
      s.name.toLowerCase().includes(q) ||
      (s.details && s.details.toLowerCase().includes(q)) ||
      (s.plugin && s.plugin.toLowerCase().includes(q)) ||
      (s.kind && s.kind.toLowerCase().includes(q)) ||
      s.status.toLowerCase().includes(q)
    )
  }, [sources, filter])

  useEffect(() => {
    setCurrentPage(1)
  }, [filter])

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize))
  const safePage = Math.min(Math.max(1, currentPage), totalPages)
  const startIndex = filtered.length === 0 ? 0 : (safePage - 1) * pageSize
  const endIndex = Math.min(startIndex + pageSize, filtered.length)

  const paginatedSources = useMemo(() => {
    return filtered.slice(startIndex, endIndex)
  }, [filtered, startIndex, endIndex])

  return (
    <div className="page">
      <div className="page-header" style={{ flexShrink: 0 }}>
        <div>
          <div className="page-title">Sources</div>
          <div className="page-subtitle">
            Active log sources — Docker containers &amp; log files
          </div>
        </div>
        <div className="header-actions">
          {sources.length > 5 && (
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <Search size={13} color="var(--text-muted)" style={{ position: 'absolute', left: 8, pointerEvents: 'none' }} />
              <input
                className="filter-input"
                style={{ paddingLeft: 26, height: 30, minWidth: 160 }}
                placeholder="Search sources…"
                value={filter}
                onChange={e => setFilter(e.target.value)}
              />
            </div>
          )}
          <span className="event-count-badge">{filtered.length} source{filtered.length !== 1 ? 's' : ''}</span>
          {hasInactive && onClearStopped && (
            <button
              className="toolbar-btn"
              onClick={onClearStopped}
              title="Clear stopped and inactive sources"
            >
              <Trash2 size={13} />
              Clear Inactive
            </button>
          )}
        </div>
      </div>

      {sources.length === 0 ? (
        <EmptySourceState />
      ) : filtered.length === 0 ? (
        <div className="empty-state" style={{ flex: 1 }}>
          <p>No sources match query "{filter}"</p>
        </div>
      ) : (
        <div className="source-list">
          {paginatedSources.map(src => (
            <SourceCard
              key={src.id}
              source={src}
              onSelectSource={onSelectSource}
              onOpenConfig={onOpenConfig}
            />
          ))}
        </div>
      )}

      {sources.length > 0 && filtered.length > 0 && (
        <div className="pagination-bar" style={{ borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)', marginTop: 8 }}>
          <div className="pagination-info">
            <span>
              Showing <strong className="text-secondary">{filtered.length === 0 ? 0 : startIndex + 1}–{endIndex}</strong> of{' '}
              <strong className="text-secondary">{filtered.length.toLocaleString()}</strong> sources
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
                title="Sources per page"
              >
                <option value={5}>5</option>
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
              </select>
            </div>
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
      )}
    </div>
  )
}

function SourceCard({
  source: s,
  onSelectSource,
  onOpenConfig,
}: {
  source: Source
  onSelectSource?: (name: string) => void
  onOpenConfig?: (source: Source) => void
}) {
  const Icon = s.kind === 'docker' ? Container : FileText

  return (
    <div className="source-card">
      <div className="source-icon">
        <Icon size={18} />
      </div>

      <div className="source-info">
        <div className="source-name">{s.name}</div>
        <div className="source-detail">{s.details || (s.kind === 'docker' ? 'Container' : 'Log file')}</div>
      </div>

      <div className="source-badges">
        <span className={pluginBadgeClass(s.plugin)}>
          {pluginLabel(s.plugin)}
        </span>

        <span className="badge" style={{
          background: 'var(--bg-elevated)',
          color: s.kind === 'docker' ? 'var(--blue)' : 'var(--yellow)',
        }}>
          {s.kind === 'docker' ? '🐳 Docker' : '📄 File'}
        </span>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div className={`source-dot ${s.status}`} />
          <span className={`source-status-${s.status}`} style={{ fontSize: 12, fontWeight: 500, textTransform: 'capitalize' }}>
            {s.status}
          </span>
        </div>

        {onOpenConfig && (
          <button
            className="source-action-btn"
            onClick={() => onOpenConfig(s)}
            title={`View RouteWarden configuration for ${s.name}`}
          >
            <FileCode size={12} />
            Config
          </button>
        )}

        {onSelectSource && (
          <button
            className="source-action-btn"
            onClick={() => onSelectSource(s.name)}
            title={`Filter live event logs for ${s.name}`}
          >
            <Radio size={12} />
            Logs
          </button>
        )}
      </div>
    </div>
  )
}

function EmptySourceState() {
  return (
    <div className="empty-state" style={{ flex: 1 }}>
      <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
        <line x1="8" y1="21" x2="16" y2="21" />
        <line x1="12" y1="17" x2="12" y2="21" />
      </svg>
      <p>No sources found</p>
      <p style={{ fontSize: 11, maxWidth: 320 }}>
        Make sure Docker is running with containers that use a RouteWarden middleware,
        or pass <code style={{ background: 'var(--bg-elevated)', padding: '1px 5px', borderRadius: 4 }}>--log</code> to specify a log file.
      </p>
    </div>
  )
}
