import { useState, useEffect } from 'react'
import {
  X, Copy, Check, Shield, FileCode, CheckCircle2,
  AlertCircle, ExternalLink, Terminal, Code2, Layers
} from 'lucide-react'
import type { ConfigResponse } from '../types'
import { pluginBadgeClass, pluginLabel, modeBadgeClass, modeLabel } from '../utils'

interface ConfigDrawerProps {
  sourceId: string | null
  sourceName?: string
  sourcePlugin?: string
  sourceKind?: string
  onClose: () => void
}

export default function ConfigDrawer({
  sourceId,
  sourceName,
  sourcePlugin,
  sourceKind,
  onClose,
}: ConfigDrawerProps) {
  const [data, setData] = useState<ConfigResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'summary' | 'raw'>('summary')
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!sourceId) return

    setLoading(true)
    setData(null)
    setActiveTab('summary')

    fetch(`/api/config/${encodeURIComponent(sourceId)}`)
      .then(res => res.json())
      .then((resData: ConfigResponse) => {
        setData(resData)
        setLoading(false)
      })
      .catch(err => {
        setData({
          id: sourceId,
          name: sourceName || sourceId,
          kind: sourceKind || 'docker',
          has_config: false,
          error: `Failed to fetch configuration: ${err.message}`,
        })
        setLoading(false)
      })
  }, [sourceId, sourceName, sourceKind])

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  if (!sourceId) return null

  const handleCopy = () => {
    if (!data?.raw) return
    let textToCopy = data.raw
    try {
      // Pretty-print JSON if valid
      textToCopy = JSON.stringify(JSON.parse(data.raw), null, 2)
    } catch {}
    navigator.clipboard.writeText(textToCopy).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const cfg = data?.config
  const displayName = data?.name || sourceName || sourceId

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-panel" onClick={e => e.stopPropagation()}>
        {/* Drawer Header */}
        <div className="drawer-header">
          <div className="drawer-title-group">
            <div className="drawer-title">
              <FileCode size={18} className="drawer-title-icon" />
              <span>Configuration</span>
              {sourcePlugin && (
                <span className={pluginBadgeClass(sourcePlugin)}>
                  {pluginLabel(sourcePlugin)}
                </span>
              )}
            </div>
            <div className="drawer-subtitle">
              <span className="mono">{displayName}</span>
              {data?.id && data.id !== displayName && (
                <span className="drawer-id-chip mono">{data.id}</span>
              )}
            </div>
          </div>

          <button className="drawer-close-btn" onClick={onClose} title="Close (Esc)">
            <X size={18} />
          </button>
        </div>

        {/* Loading state */}
        {loading && (
          <div className="drawer-body drawer-loading">
            <div className="spinner" />
            <p>Inspecting container metadata &amp; reading routewarden.json label…</p>
          </div>
        )}

        {/* Content state */}
        {!loading && data && (
          <>
            {/* Tabs (only when config is available) */}
            {data.has_config && (
              <div className="drawer-tabs">
                <button
                  className={`drawer-tab ${activeTab === 'summary' ? 'active' : ''}`}
                  onClick={() => setActiveTab('summary')}
                >
                  <Layers size={14} />
                  Summary View
                </button>
                <button
                  className={`drawer-tab ${activeTab === 'raw' ? 'active' : ''}`}
                  onClick={() => setActiveTab('raw')}
                >
                  <Code2 size={14} />
                  Raw JSON
                </button>

                <div className="drawer-tab-actions">
                  <button
                    className="toolbar-btn text-sm"
                    onClick={handleCopy}
                    title="Copy formatted JSON to clipboard"
                  >
                    {copied ? <Check size={13} color="var(--green)" /> : <Copy size={13} />}
                    {copied ? 'Copied' : 'Copy JSON'}
                  </button>
                </div>
              </div>
            )}

            <div className="drawer-body">
              {data.has_config && cfg && activeTab === 'summary' && (
                <div className="config-summary">
                  {/* Status Banner */}
                  <div className="config-banner">
                    <div className="config-banner-left">
                      <div className="config-status-indicator">
                        <CheckCircle2 size={16} color="var(--green)" />
                        <span className="config-status-label">
                          {cfg.enabled !== false ? 'RouteWarden Active' : 'RouteWarden Disabled'}
                        </span>
                      </div>
                      <div className="config-banner-meta">
                        Source: <span className="mono">{data.label_key || 'routewarden.json'}</span>
                      </div>
                    </div>

                    {cfg.response?.mode && (
                      <span className={modeBadgeClass(cfg.response.mode)}>
                        Response: {modeLabel(cfg.response.mode, cfg.response.statusCode)}
                      </span>
                    )}
                  </div>

                  {/* Response settings card */}
                  {cfg.response && (
                    <div className="config-section card">
                      <div className="config-section-title">
                        <Shield size={14} />
                        Defense &amp; Response Action
                      </div>
                      <div className="config-grid-2">
                        <div className="config-prop">
                          <span className="config-prop-label">Action Mode</span>
                          <span className="config-prop-val mono">
                            {cfg.response.mode || 'block'}
                          </span>
                        </div>
                        <div className="config-prop">
                          <span className="config-prop-label">HTTP Status Code</span>
                          <span className="config-prop-val mono">
                            {cfg.response.statusCode || 403}
                          </span>
                        </div>
                      </div>
                      {cfg.response.body && (
                        <div className="config-prop" style={{ marginTop: 10 }}>
                          <span className="config-prop-label">Custom Block Body</span>
                          <pre className="config-code-block">{cfg.response.body}</pre>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Path Patterns card */}
                  <div className="config-section card">
                    <div className="config-section-header">
                      <div className="config-section-title">
                        <Terminal size={14} />
                        Blocked Path Patterns (pathPatterns)
                      </div>
                      <span className="event-count-badge">
                        {cfg.pathPatterns?.length ?? 0}
                      </span>
                    </div>

                    {(!cfg.pathPatterns || cfg.pathPatterns.length === 0) ? (
                      <p className="text-muted text-sm">No custom path patterns defined. Using default patterns.</p>
                    ) : (
                      <div className="config-pattern-list">
                        {cfg.pathPatterns.map((pat: string, i: number) => (
                          <div key={i} className="config-pattern-item mono">
                            <span className="config-pattern-index">{i + 1}</span>
                            <span className="config-pattern-text">{pat}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Allow Patterns card */}
                  {cfg.allowPatterns && cfg.allowPatterns.length > 0 && (
                    <div className="config-section card">
                      <div className="config-section-header">
                        <div className="config-section-title" style={{ color: 'var(--green)' }}>
                          <CheckCircle2 size={14} />
                          Whitelist Exceptions (allowPatterns)
                        </div>
                        <span className="event-count-badge">
                          {cfg.allowPatterns.length}
                        </span>
                      </div>
                      <div className="config-pattern-list">
                        {cfg.allowPatterns.map((pat: string, i: number) => (
                          <div key={i} className="config-pattern-item allow mono">
                            <span className="config-pattern-index">{i + 1}</span>
                            <span className="config-pattern-text">{pat}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Allowed IPs card */}
                  {cfg.allowedIps && cfg.allowedIps.length > 0 && (
                    <div className="config-section card">
                      <div className="config-section-header">
                        <div className="config-section-title">
                          Allowed IP Addresses &amp; CIDRs
                        </div>
                        <span className="event-count-badge">{cfg.allowedIps.length}</span>
                      </div>
                      <div className="config-chips">
                        {cfg.allowedIps.map((ip: string, i: number) => (
                          <span key={i} className="config-chip mono">{ip}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Methods & Inspection */}
                  <div className="config-section card">
                    <div className="config-section-title">Inspection Settings</div>
                    <div className="config-grid-2">
                      <div className="config-prop">
                        <span className="config-prop-label">Inspected HTTP Methods</span>
                        <div className="config-chips" style={{ marginTop: 4 }}>
                          {cfg.methods?.length ? (
                            cfg.methods.map((m: string) => (
                              <span key={m} className="config-chip mono">{m}</span>
                            ))
                          ) : (
                            <span className="text-muted text-sm">All methods (default)</span>
                          )}
                        </div>
                      </div>
                      <div className="config-prop">
                        <span className="config-prop-label">Query Inspection</span>
                        <span className="config-prop-val">
                          {cfg.checkQuery !== false ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>
                    </div>

                    {cfg.checkHeaders && cfg.checkHeaders.length > 0 && (
                      <div className="config-prop" style={{ marginTop: 10 }}>
                        <span className="config-prop-label">Custom Inspected Headers</span>
                        <div className="config-chips" style={{ marginTop: 4 }}>
                          {cfg.checkHeaders.map((h: string) => (
                            <span key={h} className="config-chip mono">{h}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Raw JSON tab */}
              {data.has_config && activeTab === 'raw' && (
                <div className="config-raw-view">
                  <pre className="config-raw-pre mono">
                    {formatJSON(data.raw || JSON.stringify(data.config))}
                  </pre>
                </div>
              )}

              {/* No config found state */}
              {!data.has_config && (
                <div className="config-empty">
                  <div className="config-empty-icon">
                    <AlertCircle size={32} color="var(--yellow)" />
                  </div>
                  <h3 className="config-empty-title">
                    No <span className="mono">routewarden.json</span> Label Found
                  </h3>
                  <p className="config-empty-desc">
                    {data.error || `Container "${displayName}" has no RouteWarden configuration attached.`}
                  </p>

                  <div className="config-instructions card">
                    <div className="config-instructions-title">
                      How to attach a configuration to this container:
                    </div>

                    <div className="config-instruction-block">
                      <span className="instruction-step">Option 1: Docker Run CLI</span>
                      <pre className="instruction-code mono">
{`docker run -d \\
  --label routewarden=true \\
  --label routewarden.json='{
    "enabled": true,
    "pathPatterns": ["(?i)^/admin/secret.*$"],
    "response": { "mode": "tarpit", "statusCode": 403 }
  }' \\
  ${sourcePlugin || 'traefik:v3.0'}`}
                      </pre>
                    </div>

                    <div className="config-instruction-block">
                      <span className="instruction-step">Option 2: Docker Compose (docker-compose.yml)</span>
                      <pre className="instruction-code mono">
{`services:
  ${displayName}:
    image: ${sourcePlugin || 'traefik:v3.0'}
    labels:
      - "routewarden=true"
      - "routewarden.json={\\"enabled\\":true,\\"pathPatterns\\":[\\"(?i)^/admin/secret.*$\\"]}"`}
                      </pre>
                    </div>

                    <div className="config-instruction-block">
                      <span className="instruction-step">Option 3: Dockerfile</span>
                      <pre className="instruction-code mono">
{`LABEL routewarden.json="{\\"enabled\\":true,\\"response\\":{\\"mode\\":\\"tarpit\\"}}"`}
                      </pre>
                    </div>

                    <div style={{ marginTop: 12, fontSize: 11, color: 'var(--text-muted)' }}>
                      💡 Once set, restart or run the container. The RouteWarden dashboard will automatically detect the configuration in real time.
                    </div>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function formatJSON(raw: string | undefined): string {
  if (!raw) return '// No configuration data'
  try {
    const parsed = JSON.parse(raw)
    return JSON.stringify(parsed, null, 2)
  } catch {
    return raw
  }
}
