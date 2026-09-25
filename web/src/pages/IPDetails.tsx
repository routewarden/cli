import { useState, useEffect, useMemo } from 'react'
import {
  ArrowLeft,
  Search,
  Copy,
  Check,
  Radio,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Home,
  MapPin,
  Server,
  Activity,
  Layers,
  Clock,
  RefreshCw,
  ChevronsLeft,
  ChevronLeft,
  ChevronRight,
  ChevronsRight,
} from 'lucide-react'
import type { IPDetailsResponse, SecurityEvent } from '../types'
import {
  relativeTime,
  methodBadgeClass,
  modeBadgeClass,
  modeLabel,
  pluginBadgeClass,
  pluginLabel,
} from '../utils'

interface IPDetailsProps {
  ip: string
  onBack: () => void
  onSelectContainer?: (container: string) => void
  onFilterInFeed?: (ip: string) => void
  recentEvents?: SecurityEvent[]
  onSelectIP?: (ip: string) => void
}

export default function IPDetails({
  ip: initialIP,
  onBack,
  onSelectContainer,
  onFilterInFeed,
  recentEvents = [],
  onSelectIP,
}: IPDetailsProps) {
  const [currentIP, setCurrentIP] = useState<string>(initialIP || '127.0.0.1')
  const [searchInput, setSearchInput] = useState<string>(initialIP || '')
  const [data, setData] = useState<IPDetailsResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState<boolean>(false)

  // Internal log event table search & pagination
  const [tableFilter, setTableFilter] = useState<string>('')
  const [pageSize, setPageSize] = useState<number>(25)
  const [currentPage, setCurrentPage] = useState<number>(1)

  // Update currentIP if initialIP prop changes
  useEffect(() => {
    if (initialIP && initialIP !== currentIP) {
      setCurrentIP(initialIP)
      setSearchInput(initialIP)
    }
  }, [initialIP])

  // Fetch IP details from backend with smart fallback
  const fetchIPDetails = async (targetIP: string) => {
    if (!targetIP) return
    setLoading(true)
    setError(null)
    try {
      // 1. Try GET /api/ip/:ip
      let resp = await fetch(`/api/ip/${encodeURIComponent(targetIP)}`)
      if (resp.status === 404) {
        // Try GET /api/ip?ip=...
        const queryResp = await fetch(`/api/ip?ip=${encodeURIComponent(targetIP)}`)
        if (queryResp.ok) {
          resp = queryResp
        }
      }

      if (resp.ok) {
        const json: IPDetailsResponse = await resp.json()
        setData(json)
        setCurrentPage(1)
        return
      }

      // If backend returned 404 (e.g. running daemon has not been restarted yet),
      // gracefully resolve via /api/geoip and compute intelligence from local events.
      if (resp.status === 404) {
        const lower = targetIP.trim().toLowerCase()
        const parts = lower.split('.').map(Number)
        const isCgnatVpn = parts.length === 4 && parts[0] === 100 && (parts[1] & 0xc0) === 64
        const isTailscaleV6 = lower.startsWith('fd7a:115c:a1e0:')
        const isNetbirdV6 = lower.startsWith('fd00:') || (lower.startsWith('fd') && !isTailscaleV6)
        const isVpn = isCgnatVpn || isTailscaleV6 || isNetbirdV6

        let geoData: any = {
          ip: targetIP,
          country_code: isVpn ? 'VPN' : 'XX',
          country_name: isVpn
            ? isTailscaleV6
              ? 'Tailscale Mesh IPv6'
              : isNetbirdV6
              ? 'NetBird Mesh IPv6'
              : parts[1] === 64
              ? 'NetBird / Tailscale Mesh'
              : 'Tailscale / NetBird Mesh'
            : 'Public IP',
          flag_emoji: isVpn ? '🔒' : '🌐',
          region: isVpn
            ? isTailscaleV6
              ? 'Tailscale IPv6 Overlay (fd7a:115c:a1e0::/48)'
              : isNetbirdV6
              ? 'NetBird IPv6 Overlay (fd00::/8 ULA)'
              : 'Mesh Overlay Network (100.64.0.0/10)'
            : undefined,
          isp: isVpn
            ? isTailscaleV6
              ? 'Tailscale WireGuard Mesh'
              : isNetbirdV6
              ? 'NetBird WireGuard Overlay'
              : 'Tailscale / NetBird WireGuard Mesh'
            : undefined,
          is_private: isVpn,
        }

        try {
          const geoResp = await fetch(`/api/geoip?ip=${encodeURIComponent(targetIP)}`)
          if (geoResp.ok) {
            const g = await geoResp.json()
            geoData = { ...geoData, ...g }
          }
        } catch {
          // ignore geo fetch error
        }

        // Aggregate from recentEvents
        const matched = recentEvents.filter(e => e.client_ip === targetIP)
        const pathCounts: Record<string, number> = {}
        const methodCounts: Record<string, number> = {}
        const patternCounts: Record<string, number> = {}
        const modeCounts: Record<string, number> = {}
        const sourceCounts: Record<string, number> = {}

        let firstSeen: string | undefined
        let lastSeen: string | undefined
        let hasExploit = false

        for (const e of matched) {
          if (!firstSeen || new Date(e.timestamp) < new Date(firstSeen)) firstSeen = e.timestamp
          if (!lastSeen || new Date(e.timestamp) > new Date(lastSeen)) lastSeen = e.timestamp

          if (e.path) pathCounts[e.path] = (pathCounts[e.path] || 0) + 1
          if (e.method) methodCounts[e.method] = (methodCounts[e.method] || 0) + 1
          if (e.pattern) patternCounts[e.pattern] = (patternCounts[e.pattern] || 0) + 1
          const mode = e.response_mode || e.action || 'block'
          modeCounts[mode] = (modeCounts[mode] || 0) + 1
          const src = e.source || e.plugin || 'unknown'
          sourceCounts[src] = (sourceCounts[src] || 0) + 1

          const lp = (e.path || '').toLowerCase()
          const lpat = (e.pattern || '').toLowerCase()
          if (
            lp.includes('.env') ||
            lp.includes('wp-') ||
            lp.includes('passwd') ||
            lpat.includes('sqli') ||
            lpat.includes('rce')
          ) {
            hasExploit = true
          }
        }

        const toCountEntries = (m: Record<string, number>) =>
          Object.entries(m)
            .map(([label, count]) => ({ label, count }))
            .sort((a, b) => b.count - a.count)

        const totalEvents = matched.length
        let riskScore: 'critical' | 'high' | 'medium' | 'low' = 'low'
        let riskReason = 'No security events recorded for this IP address.'

        if (totalEvents > 0) {
          if (hasExploit || totalEvents >= 50) {
            riskScore = 'critical'
            riskReason = hasExploit
              ? 'Detected targeted exploitation attempts (e.g. sensitive files, SQLi/RCE, or path traversal).'
              : `Excessive malicious request volume (${totalEvents} blocked requests).`
          } else if (totalEvents >= 15) {
            riskScore = 'high'
            riskReason = `Repeated attack signatures detected across multiple endpoints (${totalEvents} events).`
          } else if (totalEvents >= 3) {
            riskScore = 'medium'
            riskReason = `Multiple reconnaissance probes or policy violations detected (${totalEvents} events).`
          } else {
            riskScore = 'low'
            riskReason = 'Isolated suspicious request blocked by RouteWarden.'
          }
        }

        setData({
          ip: targetIP,
          geo: geoData,
          total_events: totalEvents,
          first_seen: firstSeen,
          last_seen: lastSeen,
          risk_score: riskScore,
          risk_reason: riskReason,
          top_paths: toCountEntries(pathCounts).slice(0, 8),
          top_methods: toCountEntries(methodCounts).slice(0, 8),
          top_patterns: toCountEntries(patternCounts).slice(0, 8),
          response_modes: toCountEntries(modeCounts).slice(0, 8),
          target_sources: toCountEntries(sourceCounts).slice(0, 8),
          events: matched,
        })
        setCurrentPage(1)
        return
      }

      throw new Error(`Failed to load details for ${targetIP} (HTTP ${resp.status})`)
    } catch (err: any) {
      setError(err?.message || 'Error fetching IP details')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (currentIP) {
      fetchIPDetails(currentIP)
    }
  }, [currentIP])

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const clean = searchInput.trim()
    if (clean && clean !== currentIP) {
      setCurrentIP(clean)
      if (onSelectIP) onSelectIP(clean)
    }
  }

  const handleCopy = () => {
    if (!currentIP) return
    navigator.clipboard.writeText(currentIP)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Extract unique recent IPs for quick-switch suggestions
  const recentUniqueIPs = useMemo(() => {
    const set = new Set<string>()
    const list: string[] = []
    for (const ev of recentEvents) {
      if (ev.client_ip && !set.has(ev.client_ip)) {
        set.add(ev.client_ip)
        list.push(ev.client_ip)
        if (list.length >= 10) break
      }
    }
    return list
  }, [recentEvents])

  // Filter events inside this IP view
  const events = data?.events ?? []
  const filteredEvents = useMemo(() => {
    if (!tableFilter.trim()) return events
    const q = tableFilter.toLowerCase()
    return events.filter(
      e =>
        e.path?.toLowerCase().includes(q) ||
        e.pattern?.toLowerCase().includes(q) ||
        e.method?.toLowerCase().includes(q) ||
        e.source?.toLowerCase().includes(q) ||
        e.response_mode?.toLowerCase().includes(q)
    )
  }, [events, tableFilter])

  // Pagination calculations
  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / pageSize))
  const safePage = Math.min(currentPage, totalPages)
  const startIndex = (safePage - 1) * pageSize
  const endIndex = Math.min(startIndex + pageSize, filteredEvents.length)
  const paginatedEvents = filteredEvents.slice(startIndex, endIndex)

  const riskBadge = (score: string) => {
    switch (score) {
      case 'critical':
        return (
          <span className="risk-badge risk-critical">
            <ShieldAlert size={14} /> Critical Threat
          </span>
        )
      case 'high':
        return (
          <span className="risk-badge risk-high">
            <AlertTriangle size={14} /> High Risk
          </span>
        )
      case 'medium':
        return (
          <span className="risk-badge risk-medium">
            <AlertTriangle size={14} /> Suspicious
          </span>
        )
      default:
        return (
          <span className="risk-badge risk-low">
            <ShieldCheck size={14} /> Low Threat
          </span>
        )
    }
  }

  return (
    <div className="page ip-details-page">
      {/* ── Top Navigation & Search Bar ── */}
      <div className="ip-header-bar">
        <div className="ip-header-left">
          <button className="back-btn" onClick={onBack} title="Back to Feed / Statistics">
            <ArrowLeft size={16} />
            <span>Back</span>
          </button>
          <div>
            <h1 className="page-title" style={{ fontSize: 20 }}>IP Intelligence</h1>
            <div className="page-subtitle">Deep dive network & threat analysis</div>
          </div>
        </div>

        {/* Quick IP Switcher Search */}
        <form className="ip-search-form" onSubmit={handleSearchSubmit}>
          <Search size={14} className="ip-search-icon" />
          <input
            className="ip-search-input mono"
            placeholder="Inspect any IP address…"
            value={searchInput}
            onChange={e => setSearchInput(e.target.value)}
          />
          <button type="submit" className="ip-search-btn">
            Inspect
          </button>
        </form>
      </div>

      {/* Quick recent IP chips */}
      {recentUniqueIPs.length > 0 && (
        <div className="recent-ip-chips-bar">
          <span className="recent-ip-chips-label">Recent Active IPs:</span>
          <div className="recent-ip-chips-list">
            {recentUniqueIPs.map(ipAddr => (
              <button
                key={ipAddr}
                className={`ip-chip ${ipAddr === currentIP ? 'active' : ''}`}
                onClick={() => {
                  setSearchInput(ipAddr)
                  setCurrentIP(ipAddr)
                  if (onSelectIP) onSelectIP(ipAddr)
                }}
              >
                {ipAddr}
              </button>
            ))}
          </div>
        </div>
      )}

      {loading && !data && (
        <div className="ip-loading-state">
          <RefreshCw size={24} className="spin-icon" />
          <span>Resolving geolocation and aggregating intelligence for {currentIP}…</span>
        </div>
      )}

      {error && (
        <div className="card ip-error-card">
          <AlertTriangle size={20} color="var(--red)" />
          <div>
            <strong>Error loading details:</strong> {error}
          </div>
          <button className="toolbar-btn" onClick={() => fetchIPDetails(currentIP)}>
            Retry
          </button>
        </div>
      )}

      {data && (
        <>
          {/* ── Hero Identity & Threat Card ── */}
          <div className="card ip-hero-card">
            <div className="ip-hero-top">
              <div className="ip-hero-identity">
                <span className="ip-hero-flag">{data.geo.flag_emoji || '🌐'}</span>
                <div>
                  <div className="ip-hero-address mono">
                    {data.ip}
                    <button
                      className="ip-copy-btn"
                      onClick={handleCopy}
                      title="Copy IP Address"
                    >
                      {copied ? <Check size={14} color="var(--green)" /> : <Copy size={14} />}
                      <span className="ip-copy-text">{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className="ip-hero-geo-line">
                    <span>
                      {data.geo.country_name || 'Unknown Country'}
                      {data.geo.country_code ? ` (${data.geo.country_code})` : ''}
                    </span>
                    {data.geo.city && <span>• {data.geo.city}</span>}
                    {data.geo.region && <span>• {data.geo.region}</span>}
                  </div>
                </div>
              </div>

              <div className="ip-hero-badges">
                {riskBadge(data.risk_score)}
                {data.geo.is_private ? (
                  <span className="net-type-badge net-private">
                    <Home size={13} /> Private Network
                  </span>
                ) : (
                  <span className="net-type-badge net-public">
                    <Globe size={13} /> Public Internet
                  </span>
                )}
              </div>
            </div>

            {/* Threat description banner */}
            <div className={`ip-threat-banner risk-border-${data.risk_score}`}>
              <div className="ip-threat-title">Threat Assessment:</div>
              <div className="ip-threat-reason">{data.risk_reason}</div>
            </div>

            {/* Quick Actions Row */}
            <div className="ip-actions-row">
              {onFilterInFeed && (
                <button
                  className="toolbar-btn primary-action-btn"
                  onClick={() => onFilterInFeed(data.ip)}
                  title="View and filter all requests from this IP in the Live Feed"
                >
                  <Radio size={13} /> Filter in Live Feed
                </button>
              )}
              <button
                className="toolbar-btn"
                onClick={() => fetchIPDetails(currentIP)}
                title="Refresh metrics and geolocation"
              >
                <RefreshCw size={13} /> Refresh
              </button>
              {!data.geo.is_private && (
                <>
                  <a
                    href={`https://www.abuseipdb.com/check/${data.ip}`}
                    target="_blank"
                    rel="noreferrer"
                    className="toolbar-btn link-action-btn"
                    title="Check reputation on AbuseIPDB"
                  >
                    <span>AbuseIPDB</span>
                    <ExternalLink size={12} />
                  </a>
                  <a
                    href={`https://www.virustotal.com/gui/ip-address/${data.ip}`}
                    target="_blank"
                    rel="noreferrer"
                    className="toolbar-btn link-action-btn"
                    title="Check reputation on VirusTotal"
                  >
                    <span>VirusTotal</span>
                    <ExternalLink size={12} />
                  </a>
                </>
              )}
            </div>
          </div>

          {/* ── Stat Overview Cards ── */}
          <div className="stat-grid ip-stats-grid">
            <div className="stat-card">
              <span className="stat-label">Total Blocks / Events</span>
              <span className="stat-value text-red">{data.total_events.toLocaleString()}</span>
              <span className="stat-sub">recorded in buffer</span>
            </div>
            <div className="stat-card">
              <span className="stat-label">First Seen</span>
              <span className="stat-value text-secondary" style={{ fontSize: 16 }}>
                {data.first_seen ? relativeTime(data.first_seen) : 'Never'}
              </span>
              <span className="stat-sub" title={data.first_seen || ''}>
                {data.first_seen ? new Date(data.first_seen).toLocaleString() : 'No activity recorded'}
              </span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Last Seen</span>
              <span className="stat-value text-orange" style={{ fontSize: 16 }}>
                {data.last_seen ? relativeTime(data.last_seen) : 'Never'}
              </span>
              <span className="stat-sub" title={data.last_seen || ''}>
                {data.last_seen ? new Date(data.last_seen).toLocaleString() : 'No activity recorded'}
              </span>
            </div>
            <div className="stat-card">
              <span className="stat-label">Network / ASN</span>
              <span
                className="stat-value text-secondary"
                style={{ fontSize: 14, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                title={data.geo.as || data.geo.isp || 'Local'}
              >
                {data.geo.as || data.geo.isp || (data.geo.is_private ? 'LAN / Localhost' : 'Unknown')}
              </span>
              <span className="stat-sub">autonomous system</span>
            </div>
          </div>

          {/* ── 2-Column Deep Dive Panels ── */}
          <div className="ip-details-panels">
            {/* Panel 1: Geolocation & Autonomous System */}
            <div className="card ip-panel-card">
              <div className="card-header">
                <div className="card-title-group">
                  <MapPin size={16} color="var(--accent)" />
                  <span className="card-title">Geolocation & Network Info</span>
                </div>
                <span className="text-muted text-sm">{data.geo.is_private ? 'Internal Subnet' : 'Global BGP'}</span>
              </div>

              <div className="ip-info-table">
                <div className="ip-info-row">
                  <span className="ip-info-key">Country</span>
                  <span className="ip-info-val">
                    {data.geo.flag_emoji} {data.geo.country_name || 'Unknown'}{' '}
                    {data.geo.country_code ? `(${data.geo.country_code})` : ''}
                  </span>
                </div>
                <div className="ip-info-row">
                  <span className="ip-info-key">Region / State</span>
                  <span className="ip-info-val">{data.geo.region || '—'}</span>
                </div>
                <div className="ip-info-row">
                  <span className="ip-info-key">City</span>
                  <span className="ip-info-val">{data.geo.city || '—'}</span>
                </div>
                <div className="ip-info-row">
                  <span className="ip-info-key">Postal / ZIP Code</span>
                  <span className="ip-info-val">{data.geo.zip || '—'}</span>
                </div>
                <div className="ip-info-row">
                  <span className="ip-info-key">Coordinates</span>
                  <span className="ip-info-val">
                    {data.geo.lat !== undefined && data.geo.lon !== undefined && (data.geo.lat !== 0 || data.geo.lon !== 0) ? (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <span className="mono">{data.geo.lat.toFixed(4)}, {data.geo.lon.toFixed(4)}</span>
                        <a
                          href={`https://www.openstreetmap.org/?mlat=${data.geo.lat}&mlon=${data.geo.lon}#map=12/${data.geo.lat}/${data.geo.lon}`}
                          target="_blank"
                          rel="noreferrer"
                          className="ip-map-link"
                          title="View on OpenStreetMap"
                        >
                          <ExternalLink size={12} /> Map
                        </a>
                      </span>
                    ) : (
                      '—'
                    )}
                  </span>
                </div>
                <div className="ip-info-row">
                  <span className="ip-info-key">Timezone</span>
                  <span className="ip-info-val mono">{data.geo.timezone || '—'}</span>
                </div>
                <div className="ip-info-row">
                  <span className="ip-info-key">ISP / Provider</span>
                  <span className="ip-info-val">{data.geo.isp || (data.geo.is_private ? 'Local Network (RFC 1918)' : '—')}</span>
                </div>
                <div className="ip-info-row">
                  <span className="ip-info-key">Organization</span>
                  <span className="ip-info-val">{data.geo.org || '—'}</span>
                </div>
                <div className="ip-info-row">
                  <span className="ip-info-key">Autonomous System (AS)</span>
                  <span className="ip-info-val mono">{data.geo.as || '—'}</span>
                </div>
                <div className="ip-info-row">
                  <span className="ip-info-key">Routing Classification</span>
                  <span className="ip-info-val">
                    {data.geo.is_private
                      ? 'Private / Non-Routable IP space'
                      : 'Public Internet Routable IP'}
                  </span>
                </div>
              </div>
            </div>

            {/* Panel 2: Attack Profile & Behavioral Fingerprint */}
            <div className="card ip-panel-card">
              <div className="card-header">
                <div className="card-title-group">
                  <Activity size={16} color="var(--red)" />
                  <span className="card-title">Behavior & Attack Profile</span>
                </div>
                <span className="text-muted text-sm">{data.total_events} requests</span>
              </div>

              <div className="ip-profile-content">
                {/* Top paths breakdown */}
                <div className="ip-profile-section">
                  <div className="ip-profile-section-title">Most Targeted Endpoints</div>
                  {data.top_paths.length === 0 ? (
                    <div className="text-muted text-sm" style={{ padding: '6px 0' }}>No paths recorded</div>
                  ) : (
                    <div className="ip-bar-list">
                      {data.top_paths.map(p => {
                        const maxCount = data.top_paths[0]?.count || 1
                        const pct = Math.max(8, Math.round((p.count / maxCount) * 100))
                        return (
                          <div key={p.label} className="ip-bar-item">
                            <div className="ip-bar-header">
                              <span className="ip-bar-label mono" title={p.label}>
                                {p.label}
                              </span>
                              <span className="ip-bar-count">{p.count} hit{p.count !== 1 ? 's' : ''}</span>
                            </div>
                            <div className="ip-bar-track">
                              <div
                                className="ip-bar-fill ip-bar-red"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>

                {/* Top matched patterns */}
                <div className="ip-profile-section">
                  <div className="ip-profile-section-title">Triggered Signatures & Rules</div>
                  {data.top_patterns.length === 0 ? (
                    <div className="text-muted text-sm" style={{ padding: '6px 0' }}>No specific rule patterns recorded</div>
                  ) : (
                    <div className="ip-tags-wrap">
                      {data.top_patterns.map(pat => (
                        <span key={pat.label} className="ip-tag ip-tag-pattern">
                          <span className="mono">{pat.label}</span>
                          <span className="ip-tag-badge">{pat.count}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* HTTP Methods & Response Modes Grid */}
                <div className="ip-mini-grid">
                  <div>
                    <div className="ip-profile-section-title">HTTP Methods</div>
                    {data.top_methods.length === 0 ? (
                      <div className="text-muted text-sm">—</div>
                    ) : (
                      <div className="ip-tags-wrap">
                        {data.top_methods.map(m => (
                          <span key={m.label} className={methodBadgeClass(m.label)}>
                            {m.label} ({m.count})
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div>
                    <div className="ip-profile-section-title">Response Modes</div>
                    {data.response_modes.length === 0 ? (
                      <div className="text-muted text-sm">—</div>
                    ) : (
                      <div className="ip-tags-wrap">
                        {data.response_modes.map(rm => (
                          <span key={rm.label} className={modeBadgeClass(rm.label)}>
                            {modeLabel(rm.label, undefined)} ({rm.count})
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Targeted containers / gateways */}
                <div className="ip-profile-section">
                  <div className="ip-profile-section-title">Targeted Containers & Gateways</div>
                  {data.target_sources.length === 0 ? (
                    <div className="text-muted text-sm" style={{ padding: '6px 0' }}>No container origins mapped</div>
                  ) : (
                    <div className="ip-tags-wrap">
                      {data.target_sources.map(src => (
                        <button
                          key={src.label}
                          className="ip-tag ip-tag-source"
                          onClick={() => onSelectContainer && onSelectContainer(src.label)}
                          title={`Filter dashboard for container: ${src.label}`}
                        >
                          <Server size={12} />
                          <span>{src.label}</span>
                          <span className="ip-tag-badge">{src.count}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* ── Event History Table for this IP ── */}
          <div className="card ip-history-card">
            <div className="card-header ip-history-header">
              <div>
                <span className="card-title">Activity Log for {data.ip}</span>
                <span className="text-muted text-sm" style={{ marginLeft: 8 }}>
                  ({filteredEvents.length} event{filteredEvents.length !== 1 ? 's' : ''})
                </span>
              </div>

              {/* Table search filter */}
              <div className="ip-table-search-wrap">
                <Search size={13} color="var(--text-muted)" />
                <input
                  className="filter-input"
                  style={{ width: 220 }}
                  placeholder="Filter by path, pattern, method…"
                  value={tableFilter}
                  onChange={e => {
                    setTableFilter(e.target.value)
                    setCurrentPage(1)
                  }}
                />
                {tableFilter && (
                  <button
                    className="clear-filter-btn"
                    onClick={() => setTableFilter('')}
                    title="Clear filter"
                  >
                    ×
                  </button>
                )}
              </div>
            </div>

            <div className="event-table-content">
              <div className="event-table-head">
                <span className="col-head">Time</span>
                <span className="col-head">Method</span>
                <span className="col-head">Requested Path</span>
                <span className="col-head">Triggered Rule</span>
                <span className="col-head">Action / Response</span>
                <span className="col-head">Container</span>
              </div>

              <div className="event-list ip-history-list">
                {paginatedEvents.length === 0 ? (
                  <div className="empty-state" style={{ padding: '32px 16px' }}>
                    <Clock size={32} color="var(--text-muted)" style={{ opacity: 0.5, marginBottom: 8 }} />
                    <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)' }}>
                      {tableFilter ? `No events match "${tableFilter}"` : 'No security events recorded for this IP address yet.'}
                    </p>
                  </div>
                ) : (
                  paginatedEvents.map((e, idx) => (
                    <div key={`${e.timestamp}-${idx}`} className="event-row">
                      <span className="event-time" title={e.timestamp}>
                        {relativeTime(e.timestamp)}
                      </span>
                      <span>
                        <span className={methodBadgeClass(e.method)}>{e.method || '—'}</span>
                      </span>
                      <span className="event-path mono" title={e.path}>
                        {e.path || '—'}
                      </span>
                      <span className="event-pattern mono" title={e.pattern}>
                        {e.pattern || '—'}
                      </span>
                      <span>
                        <span className={modeBadgeClass(e.response_mode || e.action)}>
                          {modeLabel(e.response_mode, e.status)}
                        </span>
                      </span>
                      <span className="event-source-cell">
                        {e.source ? (
                          <button
                            className="event-source-btn"
                            onClick={() => onSelectContainer && onSelectContainer(e.source || '')}
                            title={`Filter logs by container: ${e.source}`}
                          >
                            {e.source}
                          </button>
                        ) : (
                          '—'
                        )}
                        {e.plugin && (
                          <span className={pluginBadgeClass(e.plugin)}>
                            {pluginLabel(e.plugin)}
                          </span>
                        )}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Pagination Controls */}
            {filteredEvents.length > 0 && (
              <div className="pagination-bar">
                <div className="pagination-info">
                  <span>
                    Showing <strong className="text-secondary">{startIndex + 1}–{endIndex}</strong> of{' '}
                    <strong className="text-secondary">{filteredEvents.length.toLocaleString()}</strong> events
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
                    >
                      <option value={25}>25</option>
                      <option value={50}>50</option>
                      <option value={100}>100</option>
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

                  <span style={{ fontSize: 12, color: 'var(--text-secondary)', padding: '0 8px' }}>
                    Page {safePage} of {totalPages}
                  </span>

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
        </>
      )}
    </div>
  )
}
