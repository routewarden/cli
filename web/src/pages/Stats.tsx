import { useState, useEffect } from 'react'
import { Container } from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, Legend
} from 'recharts'
import type { StatsSnapshot, Source } from '../types'
import { useMediaQuery } from '../hooks/useMediaQuery'

const HOURS_OPTIONS = [
  { label: '1h',  value: 1 },
  { label: '6h',  value: 6 },
  { label: '24h', value: 24 },
]

const PIE_COLORS = [
  '#6366f1', '#ef4444', '#f97316', '#3b82f6',
  '#10b981', '#8b5cf6', '#ec4899', '#f59e0b',
  '#06b6d4', '#14b8a6', '#84cc16', '#a855f7',
]

interface StatsProps {
  sources?: Source[]
  selectedContainer?: string
  onSelectContainer?: (c: string) => void
  onSelectIP?: (ip: string) => void
}

export default function Stats({
  sources = [],
  selectedContainer = 'all',
  onSelectContainer,
  onSelectIP,
}: StatsProps) {
  const [hours, setHours] = useState(24)
  const [stats, setStats] = useState<StatsSnapshot | null>(null)
  const [loading, setLoading] = useState(true)
  const isNarrow = useMediaQuery('(max-width: 768px)')
  const isMobile = useMediaQuery('(max-width: 540px)')

  useEffect(() => {
    setLoading(true)
    const srcParam = selectedContainer && selectedContainer !== 'all'
      ? `&source=${encodeURIComponent(selectedContainer)}`
      : ''

    fetch(`/api/stats?hours=${hours}${srcParam}`)
      .then(r => r.json())
      .then((data: StatsSnapshot) => { setStats(data); setLoading(false) })
      .catch(() => setLoading(false))

    const interval = setInterval(() => {
      fetch(`/api/stats?hours=${hours}${srcParam}`)
        .then(r => r.json())
        .then((data: StatsSnapshot) => setStats(data))
        .catch(() => {})
    }, 10_000)
    return () => clearInterval(interval)
  }, [hours, selectedContainer])

  return (
    <div className="page">
      <div className="page-header" style={{ flexShrink: 0 }}>
        <div>
          <div className="page-title">
            Statistics
            {selectedContainer !== 'all' && (
              <span className="badge badge-plugin-traefik" style={{ fontSize: 11, marginLeft: 8 }}>
                {selectedContainer}
              </span>
            )}
          </div>
          <div className="page-subtitle">
            {selectedContainer !== 'all'
              ? `Aggregated metrics for container: ${selectedContainer}`
              : 'Aggregated metrics from the in-memory event buffer'
            }
          </div>
        </div>
        <div className="header-actions">
          {sources.length > 0 && onSelectContainer && (
            <div className="container-filter-wrap">
              <Container size={13} color="var(--text-muted)" style={{ flexShrink: 0 }} />
              <select
                className="container-select"
                value={selectedContainer}
                onChange={e => onSelectContainer(e.target.value)}
                title="Filter statistics by container"
              >
                <option value="all">All Containers</option>
                {sources.map(s => (
                  <option key={s.id} value={s.name}>
                    {s.name}
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
          )}

          {HOURS_OPTIONS.map(o => (
            <button
              key={o.value}
              className={`toolbar-btn ${hours === o.value ? 'active' : ''}`}
              onClick={() => setHours(o.value)}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>

      {/* Stat cards */}
      {stats && (
        <div className="stat-grid">
          <StatCard
            label="Total Events"
            value={stats.total_events.toLocaleString()}
            accent="accent"
            sub={`in last ${hours}h`}
          />
          <StatCard
            label="Unique IPs"
            value={stats.unique_ips.toLocaleString()}
            accent="red"
            sub="attacker addresses"
          />
          <StatCard
            label="Blocks / Min"
            value={stats.blocks_per_min.toString()}
            accent="orange"
            sub="rolling average"
          />
          <StatCard
            label="Top Path"
            value={stats.top_paths?.[0]?.label ?? '—'}
            accent="green"
            sub={`${stats.top_paths?.[0]?.count ?? 0} hits`}
            mono
          />
        </div>
      )}

      {loading && <LoadingPlaceholder />}

      {stats && !loading && stats.total_events === 0 && (
        <div className="empty-state" style={{ flex: 1 }}>
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <p>No security events recorded in the last {hours}h</p>
          <p style={{ fontSize: 12, maxWidth: 360 }}>
            Metrics and visual analytics will appear here in real time as RouteWarden analyzes and blocks traffic.
          </p>
        </div>
      )}

      {stats && !loading && stats.total_events > 0 && (
        <div className="charts-grid">
          {/* Block rate over time */}
          <div className="card chart-full">
            <div className="card-header">
              <div>
                <span className="card-title">Block Rate Over Time</span>
                <span className="text-muted text-sm chart-sub-label" style={{ marginLeft: 8 }}>per minute (last 60 min)</span>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={isMobile ? 180 : 220}>
              <AreaChart
                data={stats.rate_over_time ?? []}
                margin={{ top: 12, right: isMobile ? 12 : 24, left: isMobile ? -16 : -6, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="rateGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="var(--accent)" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="minute" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} width={isMobile ? 32 : 38} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8 }}
                  labelStyle={{ color: 'var(--text-secondary)' }}
                  itemStyle={{ color: 'var(--accent-hover)' }}
                  formatter={(val: any) => [`${val} blocks/min`, 'Rate']}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="var(--accent)"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#rateGradient)"
                  activeDot={{ r: 4, fill: 'var(--accent-hover)' }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Top paths */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Top Attacked Paths</span>
              <span className="text-muted text-sm">{stats.top_paths?.length ?? 0} endpoints</span>
            </div>
            <ResponsiveContainer width="100%" height={isNarrow ? 260 : 280}>
              <BarChart
                data={stats.top_paths ?? []}
                layout="vertical"
                margin={{ top: 8, right: isMobile ? 26 : isNarrow ? 30 : 38, left: isMobile ? 2 : 8, bottom: 8 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                <YAxis
                  type="category"
                  dataKey="label"
                  width={isMobile ? 85 : isNarrow ? 110 : 160}
                  interval={0}
                  tickLine={false}
                  axisLine={{ stroke: 'var(--border)' }}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'JetBrains Mono, monospace' }}
                  tickFormatter={(val: string) => val.length > (isMobile ? 10 : isNarrow ? 15 : 26) ? val.slice(0, isMobile ? 8 : isNarrow ? 13 : 24) + '…' : val}
                />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8 }}
                  itemStyle={{ color: 'var(--red)' }}
                  formatter={(val: any) => [`${val} hits`, 'Requests']}
                />
                <Bar
                  dataKey="count"
                  fill="var(--red)"
                  radius={[0, 4, 4, 0]}
                  barSize={14}
                  label={{ position: 'right', fill: 'var(--text-muted)', fontSize: 10, offset: 6 }}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Top IPs */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Top Attacker IPs</span>
              <span className="text-muted text-sm">{stats.top_ips?.length ?? 0} addresses</span>
            </div>
            <ResponsiveContainer width="100%" height={isNarrow ? 260 : 280}>
              <BarChart
                data={stats.top_ips ?? []}
                layout="vertical"
                margin={{ top: 8, right: isMobile ? 26 : isNarrow ? 30 : 38, left: isMobile ? 2 : 8, bottom: 8 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                <YAxis
                  type="category"
                  dataKey="label"
                  width={isMobile ? 95 : isNarrow ? 110 : 130}
                  interval={0}
                  tickLine={false}
                  axisLine={{ stroke: 'var(--border)' }}
                  tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'JetBrains Mono, monospace' }}
                />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8 }}
                  itemStyle={{ color: 'var(--orange)' }}
                  formatter={(val: any) => [`${val} blocks`, 'Events']}
                />
                <Bar
                  dataKey="count"
                  fill="var(--orange)"
                  radius={[0, 4, 4, 0]}
                  barSize={14}
                  label={{ position: 'right', fill: 'var(--text-muted)', fontSize: 10, offset: 6 }}
                  cursor={onSelectIP ? 'pointer' : 'default'}
                  onClick={(entry: any) => {
                    if (onSelectIP && entry?.label) {
                      onSelectIP(entry.label)
                    }
                  }}
                />
              </BarChart>
            </ResponsiveContainer>
            {onSelectIP && stats.top_ips && stats.top_ips.length > 0 && (
              <div className="stats-top-ips-pills">
                <span className="stats-top-ips-label">Inspect IP:</span>
                {stats.top_ips.slice(0, 5).map(item => (
                  <button
                    key={item.label}
                    className="stats-ip-pill"
                    onClick={() => onSelectIP(item.label)}
                    title={`Inspect full intelligence for ${item.label}`}
                  >
                    <span className="mono">{item.label}</span>
                    <span className="stats-ip-count">{item.count}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Response modes donut */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Response Modes</span>
              <span className="text-muted text-sm">action distribution</span>
            </div>
            <ResponsiveContainer width="100%" height={isNarrow ? 290 : 280}>
              <PieChart margin={{ top: 0, right: 10, left: 10, bottom: isNarrow ? 10 : 0 }}>
                <Pie
                  data={stats.response_modes ?? []}
                  dataKey="count"
                  nameKey="label"
                  cx={isNarrow ? '50%' : '36%'}
                  cy={isNarrow ? '38%' : '50%'}
                  outerRadius={isMobile ? 65 : 75}
                  innerRadius={isMobile ? 38 : 45}
                  paddingAngle={3}
                >
                  {(stats.response_modes ?? []).map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} stroke="var(--bg-surface)" strokeWidth={2} />
                  ))}
                </Pie>
                <Legend
                  layout={isNarrow ? 'horizontal' : 'vertical'}
                  align={isNarrow ? 'center' : 'right'}
                  verticalAlign={isNarrow ? 'bottom' : 'middle'}
                  wrapperStyle={
                    isNarrow
                      ? { maxHeight: 90, overflowY: 'auto', paddingTop: 8, fontSize: 10 }
                      : { maxHeight: 220, overflowY: 'auto', paddingRight: 4, maxWidth: '50%' }
                  }
                  formatter={(value, entry: any) => (
                    <span style={{ color: 'var(--text-secondary)', fontSize: 11, display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 160 }}>{value}</span>
                      <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>({entry.payload?.count})</span>
                    </span>
                  )}
                />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8 }}
                  formatter={(val: any) => [`${val} times`, 'Count']}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* By gateway */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Events by Gateway</span>
              <span className="text-muted text-sm">traffic origin</span>
            </div>
            <ResponsiveContainer width="100%" height={isMobile ? 220 : 280}>
              <BarChart
                data={stats.by_gateway ?? []}
                margin={{ top: 20, right: isMobile ? 16 : 24, left: isMobile ? -16 : -6, bottom: 8 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} width={isMobile ? 32 : 38} axisLine={{ stroke: 'var(--border)' }} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8 }}
                  itemStyle={{ color: 'var(--accent-hover)' }}
                  formatter={(val: any) => [`${val} events`, 'Gateway Total']}
                />
                <Bar
                  dataKey="count"
                  fill="var(--accent)"
                  radius={[4, 4, 0, 0]}
                  barSize={32}
                  label={{ position: 'top', fill: 'var(--text-muted)', fontSize: 10, offset: 6 }}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, accent, sub, mono }: {
  label: string; value: string; accent: string; sub?: string; mono?: boolean
}) {
  return (
    <div className={`stat-card ${accent}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value" style={mono ? { fontFamily: 'JetBrains Mono, monospace', fontSize: 14 } : {}}>
        {value}
      </span>
      {sub && <span className="stat-sub">{sub}</span>}
    </div>
  )
}

function LoadingPlaceholder() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 200, color: 'var(--text-muted)', fontSize: 13 }}>
      Loading statistics…
    </div>
  )
}
