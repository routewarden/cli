import type { SecurityEvent } from './types'

// ── Time formatting ──────────────────────────────────────────────────────────

/** Format timestamp as relative time string, e.g. "3s ago" */
export function relativeTime(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 2)  return 'just now'
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

/** Format timestamp as HH:MM:SS */
export function timeStr(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString('en-US', {
      hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
    })
  } catch {
    return '--:--:--'
  }
}

// ── Badge CSS class helpers ──────────────────────────────────────────────────

export function methodBadgeClass(method?: string): string {
  switch (method?.toUpperCase()) {
    case 'GET':    return 'badge badge-method-get'
    case 'POST':   return 'badge badge-method-post'
    case 'PUT':    return 'badge badge-method-put'
    case 'DELETE': return 'badge badge-method-delete'
    case 'HEAD':   return 'badge badge-method-head'
    default:       return 'badge badge-method-other'
  }
}

export function modeBadgeClass(mode?: string): string {
  const m = (mode || 'block').toLowerCase()
  if (m === 'allow' || m === 'allowed') return 'badge badge-mode-allow'
  if (m.includes('tarpit'))     return 'badge badge-mode-tarpit'
  if (m.includes('gzip'))       return 'badge badge-mode-gzip'
  if (m.includes('silent') || m.includes('drop')) return 'badge badge-mode-silent'
  if (m.includes('fake'))       return 'badge badge-mode-fake'
  if (m.includes('captcha'))    return 'badge badge-mode-captcha'
  if (m === 'block' || m === 'blocked') return 'badge badge-mode-block'
  return 'badge badge-mode-other'
}

export function pluginBadgeClass(plugin?: string): string {
  const p = (plugin || '').toLowerCase()
  if (p.includes('traefik')) return 'badge badge-plugin-traefik'
  if (p.includes('caddy'))   return 'badge badge-plugin-caddy'
  if (p.includes('nginx'))   return 'badge badge-plugin-nginx'
  if (p.includes('tcp'))     return 'badge badge-plugin-tcp'
  return 'badge badge-plugin-unknown'
}

export function pluginLabel(plugin?: string): string {
  const p = (plugin || '').toLowerCase()
  if (p.includes('traefik')) return 'Traefik Warden'
  if (p.includes('caddy'))   return 'Caddy Warden'
  if (p.includes('nginx'))   return 'NGINX Warden'
  if (p.includes('tcp'))     return 'TCP Warden'
  return plugin || 'Unknown'
}

export function modeLabel(mode: string | undefined, status: number | undefined): string {
  if (mode) {
    if (mode === 'gzipBomb') return 'GzipBomb'
    if (mode === 'silentDrop') return 'Silent Drop'
    if (mode === 'fakeSuccess') return 'Fake 200'
    if (mode === 'rateLimitChallenge') return 'RateLimit'
    if (mode === 'infiniteStream') return '∞ Stream'
    if (mode === 'allow' || mode === 'allowed') return 'Allow'
    return mode.charAt(0).toUpperCase() + mode.slice(1)
  }
  return status ? `HTTP ${status}` : 'Block'
}

// ── Event filtering ──────────────────────────────────────────────────────────

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0 || isNaN(bytes)) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1)
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function filterEvents(events: SecurityEvent[], query: string): SecurityEvent[] {
  if (!query.trim()) return events
  const q = query.toLowerCase()
  return events.filter(e =>
    e.client_ip?.toLowerCase().includes(q) ||
    e.country_name?.toLowerCase().includes(q) ||
    e.country_code?.toLowerCase().includes(q) ||
    e.path?.toLowerCase().includes(q) ||
    e.plugin?.toLowerCase().includes(q) ||
    e.method?.toLowerCase().includes(q) ||
    e.response_mode?.toLowerCase().includes(q) ||
    e.source?.toLowerCase().includes(q) ||
    e.pattern?.toLowerCase().includes(q) ||
    e.service?.toLowerCase().includes(q) ||
    e.protocol?.toLowerCase().includes(q) ||
    e.action?.toLowerCase().includes(q) ||
    e.reason?.toLowerCase().includes(q)
  )
}
