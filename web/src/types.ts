// Shared types mirroring the Go backend structs

export interface SecurityEvent {
  type: string
  timestamp: string
  plugin: string
  client_ip: string
  method: string
  path: string
  target?: string
  query?: string
  pattern?: string
  reason?: string
  action: string
  status?: number
  response_mode?: string
  source?: string
  source_id?: string
  country_code?: string
  country_name?: string
  flag_emoji?: string
}

export interface RouteWardenConfig {
  $schema?: string
  enabled?: boolean
  enableDefaultPatterns?: boolean
  enableDefaultAllowPatterns?: boolean
  pathPatterns?: string[]
  allowPatterns?: string[]
  allowedIps?: string[]
  methods?: string[]
  checkQuery?: boolean
  checkHeaders?: string[]
  response?: {
    mode?: string
    statusCode?: number
    body?: string
    headers?: Record<string, string>
  }
  [key: string]: any
}

export interface ConfigResponse {
  id: string
  name: string
  kind: string
  has_config: boolean
  label_key?: string
  config?: RouteWardenConfig | null
  raw?: string
  error?: string
  hint?: string
}

export interface Source {
  id: string
  name: string
  kind: 'docker' | 'file'
  plugin: string
  status: 'live' | 'stopped' | 'error'
  details?: string
}

export interface CountEntry {
  label: string
  count: number
}

export interface RatePoint {
  minute: string
  count: number
}

export interface StatsSnapshot {
  total_events: number
  unique_ips: number
  blocks_per_min: number
  top_paths: CountEntry[]
  top_ips: CountEntry[]
  response_modes: CountEntry[]
  rate_over_time: RatePoint[]
  by_gateway: CountEntry[]
}

export interface GeoResult {
  ip: string
  country_code: string
  country_name: string
  flag_emoji: string
  region?: string
  city?: string
  zip?: string
  lat?: number
  lon?: number
  timezone?: string
  isp?: string
  org?: string
  as?: string
  is_private: boolean
}

export interface IPDetailsResponse {
  ip: string
  geo: GeoResult
  total_events: number
  first_seen?: string
  last_seen?: string
  risk_score: 'critical' | 'high' | 'medium' | 'low'
  risk_reason: string
  top_paths: CountEntry[]
  top_methods: CountEntry[]
  top_patterns: CountEntry[]
  response_modes: CountEntry[]
  target_sources: CountEntry[]
  events: SecurityEvent[]
}


export interface WsMessage {
  msg_type: 'event' | 'sources'
  payload: SecurityEvent | Source[]
}
