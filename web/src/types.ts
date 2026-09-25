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

export interface WsMessage {
  msg_type: 'event' | 'sources'
  payload: SecurityEvent | Source[]
}
