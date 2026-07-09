// Types mirror the JSON emitted by the Go backend (internal/stats, internal/blacklist).

export interface RequestEvent {
  time: string
  ip: string
  method: string
  host: string
  path: string
  query?: string
  status: number
  outcome: 'proxied' | 'blocked' | 'honeypot' | string
  upstream?: string
}

export interface Bucket {
  t: number // unix minute
  requests: number
  blocked: number
}

export interface Snapshot {
  requests: number
  blocked: number
  honeypots: number
  temp_bans: number
  status_2xx: number
  status_3xx: number
  status_4xx: number
  status_5xx: number
  since: string
  series: Bucket[]
  recent: RequestEvent[]
}

export interface StatsResponse {
  enabled: boolean
  stats?: Snapshot
}

export interface BlacklistEntry {
  ip: string
  reason: string
  path?: string
  timestamp: string
  until?: string
}
