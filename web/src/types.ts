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
  bytes: number
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
  bytes_sent: number
  since: string
  series: Bucket[]
}

export interface StatsResponse {
  enabled: boolean
  stats?: Snapshot
}

// One page of the last-24h request feed (GET /admin/stats/recent).
export interface RecentResponse {
  enabled: boolean
  total: number
  page: number
  page_size: number
  events: RequestEvent[]
  // window-wide request count per IP appearing in events
  ip_counts: Record<string, number>
}

export interface BlacklistEntry {
  ip: string
  reason: string
  path?: string
  timestamp: string
  until?: string
}
