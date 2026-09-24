// Types mirror the JSON emitted by the Go backend (internal/stats, internal/blacklist,
// internal/admin).

export interface RequestEvent {
  time: string
  ip: string
  method: string
  host: string
  path: string
  query?: string
  status: number
  outcome: 'proxied' | 'blocked' | 'honeypot' | string
  deny?: 'tarpit' | 'drop' | string
  upstream?: string
  bytes: number
  country?: string
  ua?: string
}

export interface Bucket {
  t: number // unix minute (bucket start)
  requests: number
  blocked: number
}

export interface Snapshot {
  requests: number
  blocked: number
  honeypots: number
  temp_bans: number
  escalated: number
  status_2xx: number
  status_3xx: number
  status_4xx: number
  status_5xx: number
  bytes_sent: number
  since: string
  series: Bucket[]
}

export interface ArchiveInfo {
  enabled: boolean
  retention_days?: number
  segments?: number
  bytes?: number
  dropped?: number
}

export interface StatsResponse {
  enabled: boolean
  stats?: Snapshot
  archive?: ArchiveInfo
}

export interface RequestFilter {
  ip?: string
  outcome?: string
  status?: string
  q?: string
  range?: string
}

// One page of request history (GET /admin/requests).
export interface RequestsResponse {
  enabled: boolean
  archive: boolean
  total: number
  page: number
  page_size: number
  events: RequestEvent[]
  // range-wide request count per IP appearing in events
  ip_counts: Record<string, number>
  banned?: Record<string, boolean>
}

export interface Counted {
  key: string
  count: number
}

export interface TopResponse {
  enabled: boolean
  ips?: Counted[]
  paths?: Counted[]
  banned?: Record<string, boolean>
}

export interface HourlyResponse {
  enabled: boolean
  series?: Bucket[]
}

export interface BlacklistEntry {
  ip: string
  reason: string
  path?: string
  timestamp: string
  until?: string
}

export interface IPSummary {
  ip: string
  requests: number
  outcomes: Record<string, number>
  statuses: Record<string, number>
  paths: Counted[]
  hosts: Counted[]
  first_seen?: string
  last_seen?: string
  country?: string
  ua?: string
}

export interface IPProfile {
  ip: string
  whitelisted: boolean
  ban: BlacklistEntry | null
  summary?: IPSummary
}

export interface WhitelistEntry {
  ip: string
  no_log: boolean
}

export interface ImportResult {
  added: number
  skipped: number
  invalid: string[]
}
