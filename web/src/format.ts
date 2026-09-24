// Formatting helpers shared across the portal.

export function formatBytes(n: number | undefined): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return (i === 0 ? v.toString() : v.toFixed(1)) + ' ' + units[i]
}

export function formatNumber(n: number): string {
  return n.toLocaleString()
}

// Compact count for tight spaces: 1234 -> "1.2k".
export function compact(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return (n / 1000).toFixed(n < 10_000 ? 1 : 0) + 'k'
  return (n / 1_000_000).toFixed(1) + 'M'
}

export function percent(part: number, whole: number): string {
  if (!whole) return '0%'
  const p = (part / whole) * 100
  return (p < 10 && p > 0 ? p.toFixed(1) : Math.round(p).toString()) + '%'
}

function span(ms: number): string {
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m`
  const h = Math.round(m / 60)
  if (h < 48) return `${h}h`
  return `${Math.round(h / 24)}d`
}

// "3m ago" for past times; "just now" under five seconds.
export function ago(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime()
  if (ms < 5000) return 'just now'
  return span(ms) + ' ago'
}

// "in 12m" for future times; "expired" once past.
export function until(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now()
  return ms <= 0 ? 'expired' : 'in ' + span(ms)
}

export function fullTime(iso: string): string {
  return new Date(iso).toLocaleString()
}

// A denied request may never get a response written (block_action
// drop/tarpit); show what happened to it instead of a status code.
export function formatStatus(code: number, deny?: string): string {
  if (deny === 'tarpit') return 'tarpit'
  if (deny === 'drop') return 'dropped'
  return code === 0 ? '(ghosted)' : String(code)
}

export function statusColor(code: number): string {
  if (code === 0) return 'text-slate-400 dark:text-slate-500'
  if (code >= 500) return 'text-rose-500'
  if (code >= 400) return 'text-amber-500'
  if (code >= 300) return 'text-sky-500'
  return 'text-emerald-500'
}

export function isRange(key: string): boolean {
  return key.includes('/')
}

export function isIPv6(ip: string): boolean {
  return ip.includes(':')
}
