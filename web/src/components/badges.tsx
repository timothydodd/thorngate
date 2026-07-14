// Shared presentational helpers for request status and outcome.

export function statusColor(code: number): string {
  if (code >= 500) return 'text-rose-500'
  if (code >= 400) return 'text-amber-500'
  if (code >= 300) return 'text-sky-500'
  return 'text-emerald-500'
}

const OUTCOME_STYLES: Record<string, string> = {
  blocked: 'bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300',
  honeypot: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
  proxied: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
}

export function OutcomeBadge({ outcome }: { outcome: string }) {
  const cls = OUTCOME_STYLES[outcome] ?? OUTCOME_STYLES.proxied
  return <span className={'text-xs px-1.5 py-0.5 rounded ' + cls}>{outcome}</span>
}

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
