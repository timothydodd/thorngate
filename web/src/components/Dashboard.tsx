import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { Snapshot } from '../types'
import TrafficChart from './TrafficChart'
import RecentRequests from './RecentRequests'
import { formatBytes } from './badges'

function StatCard({ label, value, accent }: { label: string; value: string | number; accent?: string }) {
  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
      <div className={'text-2xl font-semibold ' + (accent ?? '')}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      <div className="text-xs text-slate-500 mt-1">{label}</div>
    </div>
  )
}

export default function Dashboard() {
  const [snap, setSnap] = useState<Snapshot | null>(null)
  const [enabled, setEnabled] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const r = await api.stats()
      setEnabled(r.enabled)
      setSnap(r.stats ?? null)
      setError('')
    } catch (err: any) {
      setError(err?.message || 'failed to load stats')
    }
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [load])

  if (!enabled) {
    return (
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-8 text-center text-sm text-slate-400">
        Stats are disabled in the config (<code className="font-mono">stats.enabled = false</code>).
      </div>
    )
  }

  if (!snap) {
    return (
      <div className="text-sm text-slate-400">{error || 'loading…'}</div>
    )
  }

  return (
    <div className="space-y-6">
      {error && <p className="text-sm text-rose-500">{error}</p>}

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        <StatCard label="Total requests" value={snap.requests} />
        <StatCard label="Blocked (blacklist)" value={snap.blocked} accent="text-rose-500" />
        <StatCard label="Honeypot bans" value={snap.honeypots} accent="text-amber-500" />
        <StatCard label="Temp bans" value={snap.temp_bans} accent="text-amber-500" />
        <StatCard label="2xx" value={snap.status_2xx} accent="text-emerald-500" />
        <StatCard label="3xx" value={snap.status_3xx} accent="text-sky-500" />
        <StatCard label="4xx" value={snap.status_4xx} accent="text-amber-500" />
        <StatCard label="5xx" value={snap.status_5xx} accent="text-rose-500" />
        <StatCard label="Data sent" value={formatBytes(snap.bytes_sent)} accent="text-sky-500" />
      </div>

      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">Traffic (requests / min)</h2>
          <div className="flex items-center gap-3 text-xs text-slate-500">
            <span className="flex items-center gap-1">
              <span className="inline-block w-3 h-1.5 rounded bg-blue-500" />requests
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-3 h-1.5 rounded bg-rose-500" />blocked
            </span>
          </div>
        </div>
        <TrafficChart series={snap.series ?? []} />
        <p className="text-xs text-slate-400 mt-3">counting since {new Date(snap.since).toLocaleString()}</p>
      </div>

      <RecentRequests />
    </div>
  )
}
