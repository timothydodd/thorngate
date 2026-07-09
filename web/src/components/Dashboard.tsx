import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { RequestEvent, Snapshot } from '../types'
import TrafficChart from './TrafficChart'
import DetailsModal from './DetailsModal'
import { OutcomeBadge, statusColor } from './badges'

function StatCard({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
      <div className={'text-2xl font-semibold ' + (accent ?? '')}>{value.toLocaleString()}</div>
      <div className="text-xs text-slate-500 mt-1">{label}</div>
    </div>
  )
}

export default function Dashboard() {
  const [snap, setSnap] = useState<Snapshot | null>(null)
  const [enabled, setEnabled] = useState(true)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<RequestEvent | null>(null)

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

      <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="px-4 py-2.5 bg-slate-100 dark:bg-slate-800/60 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">Recent requests</h2>
          <span className="text-xs text-slate-400">
            {snap.recent?.length ? `${snap.recent.length} shown (newest first)` : ''}
          </span>
        </div>
        <div className="max-h-[28rem] overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 text-xs uppercase tracking-wide sticky top-0">
              <tr>
                {['Time', 'IP', 'Method', 'Host', 'Path', 'Upstream', 'Status', 'Outcome', ''].map((h, i) => (
                  <th key={i} className="text-left font-medium px-3 py-2 whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {!snap.recent?.length ? (
                <tr>
                  <td colSpan={9} className="px-4 py-3 text-slate-400">
                    no requests yet
                  </td>
                </tr>
              ) : (
                snap.recent.map((e, i) => {
                  const pathFull = e.path + (e.query ? '?' + e.query : '')
                  return (
                    <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="px-3 py-1.5 text-slate-400 whitespace-nowrap">
                        {new Date(e.time).toLocaleTimeString()}
                      </td>
                      <td className="px-3 py-1.5 font-mono whitespace-nowrap">{e.ip}</td>
                      <td className="px-3 py-1.5">{e.method}</td>
                      <td className="px-3 py-1.5 font-mono max-w-[11rem] truncate" title={e.host}>
                        {e.host}
                      </td>
                      <td className="px-3 py-1.5 font-mono max-w-[15rem] truncate" title={pathFull}>
                        {pathFull}
                      </td>
                      <td
                        className="px-3 py-1.5 font-mono max-w-[11rem] truncate text-slate-500"
                        title={e.upstream}
                      >
                        {e.upstream || '—'}
                      </td>
                      <td className={'px-3 py-1.5 font-mono ' + statusColor(e.status)}>{e.status}</td>
                      <td className="px-3 py-1.5">
                        <OutcomeBadge outcome={e.outcome} />
                      </td>
                      <td className="px-3 py-1.5 text-right">
                        <button
                          onClick={() => setSelected(e)}
                          className="px-2 py-0.5 rounded-md border border-slate-300 dark:border-slate-700 text-xs text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && <DetailsModal event={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
