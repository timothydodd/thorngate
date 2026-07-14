import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { RecentResponse, RequestEvent } from '../types'
import DetailsModal from './DetailsModal'
import { OutcomeBadge, formatBytes, statusColor } from './badges'

const PAGE_SIZE = 50
// An IP gets a request-count badge once it has more than this many requests
// in the 24h window.
const BADGE_THRESHOLD = 5

export default function RecentRequests() {
  const [data, setData] = useState<RecentResponse | null>(null)
  const [page, setPage] = useState(1)
  const [error, setError] = useState('')
  const [banError, setBanError] = useState('')
  const [banning, setBanning] = useState('')
  const [selected, setSelected] = useState<RequestEvent | null>(null)

  const load = useCallback(async () => {
    try {
      const r = await api.recent(page, PAGE_SIZE)
      setData(r)
      // The server clamps out-of-range pages (e.g. the feed shrank); follow it.
      if (r.enabled && r.page !== page) setPage(r.page)
      setError('')
    } catch (err: any) {
      setError(err?.message || 'failed to load recent requests')
    }
  }, [page])

  useEffect(() => {
    load()
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [load])

  const ban = async (ip: string) => {
    if (!window.confirm(`Ban ${ip}? It will be blacklisted permanently.`)) return
    setBanning(ip)
    setBanError('')
    try {
      await api.ban(ip, 'manual (dashboard)')
      await load()
    } catch (err: any) {
      setBanError(`ban ${ip} failed: ` + (err?.message || 'unknown error'))
    } finally {
      setBanning('')
    }
  }

  if (data && !data.enabled) return null

  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1

  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
      <div className="px-4 py-2.5 bg-slate-100 dark:bg-slate-800/60 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">
          Requests (last 24h)
        </h2>
        <span className="text-xs text-slate-400">
          {data ? `${data.total.toLocaleString()} requests (newest first)` : ''}
        </span>
      </div>

      {(error || banError) && (
        <p className="px-4 py-2 text-sm text-rose-500">{error || banError}</p>
      )}

      <div className="max-h-[28rem] overflow-auto">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 text-xs uppercase tracking-wide sticky top-0">
            <tr>
              {['Time', 'IP', 'Method', 'Host', 'Path', 'Upstream', 'Status', 'Sent', 'Outcome', ''].map(
                (h, i) => (
                  <th key={i} className="text-left font-medium px-3 py-2 whitespace-nowrap">
                    {h}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
            {!data?.events?.length ? (
              <tr>
                <td colSpan={10} className="px-4 py-3 text-slate-400">
                  {data ? 'no requests in the last 24 hours' : 'loading…'}
                </td>
              </tr>
            ) : (
              data.events.map((e, i) => {
                const pathFull = e.path + (e.query ? '?' + e.query : '')
                const count = data.ip_counts?.[e.ip] ?? 0
                return (
                  <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="px-3 py-1.5 text-slate-400 whitespace-nowrap">
                      {new Date(e.time).toLocaleTimeString()}
                    </td>
                    <td className="px-3 py-1.5 font-mono whitespace-nowrap">
                      {e.ip}
                      {count > BADGE_THRESHOLD && (
                        <span
                          className="ml-1.5 text-xs font-sans px-1.5 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300"
                          title={`${count} requests from ${e.ip} in the last 24h`}
                        >
                          {count}
                        </span>
                      )}
                    </td>
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
                    <td className="px-3 py-1.5 text-slate-500 whitespace-nowrap">
                      {e.outcome === 'proxied' ? formatBytes(e.bytes) : '—'}
                    </td>
                    <td className="px-3 py-1.5">
                      <OutcomeBadge outcome={e.outcome} />
                    </td>
                    <td className="px-3 py-1.5 text-right whitespace-nowrap">
                      <button
                        onClick={() => setSelected(e)}
                        className="px-2 py-0.5 rounded-md border border-slate-300 dark:border-slate-700 text-xs text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
                      >
                        Details
                      </button>
                      <button
                        onClick={() => ban(e.ip)}
                        disabled={banning === e.ip}
                        className="ml-1.5 px-2 py-0.5 rounded-md border border-rose-300 dark:border-rose-900 text-xs text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-900/30 disabled:opacity-50"
                      >
                        Ban
                      </button>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="px-4 py-2 bg-slate-50 dark:bg-slate-900/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500">
        <button
          onClick={() => setPage((p) => Math.max(1, p - 1))}
          disabled={page <= 1}
          className="px-2 py-1 rounded-md border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40"
        >
          ‹ Prev
        </button>
        <span>
          Page {data?.page ?? page} of {pages}
        </span>
        <button
          onClick={() => setPage((p) => Math.min(pages, p + 1))}
          disabled={page >= pages}
          className="px-2 py-1 rounded-md border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40"
        >
          Next ›
        </button>
      </div>

      {selected && <DetailsModal event={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
