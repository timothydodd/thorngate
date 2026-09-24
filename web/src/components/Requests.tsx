import { useEffect, useState } from 'react'
import { api } from '../api'
import { formatNumber } from '../format'
import { useDebounced, usePoll } from '../hooks'
import { useNav } from '../nav'
import { RequestEvent, RequestFilter, RequestsResponse } from '../types'
import DetailsModal from './DetailsModal'
import RequestTable from './RequestTable'
import { Button, ErrorText, Pager, Segmented, inputClass, surface, cx } from './ui'

const PAGE_SIZE = 50

const OUTCOMES = [
  { value: '', label: 'All' },
  { value: 'proxied', label: 'Proxied' },
  { value: 'blocked', label: 'Blocked' },
  { value: 'honeypot', label: 'Honeypot' },
]

const STATUSES = [
  { value: '', label: 'Any' },
  { value: '2xx', label: '2xx' },
  { value: '3xx', label: '3xx' },
  { value: '4xx', label: '4xx' },
  { value: '5xx', label: '5xx' },
  { value: 'none', label: 'None', title: 'Denied without a response (tarpit / drop)' },
]

export const DEFAULT_FILTER: RequestFilter = { range: '24h' }

// Requests is the searchable request log. The filter is owned by App so other
// views (top paths, the IP panel) can jump here with one pre-set.
export default function Requests({ filter, onFilter }: { filter: RequestFilter; onFilter: (f: RequestFilter) => void }) {
  const nav = useNav()
  const [data, setData] = useState<RequestsResponse | null>(null)
  const [page, setPage] = useState(1)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<RequestEvent | null>(null)

  // Text inputs are edited locally and applied after a pause in typing; they
  // follow the filter when another view sets it.
  const [ip, setIp] = useState(filter.ip ?? '')
  const [q, setQ] = useState(filter.q ?? '')
  useEffect(() => setIp(filter.ip ?? ''), [filter.ip])
  useEffect(() => setQ(filter.q ?? ''), [filter.q])
  const dip = useDebounced(ip.trim())
  const dq = useDebounced(q.trim())
  useEffect(() => {
    if (dip !== (filter.ip ?? '') || dq !== (filter.q ?? '')) onFilter({ ...filter, ip: dip, q: dq })
  }, [dip, dq])

  // A new filter starts from the newest page.
  const key = JSON.stringify(filter)
  useEffect(() => setPage(1), [key])

  const load = async () => {
    try {
      const r = await api.requests(filter, page, PAGE_SIZE)
      setData(r)
      if (r.enabled && r.page !== page) setPage(r.page) // server clamps out-of-range pages
      setError('')
    } catch (err: any) {
      setError(err?.message || 'failed to load requests')
    }
  }
  // Only page 1 refreshes live: on older pages new traffic would shift the
  // rows under the reader.
  usePoll(load, 10000, page === 1, [key, page])
  useEffect(() => {
    if (page !== 1) load()
  }, [page])

  if (data && !data.enabled) {
    return <p className="text-sm text-slate-400">Stats are disabled in the config, so there is no request log.</p>
  }

  const set = (patch: RequestFilter) => onFilter({ ...filter, ...patch })
  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1
  const active = !!(filter.ip || filter.q || filter.outcome || filter.status)
  const ranges = ['1h', '24h', '7d', '30d'].map((r) => ({
    value: r,
    label: r,
    disabled: !nav.archive && (r === '7d' || r === '30d'),
    title: !nav.archive && (r === '7d' || r === '30d') ? 'Needs stats.archive for history past memory' : undefined,
  }))

  return (
    <div className="space-y-3">
      <div className={cx(surface, 'p-3 flex flex-wrap items-center gap-2')}>
        <input
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="IP or CIDR"
          spellCheck={false}
          className={cx(inputClass, 'w-full sm:w-72 font-mono')}
        />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search path, host, query, user agent"
          className={cx(inputClass, 'flex-1 min-w-[200px]')}
        />
        <Segmented value={filter.outcome ?? ''} onChange={(v) => set({ outcome: v })} options={OUTCOMES} />
        <Segmented value={filter.status ?? ''} onChange={(v) => set({ status: v })} options={STATUSES} />
        <Segmented value={filter.range ?? '24h'} onChange={(v) => set({ range: v })} options={ranges} />
        {active && (
          <Button variant="ghost" onClick={() => onFilter({ range: filter.range })}>
            Clear
          </Button>
        )}
      </div>

      <ErrorText>{error}</ErrorText>

      <div className={cx(surface, 'overflow-hidden')}>
        <div className="px-4 py-2 flex items-center justify-between text-xs text-slate-500 border-b border-slate-200 dark:border-slate-800">
          <span>
            {data ? `${formatNumber(data.total)} ${active ? 'matching ' : ''}requests` : 'loading…'}
            {data?.archive ? '' : ' · in-memory feed'}
          </span>
          <span>newest first</span>
        </div>
        <RequestTable
          data={data}
          onDetails={setSelected}
          onBanned={load}
          empty={active ? 'no requests match these filters' : 'no requests in this range'}
        />
        <Pager
          page={data?.page ?? page}
          pages={pages}
          onPage={setPage}
          note={
            page > 1 ? (
              <span className="text-amber-600 dark:text-amber-400">
                live updates paused ·{' '}
                <button type="button" className="underline" onClick={() => setPage(1)}>
                  jump to latest
                </button>
              </span>
            ) : undefined
          }
        />
      </div>

      {selected && <DetailsModal event={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
