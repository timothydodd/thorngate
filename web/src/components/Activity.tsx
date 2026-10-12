import { useEffect, useState } from 'react'
import { api } from '../api'
import { ago, formatNumber, fullTime, isRange } from '../format'
import { useDebounced, usePoll } from '../hooks'
import { useNav } from '../nav'
import { ActivityEvent, ActivityResponse } from '../types'
import { Badge, ErrorText, IPLink, Pager, Segmented, cx, inputClass, rowClass, surface, tdClass, thClass, theadClass } from './ui'

const PAGE_SIZE = 50

const CATEGORIES = [
  { value: '', label: 'All' },
  { value: 'ban', label: 'Bans' },
  { value: 'unban', label: 'Unbans' },
  { value: 'feed', label: 'Feeds' },
  { value: 'config', label: 'Config' },
  { value: 'auth', label: 'Logins' },
  { value: 'system', label: 'System' },
]

const LEVELS = [
  { value: '', label: 'Any level' },
  { value: 'warn', label: 'Warnings' },
  { value: 'error', label: 'Errors' },
]

const categoryTone = {
  ban: 'rose',
  unban: 'emerald',
  feed: 'sky',
  config: 'violet',
  auth: 'amber',
  system: 'slate',
} as const

// Activity lists what thorngate did outside the request flow: bans and
// unbans, whitelist feed updates, config reloads, logins, start/stop.
export default function Activity() {
  const nav = useNav()
  const [category, setCategory] = useState('')
  const [level, setLevel] = useState('')
  const [q, setQ] = useState('')
  const dq = useDebounced(q.trim())
  const [page, setPage] = useState(1)
  const [data, setData] = useState<ActivityResponse | null>(null)
  const [error, setError] = useState('')

  const key = `${category}|${level}|${dq}`
  useEffect(() => setPage(1), [key])

  const load = async () => {
    try {
      setData(await api.activity({ category, level, q: dq }, page, PAGE_SIZE))
      setError('')
    } catch (err: any) {
      setError(err?.message || 'failed to load activity')
    }
  }
  usePoll(load, 15000, page === 1, [key, page])
  useEffect(() => {
    if (page !== 1) load()
  }, [page])

  if (data && !data.enabled) {
    return <p className="text-sm text-slate-400">The activity log is disabled in the config.</p>
  }

  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1
  const filtered = !!(category || level || dq)

  return (
    <div className="space-y-3">
      <div className={cx(surface, 'p-3 flex flex-wrap items-center gap-2')}>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search message, IP, actor"
          className={cx(inputClass, 'flex-1 min-w-[200px]')}
        />
        <Segmented value={category} onChange={setCategory} options={CATEGORIES} />
        <Segmented value={level} onChange={setLevel} options={LEVELS} />
      </div>

      <ErrorText>{error}</ErrorText>

      <div className={cx(surface, 'overflow-hidden')}>
        <div className="px-4 py-2 flex items-center justify-between text-xs text-slate-500 border-b border-slate-200 dark:border-slate-800">
          <span>{data ? `${formatNumber(data.total)} ${filtered ? 'matching ' : ''}events` : 'loading…'}</span>
          <span>newest first</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className={theadClass}>
              <tr>
                <th className={thClass}>When</th>
                <th className={thClass}>Type</th>
                <th className={thClass}>Event</th>
                <th className={thClass}>IP</th>
                <th className={thClass}>By</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {data?.events.map((e, i) => <Row key={`${e.time}-${i}`} e={e} openIP={nav.openIP} />)}
              {data && data.events.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-slate-400">
                    {filtered ? 'no events match these filters' : 'no activity yet'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pager page={data?.page ?? page} pages={pages} onPage={setPage} />
      </div>
    </div>
  )
}

function Row({ e, openIP }: { e: ActivityEvent; openIP: (ip: string) => void }) {
  return (
    <tr className={rowClass}>
      <td className={cx(tdClass, 'whitespace-nowrap text-slate-500')} title={fullTime(e.time)}>
        {ago(e.time)}
      </td>
      <td className={tdClass}>
        <Badge tone={categoryTone[e.category as keyof typeof categoryTone] ?? 'slate'}>{e.category}</Badge>
      </td>
      <td className={cx(tdClass, e.level === 'error' && 'text-rose-600 dark:text-rose-400', e.level === 'warn' && 'text-amber-600 dark:text-amber-400')}>
        {e.message}
      </td>
      <td className={cx(tdClass, 'whitespace-nowrap')}>
        {e.ip && (isRange(e.ip) ? <span className="font-mono">{e.ip}</span> : <IPLink ip={e.ip} onOpen={openIP} />)}
      </td>
      <td className={cx(tdClass, 'text-slate-500 break-all')}>{e.actor}</td>
    </tr>
  )
}
