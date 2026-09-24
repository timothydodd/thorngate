import { ReactNode, useState } from 'react'
import { api } from '../api'
import { compact, formatBytes, formatNumber, percent } from '../format'
import { usePoll, useStored } from '../hooks'
import { useNav } from '../nav'
import { ArchiveInfo, Bucket, Counted, Snapshot } from '../types'
import TrafficChart from './TrafficChart'
import { Badge, Card, ErrorText, IPLink, Muted, Segmented, cx, surface } from './ui'

type Range = 'live' | '24h' | '7d' | '30d'

const RANGE_LABEL: Record<Range, string> = { live: 'Last hour', '24h': '24 hours', '7d': '7 days', '30d': '30 days' }

// The API range each view queries for top lists (live = the last hour).
const apiRange = (r: Range) => (r === 'live' ? '1h' : r)

export default function Dashboard() {
  const nav = useNav()
  const [snap, setSnap] = useState<Snapshot | null>(null)
  const [archive, setArchive] = useState<ArchiveInfo | undefined>()
  const [enabled, setEnabled] = useState(true)
  const [error, setError] = useState('')
  const [range, setRange] = useStored<Range>('tg_range', 'live')
  // Without the archive, history beyond the in-memory feed doesn't exist.
  const effective: Range = !nav.archive && (range === '7d' || range === '30d') ? '24h' : range
  const top = useTop(apiRange(effective))

  usePoll(async () => {
    try {
      const r = await api.stats()
      setEnabled(r.enabled)
      setSnap(r.stats ?? null)
      setArchive(r.archive)
      setError('')
    } catch (err: any) {
      setError(err?.message || 'failed to load stats')
    }
  }, 10000)

  if (!enabled) {
    return (
      <Card>
        <Muted>
          Stats are disabled in the config (<code className="font-mono">"stats": {'{'} "disabled": true {'}'}</code>).
        </Muted>
      </Card>
    )
  }
  if (!snap) return <Muted>{error || 'loading…'}</Muted>

  const bans = snap.honeypots + snap.temp_bans

  return (
    <div className="space-y-5">
      <ErrorText>{error}</ErrorText>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="Requests" value={compact(snap.requests)} title={formatNumber(snap.requests)} sub={`since ${new Date(snap.since).toLocaleDateString()}`} />
        <Stat
          label="Blocked"
          value={compact(snap.blocked)}
          title={formatNumber(snap.blocked)}
          accent="text-rose-500"
          sub={`${percent(snap.blocked, snap.requests)} of requests`}
        />
        <Stat
          label="Bans issued"
          value={compact(bans)}
          accent="text-amber-500"
          sub={`${snap.honeypots} honeypot · ${snap.temp_bans} temp${snap.escalated ? ` · ${snap.escalated} escalated` : ''}`}
        />
        <Stat label="Data sent" value={formatBytes(snap.bytes_sent)} accent="text-sky-500" sub="by proxied responses" />
      </div>

      <StatusMix snap={snap} />

      <Card
        title="Traffic"
        actions={
          <>
            <Legend />
            <Segmented<Range>
              value={effective}
              onChange={setRange}
              options={(['live', '24h', '7d', '30d'] as Range[]).map((r) => ({
                value: r,
                label: r === 'live' ? '1h' : r,
                disabled: !nav.archive && (r === '7d' || r === '30d'),
                title: !nav.archive && (r === '7d' || r === '30d') ? 'Needs stats.archive for history past memory' : undefined,
              }))}
            />
          </>
        }
      >
        {effective === 'live' ? (
          <TrafficChart
            series={snap.series ?? []}
            unit="min"
            tick={(t) => clock(t)}
            full={(t) => clock(t)}
          />
        ) : (
          <HourlyChart range={effective} />
        )}
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        <TopIPs top={top} label={RANGE_LABEL[effective]} />
        <TopPaths top={top} range={apiRange(effective)} label={RANGE_LABEL[effective]} />
      </div>

      <HistoryNote archive={archive} />
    </div>
  )
}

const clock = (t: number) => new Date(t * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

function Stat({ label, value, sub, accent, title }: { label: string; value: string; sub?: string; accent?: string; title?: string }) {
  return (
    <div className={cx(surface, 'p-4')}>
      <div className="text-xs font-medium text-slate-500">{label}</div>
      <div className={cx('text-2xl font-semibold mt-1 tabular-nums', accent)} title={title}>
        {value}
      </div>
      {sub && <div className="text-xs text-slate-400 mt-1 truncate">{sub}</div>}
    </div>
  )
}

// StatusMix shows proxied responses by status class as one stacked bar.
function StatusMix({ snap }: { snap: Snapshot }) {
  const parts = [
    { label: '2xx', n: snap.status_2xx, bar: 'bg-emerald-500' },
    { label: '3xx', n: snap.status_3xx, bar: 'bg-sky-500' },
    { label: '4xx', n: snap.status_4xx, bar: 'bg-amber-500' },
    { label: '5xx', n: snap.status_5xx, bar: 'bg-rose-500' },
  ]
  const total = parts.reduce((a, p) => a + p.n, 0)
  return (
    <div className={cx(surface, 'px-4 py-3')}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 mb-2">
        <span className="text-xs font-medium text-slate-500">Proxied responses</span>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
          {parts.map((p) => (
            <span key={p.label} className="flex items-center gap-1.5">
              <span className={cx('w-2 h-2 rounded-full', p.bar)} />
              {p.label} <span className="text-slate-700 dark:text-slate-300 tabular-nums">{formatNumber(p.n)}</span>
              <span className="text-slate-400">({percent(p.n, total)})</span>
            </span>
          ))}
        </div>
      </div>
      <div className="flex h-2 rounded-full overflow-hidden bg-slate-100 dark:bg-slate-800">
        {total > 0 &&
          parts.map((p) => (p.n ? <div key={p.label} className={p.bar} style={{ width: `${(p.n / total) * 100}%` }} /> : null))}
      </div>
    </div>
  )
}

function Legend() {
  return (
    <div className="hidden sm:flex items-center gap-3 text-xs text-slate-500">
      <span className="flex items-center gap-1">
        <span className="inline-block w-3 h-1.5 rounded bg-blue-500" />
        requests
      </span>
      <span className="flex items-center gap-1">
        <span className="inline-block w-3 h-1.5 rounded bg-rose-500" />
        blocked
      </span>
    </div>
  )
}

function HourlyChart({ range }: { range: string }) {
  const [series, setSeries] = useState<Bucket[] | null>(null)
  const [error, setError] = useState('')
  usePoll(
    async () => {
      try {
        const r = await api.hourly(range)
        setSeries(r.series ?? [])
        setError('')
      } catch (err: any) {
        setError(err?.message || 'failed to load history')
      }
    },
    60000,
    true,
    [range],
  )
  if (error) return <ErrorText>{error}</ErrorText>
  if (!series) return <div className="h-52" />
  const short = range === '24h'
  const d = (t: number) => new Date(t * 60000)
  return (
    <TrafficChart
      series={series}
      unit="hour"
      tick={(t) =>
        short
          ? d(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          : d(t).toLocaleDateString([], { month: 'short', day: 'numeric' })
      }
      full={(t) => d(t).toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
    />
  )
}

interface TopData {
  data: { ips: Counted[]; paths: Counted[]; banned: Record<string, boolean> } | null
  error: string
}

// useTop loads the top lists for a range, refreshing every 30s.
function useTop(range: string): TopData {
  const [data, setData] = useState<TopData['data']>(null)
  const [error, setError] = useState('')
  usePoll(
    async () => {
      try {
        const r = await api.top(range, 10)
        setData({ ips: r.ips ?? [], paths: r.paths ?? [], banned: r.banned ?? {} })
        setError('')
      } catch (err: any) {
        setError(err?.message || 'failed to load')
      }
    },
    30000,
    true,
    [range],
  )
  return { data, error }
}

function TopIPs({ top: { data, error }, label }: { top: TopData; label: string }) {
  const nav = useNav()
  return (
    <Card title={`Top IPs · ${label}`} bodyClassName="py-2">
      <ErrorText>{error}</ErrorText>
      <CountList
        items={data?.ips}
        render={(c) => (
          <>
            <IPLink ip={c.key} onOpen={nav.openIP} className="truncate" />
            {data?.banned[c.key] && <Badge tone="rose">banned</Badge>}
          </>
        )}
      />
    </Card>
  )
}

function TopPaths({ top: { data, error }, range, label }: { top: TopData; range: string; label: string }) {
  const nav = useNav()
  return (
    <Card title={`Top paths · ${label}`} bodyClassName="py-2">
      <ErrorText>{error}</ErrorText>
      <CountList
        items={data?.paths}
        render={(c) => (
          <button
            type="button"
            onClick={() => nav.searchRequests({ q: c.key, range })}
            title={`Show requests for ${c.key}`}
            className="font-mono truncate text-left hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline underline-offset-2"
          >
            {c.key}
          </button>
        )}
      />
    </Card>
  )
}

// CountList renders ranked rows with a proportional bar behind each count.
function CountList({ items, render }: { items?: Counted[]; render: (c: Counted) => ReactNode }) {
  if (!items) return <div className="h-24" />
  if (!items.length) return <p className="px-4 py-2 text-sm text-slate-400">no requests in this range</p>
  const max = items[0].count
  return (
    <ul className="text-sm">
      {items.map((c) => (
        <li key={c.key} className="relative flex items-center gap-2 px-4 py-1">
          <div
            className="absolute inset-y-0.5 left-2 rounded bg-slate-100 dark:bg-slate-800/70"
            style={{ width: `calc(${(c.count / max) * 100}% - 1rem)` }}
          />
          <div className="relative flex min-w-0 flex-1 items-center gap-2">{render(c)}</div>
          <span className="relative tabular-nums text-slate-500">{formatNumber(c.count)}</span>
        </li>
      ))}
    </ul>
  )
}

function HistoryNote({ archive }: { archive?: ArchiveInfo }) {
  if (!archive?.enabled) {
    return (
      <p className="text-xs text-slate-400">
        History: in memory only. Set <code className="font-mono">stats.archive</code> to keep weeks of searchable history on disk.
      </p>
    )
  }
  return (
    <p className="text-xs text-slate-400">
      History: {archive.retention_days} days on disk · {archive.segments} hourly segments · {formatBytes(archive.bytes)}
      {archive.dropped ? <span className="text-amber-500"> · {formatNumber(archive.dropped)} requests not archived (writer fell behind)</span> : null}
    </p>
  )
}
