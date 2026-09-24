import { ReactNode, useState } from 'react'
import { api } from '../api'
import { ago, formatNumber, fullTime, isRange, percent, until } from '../format'
import { usePoll } from '../hooks'
import { useNav } from '../nav'
import { IPProfile, RequestEvent, RequestsResponse } from '../types'
import DetailsModal from './DetailsModal'
import { Badge, Button, Card, Drawer, ErrorText, Muted, OutcomeBadge, StatusText, cx, rowClass, tdClass, thClass, theadClass } from './ui'

// IPPanel profiles one client: its ban or whitelist status, a summary of its
// traffic, and its latest requests, with ban/unban actions.
export default function IPPanel({ ip, onClose }: { ip: string; onClose: () => void }) {
  const nav = useNav()
  const [profile, setProfile] = useState<IPProfile | null>(null)
  const [recent, setRecent] = useState<RequestsResponse | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const [selected, setSelected] = useState<RequestEvent | null>(null)
  const range = nav.archive ? '30d' : '24h'

  const load = async () => {
    try {
      const [p, r] = await Promise.all([api.ip(ip), api.requests({ ip, range }, 1, 15)])
      setProfile(p)
      setRecent(r)
      setError('')
    } catch (err: any) {
      setError(err?.message || 'failed to load')
    }
  }
  usePoll(load, 15000, true, [ip])

  async function unban(key: string) {
    const what = isRange(key) ? `the range ${key} (unbans every address in it)` : key
    if (!window.confirm(`Unban ${what}?`)) return
    setBusy(true)
    try {
      await api.unban(key)
      await load()
    } catch (err: any) {
      setError(err?.message || 'unban failed')
    } finally {
      setBusy(false)
    }
  }

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(ip)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      // clipboard unavailable (e.g. non-secure context); ignore
    }
  }

  const s = profile?.summary
  const ban = profile?.ban

  return (
    <Drawer
      onClose={onClose}
      title={
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-mono font-semibold truncate">{ip}</span>
          <button type="button" onClick={copy} className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
            {copied ? 'copied' : 'copy'}
          </button>
        </div>
      }
    >
      <ErrorText>{error}</ErrorText>
      {!profile ? (
        <Muted>loading…</Muted>
      ) : (
        <>
          {/* Status + actions */}
          <Card>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="space-y-1 text-sm">
                {ban ? (
                  <>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="rose">{ban.until ? 'temp-banned' : 'banned'}</Badge>
                      <span className="text-slate-500">{ban.reason}</span>
                    </div>
                    {isRange(ban.ip) && (
                      <p className="text-xs text-slate-500">
                        via the range <span className="font-mono">{ban.ip}</span>
                      </p>
                    )}
                    {ban.path && (
                      <p className="text-xs text-slate-500">
                        honeypot <span className="font-mono">{ban.path}</span>
                      </p>
                    )}
                    <p className="text-xs text-slate-400">
                      since {fullTime(ban.timestamp)}
                      {ban.until && <> · expires {until(ban.until)}</>}
                    </p>
                  </>
                ) : profile.whitelisted ? (
                  <div className="flex items-center gap-2">
                    <Badge tone="emerald">whitelisted</Badge>
                    <span className="text-slate-500 text-xs">never banned</span>
                  </div>
                ) : (
                  <Badge tone="slate">not banned</Badge>
                )}
                {s?.country && <p className="text-xs text-slate-500">Country: {s.country}</p>}
              </div>
              <div className="flex flex-wrap gap-2">
                {ban ? (
                  <Button variant="danger-outline" disabled={busy} onClick={() => unban(ban.ip)}>
                    {isRange(ban.ip) ? 'Unban range' : 'Unban'}
                  </Button>
                ) : (
                  !profile.whitelisted && (
                    <Button variant="danger" onClick={() => nav.ban(ip, load)}>
                      Ban…
                    </Button>
                  )
                )}
                <Button
                  onClick={() => {
                    onClose()
                    nav.searchRequests({ ip, range })
                  }}
                >
                  All requests
                </Button>
                {ban && isRange(ban.ip) && (
                  <Button
                    title={`Requests from every address in ${ban.ip}`}
                    onClick={() => {
                      onClose()
                      nav.searchRequests({ ip: ban.ip, range })
                    }}
                  >
                    Range requests
                  </Button>
                )}
              </div>
            </div>
          </Card>

          {/* Traffic summary */}
          {s && s.requests > 0 ? (
            <Card title={`Activity · last ${range === '30d' ? '30 days' : '24 hours'}`}>
              <div className="grid grid-cols-3 gap-3 text-sm mb-4">
                <Fact label="Requests" value={formatNumber(s.requests)} />
                <Fact label="First seen" value={s.first_seen ? ago(s.first_seen) : '—'} title={s.first_seen && fullTime(s.first_seen)} />
                <Fact label="Last seen" value={s.last_seen ? ago(s.last_seen) : '—'} title={s.last_seen && fullTime(s.last_seen)} />
              </div>
              <Breakdown label="Outcome" counts={s.outcomes} total={s.requests} tone={{ proxied: 'bg-slate-400', blocked: 'bg-rose-500', honeypot: 'bg-amber-500' }} />
              <Breakdown
                label="Status"
                counts={s.statuses}
                total={s.requests}
                tone={{ '2xx': 'bg-emerald-500', '3xx': 'bg-sky-500', '4xx': 'bg-amber-500', '5xx': 'bg-rose-500', none: 'bg-slate-400' }}
              />
              {s.ua && (
                <p className="mt-3 text-xs text-slate-500 break-all">
                  <span className="text-slate-400">User agent</span> <span className="font-mono">{s.ua}</span>
                </p>
              )}
            </Card>
          ) : (
            <Card>
              <Muted>No requests from this IP in the last {range === '30d' ? '30 days' : '24 hours'}.</Muted>
            </Card>
          )}

          {s && s.paths.length > 0 && (
            <Card title="Top paths" bodyClassName="py-2">
              <ul className="text-sm">
                {s.paths.map((p) => (
                  <li key={p.key} className="flex items-center justify-between gap-3 px-4 py-1">
                    <span className="font-mono truncate" title={p.key}>
                      {p.key}
                    </span>
                    <span className="tabular-nums text-slate-500">{formatNumber(p.count)}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {recent && recent.events.length > 0 && (
            <Card title="Latest requests" bodyClassName="">
              <table className="w-full text-sm">
                <thead className={theadClass}>
                  <tr>
                    {['Time', 'Method', 'Path', 'Status', ''].map((h, i) => (
                      <th key={i} className={thClass}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {recent.events.map((e, i) => (
                    <tr key={i} className={cx(rowClass, 'cursor-pointer')} onClick={() => setSelected(e)}>
                      <td className={cx(tdClass, 'text-slate-400 whitespace-nowrap')} title={fullTime(e.time)}>
                        {ago(e.time)}
                      </td>
                      <td className={tdClass}>{e.method}</td>
                      <td className={cx(tdClass, 'font-mono max-w-[14rem] truncate')} title={e.path}>
                        {e.path}
                      </td>
                      <td className={tdClass}>
                        <StatusText code={e.status} deny={e.deny} />
                      </td>
                      <td className={tdClass}>
                        <OutcomeBadge outcome={e.outcome} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Card>
          )}
        </>
      )}
      {selected && <DetailsModal event={selected} onClose={() => setSelected(null)} />}
    </Drawer>
  )
}

function Fact({ label, value, title }: { label: string; value: ReactNode; title?: string }) {
  return (
    <div title={title}>
      <div className="text-xs text-slate-400">{label}</div>
      <div className="font-medium tabular-nums">{value}</div>
    </div>
  )
}

// Breakdown is a labelled stacked bar of counts by category.
function Breakdown({
  label,
  counts,
  total,
  tone,
}: {
  label: string
  counts: Record<string, number>
  total: number
  tone: Record<string, string>
}) {
  const parts = Object.entries(counts).sort((a, b) => b[1] - a[1])
  return (
    <div className="mt-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500 mb-1">
        <span className="text-slate-400 w-14">{label}</span>
        {parts.map(([k, n]) => (
          <span key={k} className="flex items-center gap-1">
            <span className={cx('w-2 h-2 rounded-full', tone[k] ?? 'bg-slate-400')} />
            {k} {formatNumber(n)} <span className="text-slate-400">({percent(n, total)})</span>
          </span>
        ))}
      </div>
      <div className="flex h-1.5 rounded-full overflow-hidden bg-slate-100 dark:bg-slate-800">
        {parts.map(([k, n]) => (
          <div key={k} className={tone[k] ?? 'bg-slate-400'} style={{ width: `${(n / total) * 100}%` }} />
        ))}
      </div>
    </div>
  )
}
