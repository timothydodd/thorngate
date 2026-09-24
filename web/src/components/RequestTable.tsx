import { ago, formatBytes, fullTime } from '../format'
import { useNav } from '../nav'
import { RequestEvent, RequestsResponse } from '../types'
import { Badge, Button, IPLink, OutcomeBadge, StatusText, cx, rowClass, tdClass, thClass, theadClass } from './ui'

// An IP gets a request-count badge once it has more than this many requests
// in the selected range.
const BADGE_THRESHOLD = 5

const COLUMNS: { label: string; className?: string }[] = [
  { label: 'Time' },
  { label: 'IP' },
  { label: 'Method' },
  { label: 'Host', className: 'hidden lg:table-cell' },
  { label: 'Path' },
  { label: 'Upstream', className: 'hidden 2xl:table-cell' },
  { label: 'Status' },
  { label: 'Sent', className: 'hidden md:table-cell' },
  { label: 'Outcome' },
  { label: '' },
]

export default function RequestTable({
  data,
  onDetails,
  onBanned,
  empty,
  maxHeight = 'max-h-[36rem]',
}: {
  data: RequestsResponse | null
  onDetails: (e: RequestEvent) => void
  onBanned: () => void
  empty: string
  maxHeight?: string
}) {
  const nav = useNav()
  return (
    <div className={cx(maxHeight, 'overflow-auto')}>
      <table className="w-full text-sm">
        <thead className={theadClass}>
          <tr>
            {COLUMNS.map((c, i) => (
              <th key={i} className={cx(thClass, c.className)}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
          {!data?.events?.length ? (
            <tr>
              <td colSpan={COLUMNS.length} className="px-4 py-3 text-slate-400">
                {data ? empty : 'loading…'}
              </td>
            </tr>
          ) : (
            data.events.map((e, i) => {
              const pathFull = e.path + (e.query ? '?' + e.query : '')
              const count = data.ip_counts?.[e.ip] ?? 0
              const banned = data.banned?.[e.ip]
              return (
                <tr key={i} className={rowClass}>
                  <td className={cx(tdClass, 'text-slate-400 whitespace-nowrap')} title={fullTime(e.time)}>
                    {ago(e.time)}
                  </td>
                  <td className={cx(tdClass, 'whitespace-nowrap')}>
                    <div className="flex items-center gap-1.5">
                      <IPLink ip={e.ip} onOpen={nav.openIP} />
                      {e.country && (
                        <span className="text-[10px] font-semibold text-slate-400" title={`Country: ${e.country}`}>
                          {e.country}
                        </span>
                      )}
                      {count > BADGE_THRESHOLD && (
                        <Badge tone="amber" title={`${count} requests from ${e.ip} in this range`}>
                          {count}
                        </Badge>
                      )}
                    </div>
                  </td>
                  <td className={tdClass}>{e.method}</td>
                  <td className={cx(tdClass, 'hidden lg:table-cell font-mono max-w-[11rem] truncate')} title={e.host}>
                    {e.host}
                  </td>
                  <td className={cx(tdClass, 'font-mono max-w-[18rem] truncate')} title={pathFull}>
                    {pathFull}
                  </td>
                  <td
                    className={cx(tdClass, 'hidden 2xl:table-cell font-mono max-w-[11rem] truncate text-slate-500')}
                    title={e.upstream}
                  >
                    {e.upstream || '—'}
                  </td>
                  <td className={tdClass}>
                    <StatusText code={e.status} deny={e.deny} />
                  </td>
                  <td className={cx(tdClass, 'hidden md:table-cell text-slate-500 whitespace-nowrap')}>
                    {e.outcome === 'proxied' ? formatBytes(e.bytes) : '—'}
                  </td>
                  <td className={tdClass}>
                    <OutcomeBadge outcome={e.outcome} />
                  </td>
                  <td className={cx(tdClass, 'text-right whitespace-nowrap')}>
                    <Button size="sm" onClick={() => onDetails(e)}>
                      Details
                    </Button>
                    {banned ? (
                      <span className="ml-1.5">
                        <Badge tone="rose" title={`${e.ip} is currently blocked`}>
                          banned
                        </Badge>
                      </span>
                    ) : (
                      <Button size="sm" variant="danger-outline" className="ml-1.5" onClick={() => nav.ban(e.ip, onBanned)}>
                        Ban
                      </Button>
                    )}
                  </td>
                </tr>
              )
            })
          )}
        </tbody>
      </table>
    </div>
  )
}
