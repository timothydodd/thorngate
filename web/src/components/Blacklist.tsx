import { FormEvent, useMemo, useState } from 'react'
import { api } from '../api'
import { ago, formatNumber, fullTime, isRange, until } from '../format'
import { usePoll } from '../hooks'
import { useNav } from '../nav'
import { BlacklistEntry, ImportResult, WhitelistEntry } from '../types'
import { DURATIONS } from './BanDialog'
import {
  Badge,
  Button,
  Card,
  ErrorText,
  IPLink,
  Modal,
  Pager,
  Segmented,
  cx,
  inputClass,
  rowClass,
  surface,
  tdClass,
  thClass,
  theadClass,
} from './ui'

const PAGE_SIZE = 50

type Kind = 'all' | 'permanent' | 'temporary' | 'range'
type Sort = 'newest' | 'oldest' | 'expiring' | 'ip'

export default function Blacklist() {
  const nav = useNav()
  const [list, setList] = useState<BlacklistEntry[] | null>(null)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState<Kind>('all')
  const [sort, setSort] = useState<Sort>('newest')
  const [page, setPage] = useState(1)
  const [importing, setImporting] = useState(false)

  const load = async () => {
    try {
      setList(await api.blacklist())
      setErr('')
    } catch (e: any) {
      setErr(e?.message || 'failed to load')
    }
  }
  usePoll(load, 10000)

  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase()
    const out = (list ?? []).filter((e) => {
      if (kind === 'permanent' && e.until) return false
      if (kind === 'temporary' && !e.until) return false
      if (kind === 'range' && !isRange(e.ip)) return false
      if (!needle) return true
      return [e.ip, e.reason, e.path ?? ''].some((f) => f.toLowerCase().includes(needle))
    })
    const t = (s?: string) => (s ? new Date(s).getTime() : Infinity)
    out.sort((a, b) => {
      switch (sort) {
        case 'oldest':
          return t(a.timestamp) - t(b.timestamp)
        case 'expiring':
          return t(a.until) - t(b.until)
        case 'ip':
          return a.ip.localeCompare(b.ip, undefined, { numeric: true })
        default:
          return t(b.timestamp) - t(a.timestamp)
      }
    })
    return out
  }, [list, search, kind, sort])

  const pages = Math.max(1, Math.ceil(shown.length / PAGE_SIZE))
  const cur = Math.min(page, pages)
  const rows = shown.slice((cur - 1) * PAGE_SIZE, cur * PAGE_SIZE)

  async function remove(target: string) {
    const what = isRange(target) ? `the range ${target} (unbans every address in it)` : target
    if (!window.confirm(`Unban ${what}?`)) return
    try {
      await api.unban(target)
      setMsg(`Unbanned ${target}.`)
      load()
    } catch (e: any) {
      setErr(e?.message || 'unban failed')
    }
  }

  async function exportList() {
    try {
      const blob = await api.exportBlacklist()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `thorngate-blacklist-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e: any) {
      setErr(e?.message || 'export failed')
    }
  }

  const counts = useMemo(() => {
    const l = list ?? []
    return {
      all: l.length,
      permanent: l.filter((e) => !e.until).length,
      temporary: l.filter((e) => e.until).length,
      range: l.filter((e) => isRange(e.ip)).length,
    }
  }, [list])

  return (
    <div className="space-y-4">
      <AddBan
        onAdded={(m) => {
          setMsg(m)
          setErr('')
          load()
        }}
        onError={setErr}
      />

      {(err || msg) && <p className={cx('text-sm', err ? 'text-rose-500' : 'text-emerald-600 dark:text-emerald-400')}>{err || msg}</p>}

      <div className={cx(surface, 'overflow-hidden')}>
        <div className="p-3 flex flex-wrap items-center gap-2 border-b border-slate-200 dark:border-slate-800">
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
            placeholder="Search IP, reason or path"
            className={cx(inputClass, 'flex-1 min-w-[200px]')}
          />
          <Segmented<Kind>
            value={kind}
            onChange={(k) => {
              setKind(k)
              setPage(1)
            }}
            options={[
              { value: 'all', label: `All ${counts.all}` },
              { value: 'permanent', label: `Permanent ${counts.permanent}` },
              { value: 'temporary', label: `Temporary ${counts.temporary}` },
              { value: 'range', label: `Ranges ${counts.range}` },
            ]}
          />
          <select value={sort} onChange={(e) => setSort(e.target.value as Sort)} className={cx(inputClass, 'py-1')}>
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
            <option value="expiring">Expiring soonest</option>
            <option value="ip">By address</option>
          </select>
          <Button onClick={exportList}>Export</Button>
          <Button onClick={() => setImporting(true)}>Import…</Button>
        </div>

        <div className="max-h-[36rem] overflow-auto">
          <table className="w-full text-sm">
            <thead className={theadClass}>
              <tr>
                {['Address', 'Reason', 'Expires', 'Added', ''].map((h, i) => (
                  <th key={i} className={thClass}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {!rows.length ? (
                <tr>
                  <td colSpan={5} className="px-4 py-3 text-slate-400">
                    {list === null ? 'loading…' : list.length ? 'nothing matches' : 'no blacklisted IPs'}
                  </td>
                </tr>
              ) : (
                rows.map((e) => (
                  <tr key={e.ip} className={rowClass}>
                    <td className={cx(tdClass, 'whitespace-nowrap')}>
                      {isRange(e.ip) ? (
                        <span className="font-mono">
                          {e.ip} <Badge tone="violet">range</Badge>
                        </span>
                      ) : (
                        <IPLink ip={e.ip} onOpen={nav.openIP} />
                      )}
                    </td>
                    <td className={tdClass}>
                      <span>{e.reason}</span>
                      {e.path && (
                        <span className="ml-2 font-mono text-xs text-slate-400" title="honeypot that was hit">
                          {e.path}
                        </span>
                      )}
                    </td>
                    <td className={cx(tdClass, 'whitespace-nowrap')}>
                      {e.until ? (
                        <span title={fullTime(e.until)} className="text-amber-600 dark:text-amber-400">
                          {until(e.until)}
                        </span>
                      ) : (
                        <Badge>permanent</Badge>
                      )}
                    </td>
                    <td className={cx(tdClass, 'text-slate-400 whitespace-nowrap')} title={fullTime(e.timestamp)}>
                      {ago(e.timestamp)}
                    </td>
                    <td className={cx(tdClass, 'text-right')}>
                      <Button size="sm" variant="danger-outline" onClick={() => remove(e.ip)}>
                        Unban
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        {pages > 1 && <Pager page={cur} pages={pages} onPage={setPage} note={`${formatNumber(shown.length)} entries`} />}
      </div>

      <Whitelist />

      {importing && (
        <ImportDialog
          onClose={() => setImporting(false)}
          onDone={(r) => {
            setMsg(`Imported ${r.added} new ban${r.added === 1 ? '' : 's'}${r.skipped ? `, ${r.skipped} already banned or whitelisted` : ''}.`)
            load()
          }}
        />
      )}
    </div>
  )
}

function AddBan({ onAdded, onError }: { onAdded: (msg: string) => void; onError: (e: string) => void }) {
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState('permanent')

  async function add(e: FormEvent) {
    e.preventDefault()
    const v = ip.trim()
    if (!v) return
    try {
      const r = await api.ban(v, reason.trim(), duration)
      setIp('')
      setReason('')
      onAdded(r.added ? `Banned ${r.ip}${duration === 'permanent' ? '' : ` for ${duration}`}.` : `${r.ip} was already banned.`)
    } catch (err: any) {
      onError(err?.message || 'ban failed')
    }
  }

  return (
    <form onSubmit={add} className={cx(surface, 'p-3 flex flex-wrap items-center gap-2')}>
      <input
        value={ip}
        onChange={(e) => setIp(e.target.value)}
        placeholder="IP or CIDR to ban (1.2.3.4, 1.2.3.0/24, 2001:db8::/64)"
        spellCheck={false}
        className={cx(inputClass, 'flex-1 min-w-[240px] font-mono')}
      />
      <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="reason (optional)" className={inputClass} />
      <select value={duration} onChange={(e) => setDuration(e.target.value)} className={cx(inputClass, 'py-1')}>
        {DURATIONS.map((d) => (
          <option key={d.value} value={d.value}>
            {d.label}
          </option>
        ))}
      </select>
      <Button type="submit" variant="primary">
        Ban
      </Button>
    </form>
  )
}

function ImportDialog({ onClose, onDone }: { onClose: () => void; onDone: (r: ImportResult) => void }) {
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<ImportResult | null>(null)

  async function pick(f: File | undefined) {
    if (f) setText(await f.text())
  }

  async function submit() {
    setBusy(true)
    setError('')
    try {
      const r = await api.importBlacklist(text)
      setResult(r)
      onDone(r)
    } catch (e: any) {
      setError(e?.message || 'import failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title="Import bans"
      onClose={onClose}
      footer={
        result ? (
          <Button onClick={onClose}>Done</Button>
        ) : (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" disabled={busy || !text.trim()} onClick={submit}>
              {busy ? 'Importing…' : 'Import'}
            </Button>
          </>
        )
      }
    >
      {result ? (
        <div className="space-y-2 text-sm">
          <p>
            <span className="font-semibold">{result.added}</span> new ban{result.added === 1 ? '' : 's'} added
            {result.skipped > 0 && <>, {result.skipped} skipped (already banned, whitelisted or expired)</>}.
          </p>
          {result.invalid.length > 0 && (
            <p className="text-amber-600 dark:text-amber-400">
              Not valid addresses: <span className="font-mono">{result.invalid.join(', ')}</span>
            </p>
          )}
        </div>
      ) : (
        <div className="space-y-3 text-sm">
          <p className="text-slate-500">
            Paste a thorngate export (JSON), or a plain list with one IP or CIDR per line — the format of most public
            blocklists. Lines starting with <code className="font-mono">#</code> are ignored. Imported bans are permanent
            unless an export entry carries an expiry.
          </p>
          <input type="file" accept=".json,.txt,.csv,.list,text/plain,application/json" onChange={(e) => pick(e.target.files?.[0])} className="text-xs" />
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={10}
            spellCheck={false}
            placeholder={'1.2.3.4\n5.6.7.0/24\n# comment'}
            className={cx(inputClass, 'w-full font-mono text-xs')}
          />
          <ErrorText>{error}</ErrorText>
        </div>
      )}
    </Modal>
  )
}

function Whitelist() {
  const [list, setList] = useState<WhitelistEntry[] | null>(null)
  usePoll(async () => {
    try {
      setList(await api.whitelist())
    } catch {
      // non-critical
    }
  }, 60000)
  return (
    <Card title="Whitelist" actions={<span className="text-xs text-slate-400">edit in config.json, then reload it from Settings</span>}>
      {!list?.length ? (
        <p className="text-sm text-slate-400">{list ? 'No whitelisted addresses.' : 'loading…'}</p>
      ) : (
        <div className="flex flex-wrap gap-2">
          {list.map((w) => (
            <span key={w.ip} className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 dark:border-slate-800 px-2 py-1 text-sm">
              <span className="font-mono">{w.ip}</span>
              {w.no_log && (
                <Badge tone="sky" title="Kept out of stats and request history">
                  no log
                </Badge>
              )}
            </span>
          ))}
        </div>
      )}
    </Card>
  )
}
