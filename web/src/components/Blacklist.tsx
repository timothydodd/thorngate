import { FormEvent, useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { BlacklistEntry } from '../types'

export default function Blacklist() {
  const [list, setList] = useState<BlacklistEntry[]>([])
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')

  const load = useCallback(async () => {
    try {
      const l = await api.blacklist()
      setList(l)
      setErr('')
      setMsg(l.length ? `${l.length} blacklisted` : 'no blacklisted IPs')
    } catch (e: any) {
      setErr(e?.message || 'failed to load')
    }
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, 10000)
    return () => clearInterval(id)
  }, [load])

  async function add(e: FormEvent) {
    e.preventDefault()
    const v = ip.trim()
    if (!v) return
    try {
      await api.ban(v, reason.trim())
      setIp('')
      setReason('')
      setErr('')
      load()
    } catch (e: any) {
      setErr(e?.message || 'ban failed')
    }
  }

  async function remove(target: string) {
    try {
      await api.unban(target)
      load()
    } catch (e: any) {
      setErr(e?.message || 'unban failed')
    }
  }

  return (
    <div className="space-y-4">
      <form onSubmit={add} className="flex flex-wrap items-center gap-2">
        <input
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="IP or CIDR to ban (e.g. 1.2.3.4 or 1.2.3.0/24)"
          className="flex-1 min-w-[240px] px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm outline-none focus:ring-2 focus:ring-emerald-500/40"
        />
        <input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="reason (optional)"
          className="px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm outline-none focus:ring-2 focus:ring-emerald-500/40"
        />
        <button
          type="submit"
          className="px-3 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium"
        >
          Ban
        </button>
      </form>

      <p className={'text-sm min-h-[1.25rem] ' + (err ? 'text-rose-500' : 'text-slate-500')}>{err || msg}</p>

      <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-100 dark:bg-slate-800/60 text-slate-500 text-xs uppercase tracking-wide">
              <tr>
                {['IP', 'Reason', 'Expires', 'Added', ''].map((h, i) => (
                  <th key={i} className="text-left font-medium px-4 py-2 whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {!list.length ? (
                <tr>
                  <td colSpan={5} className="px-4 py-3 text-slate-400">
                    no blacklisted IPs
                  </td>
                </tr>
              ) : (
                list.map((e) => (
                  <tr key={e.ip}>
                    <td className="px-4 py-2 font-mono whitespace-nowrap">{e.ip}</td>
                    <td className="px-4 py-2">{e.reason || ''}</td>
                    <td className="px-4 py-2 whitespace-nowrap">
                      {e.until ? (
                        new Date(e.until).toLocaleString()
                      ) : (
                        <span className="text-xs px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-700">
                          permanent
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-slate-400 whitespace-nowrap">
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={() => remove(e.ip)}
                        className="px-2.5 py-1 rounded-md bg-rose-600 hover:bg-rose-500 text-white text-xs"
                      >
                        Unban
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
