import { FormEvent, useState } from 'react'
import { api } from '../api'

export default function Settings({ username }: { username: string }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setMsg('')
    setErr('')
    if (next !== confirm) {
      setErr('new passwords do not match')
      return
    }
    setBusy(true)
    try {
      await api.changePassword(current, next)
      setMsg('Password changed.')
      setCurrent('')
      setNext('')
      setConfirm('')
    } catch (e: any) {
      setErr(e?.message || 'could not change password')
    } finally {
      setBusy(false)
    }
  }

  const field =
    'w-full px-3 py-2 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm outline-none focus:ring-2 focus:ring-emerald-500/40'

  return (
    <div className="max-w-md space-y-6">
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
        <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300 mb-1">Account</h2>
        <p className="text-sm text-slate-500">
          Signed in as <span className="font-medium text-slate-700 dark:text-slate-200">{username}</span>
        </p>
      </div>

      <form onSubmit={submit} className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 space-y-4">
        <h2 className="text-sm font-semibold text-slate-600 dark:text-slate-300">Change password</h2>

        <div>
          <label className="block text-xs font-medium text-slate-500 mb-1">Current password</label>
          <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" className={field} />
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-500 mb-1">New password</label>
          <input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" className={field} />
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-500 mb-1">Confirm new password</label>
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" className={field} />
        </div>

        {err && <p className="text-sm text-rose-500">{err}</p>}
        {msg && <p className="text-sm text-emerald-600 dark:text-emerald-400">{msg}</p>}

        <button
          type="submit"
          disabled={busy}
          className="px-3 py-2 rounded-md bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 text-white text-sm font-medium"
        >
          {busy ? 'Saving…' : 'Update password'}
        </button>
      </form>
    </div>
  )
}
