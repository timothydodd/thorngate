import { FormEvent, useState } from 'react'
import { api } from '../api'
import { Button, Card, ErrorText, Field, cx, inputClass } from './ui'

export const MIN_PASSWORD = 8

// PasswordForm changes the admin password. With knownCurrent set (the forced
// first-login change, where the current password is the default), the current
// password field is hidden and that value is sent instead.
export function PasswordForm({ knownCurrent, onChanged }: { knownCurrent?: string; onChanged?: () => void }) {
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
    if (next.length < MIN_PASSWORD) {
      setErr(`use at least ${MIN_PASSWORD} characters`)
      return
    }
    if (next !== confirm) {
      setErr('new passwords do not match')
      return
    }
    setBusy(true)
    try {
      await api.changePassword(knownCurrent ?? current, next)
      setMsg('Password changed. Other sessions have been signed out.')
      setCurrent('')
      setNext('')
      setConfirm('')
      onChanged?.()
    } catch (e: any) {
      setErr(e?.message || 'could not change password')
    } finally {
      setBusy(false)
    }
  }

  const field = cx(inputClass, 'w-full py-2')
  return (
    <form onSubmit={submit} className="space-y-4">
      {knownCurrent === undefined && (
        <Field label="Current password">
          <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" className={field} />
        </Field>
      )}
      <Field label={`New password (at least ${MIN_PASSWORD} characters)`}>
        <input
          type="password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          autoComplete="new-password"
          autoFocus={knownCurrent !== undefined}
          className={field}
        />
      </Field>
      <Field label="Confirm new password">
        <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" className={field} />
      </Field>
      <ErrorText>{err}</ErrorText>
      {msg && <p className="text-sm text-emerald-600 dark:text-emerald-400">{msg}</p>}
      <Button type="submit" variant="primary" disabled={busy} className={knownCurrent !== undefined ? 'w-full py-2' : ''}>
        {busy ? 'Saving…' : knownCurrent !== undefined ? 'Set password and continue' : 'Update password'}
      </Button>
    </form>
  )
}

export default function Settings({ username }: { username: string }) {
  return (
    <div className="grid gap-5 lg:grid-cols-2 items-start max-w-5xl">
      <div className="space-y-5">
        <Card title="Account">
          <p className="text-sm text-slate-500">
            Signed in as <span className="font-medium text-slate-700 dark:text-slate-200">{username}</span>
          </p>
        </Card>
        <Card title="Change password">
          <PasswordForm />
        </Card>
      </div>
      <ReloadConfig />
    </div>
  )
}

function ReloadConfig() {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ ok: boolean; text: string; restart?: string[] } | null>(null)

  async function reload() {
    setBusy(true)
    setResult(null)
    try {
      const r = await api.reload()
      setResult({ ok: true, text: 'Config reloaded.', restart: r.restart_required })
    } catch (e: any) {
      setResult({ ok: false, text: e?.message || 'reload failed' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Configuration">
      <div className="space-y-3 text-sm">
        <p className="text-slate-500">
          Re-read <code className="font-mono">config.json</code> without restarting. Honeypots, the whitelist, block action,
          tarpit settings, headers and <code className="font-mono">ipv6_ban_prefix</code> apply immediately; upstreams, routes,
          ports and feature settings need a restart. Sending the process <code className="font-mono">SIGHUP</code> does the
          same.
        </p>
        <Button onClick={reload} disabled={busy}>
          {busy ? 'Reloading…' : 'Reload config'}
        </Button>
        {result && (
          <div className={result.ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-500'}>
            <p>{result.text}</p>
            {result.restart && result.restart.length > 0 && (
              <p className="text-amber-600 dark:text-amber-400 mt-1">
                Changed but needs a restart: <span className="font-mono">{result.restart.join(', ')}</span>
              </p>
            )}
          </div>
        )}
      </div>
    </Card>
  )
}
