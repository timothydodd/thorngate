import { FormEvent, ReactNode, useState } from 'react'
import { api, setToken } from '../api'
import { PasswordForm } from './Settings'
import { Button, ErrorText, Field, cx, inputClass, surface } from './ui'

// AuthShell is the centred logo + card layout shared by the sign-in and
// forced password-change screens.
function AuthShell({ subtitle, children }: { subtitle: string; children: ReactNode }) {
  return (
    <div className="flex min-h-full items-center justify-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-6">
          <img src="/appicon.png" alt="thorngate" className="w-16 h-16 mb-3" />
          <h1 className="text-2xl font-semibold tracking-tight">thorngate</h1>
          <p className="text-sm text-slate-400 mt-1">{subtitle}</p>
        </div>
        <div className={cx(surface, 'p-6')}>{children}</div>
      </div>
    </div>
  )
}

export default function Login({ onLoggedIn }: { onLoggedIn: (username: string, mustChange: boolean) => void }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const r = await api.login(username.trim(), password)
      setToken(r.token)
      onLoggedIn(r.username, r.must_change)
    } catch (err: any) {
      setError(err?.message || 'login failed')
      setBusy(false)
    }
  }

  const field = cx(inputClass, 'w-full py-2')
  return (
    <AuthShell subtitle="admin portal">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Username">
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" className={field} />
        </Field>
        <Field label="Password">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" className={field} />
        </Field>
        <ErrorText>{error}</ErrorText>
        <Button type="submit" variant="primary" disabled={busy} className="w-full py-2">
          {busy ? 'Signing in…' : 'Sign in'}
        </Button>
        <p className="text-xs text-slate-400 text-center">
          First sign-in uses <code className="font-mono">admin</code> / <code className="font-mono">admin</code>; you'll be
          asked to set a new password.
        </p>
      </form>
    </AuthShell>
  )
}

// ForcePassword replaces the default password before the portal can be used.
export function ForcePassword({ onDone, onSignOut }: { onDone: () => void; onSignOut: () => void }) {
  return (
    <AuthShell subtitle="set a new admin password">
      <p className="text-sm text-slate-500 mb-4">
        You're signed in with the default password. Choose a new one to continue — until then the portal stays locked.
      </p>
      <PasswordForm knownCurrent="admin" onChanged={onDone} />
      <button type="button" onClick={onSignOut} className="mt-4 w-full text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
        Sign out
      </button>
    </AuthShell>
  )
}
