import { FormEvent, useState } from 'react'
import { api, setToken } from '../api'

export default function Login({ onLoggedIn }: { onLoggedIn: (username: string) => void }) {
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
      onLoggedIn(r.username)
    } catch (err: any) {
      setError(err?.message || 'login failed')
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-6">
          <img src="/appicon.png" alt="thorngate" className="w-16 h-16 mb-3" />
          <h1 className="text-2xl font-semibold tracking-tight">thorngate</h1>
          <p className="text-sm text-slate-400 mt-1">admin portal</p>
        </div>

        <form
          onSubmit={submit}
          className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4"
        >
          <div>
            <label className="block text-xs font-medium text-slate-500 mb-1">Username</label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              autoComplete="username"
              className="w-full px-3 py-2 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm outline-none focus:ring-2 focus:ring-emerald-500/40"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-500 mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="w-full px-3 py-2 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-sm outline-none focus:ring-2 focus:ring-emerald-500/40"
            />
          </div>

          {error && <p className="text-sm text-rose-500">{error}</p>}

          <button
            type="submit"
            disabled={busy}
            className="w-full px-3 py-2 rounded-md bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 text-white text-sm font-medium"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>

          <p className="text-xs text-slate-400 text-center">
            Default credentials are <code className="font-mono">admin</code> /{' '}
            <code className="font-mono">admin</code> — change the password from Settings after signing in.
          </p>
        </form>
      </div>
    </div>
  )
}
