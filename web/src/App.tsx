import { useEffect, useState } from 'react'
import { api, clearToken, getToken, setUnauthorizedHandler } from './api'
import Login from './components/Login'
import Dashboard from './components/Dashboard'
import Blacklist from './components/Blacklist'
import Settings from './components/Settings'

type Tab = 'dashboard' | 'blacklist' | 'settings'
type AuthState = 'checking' | 'in' | 'out'

const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'blacklist', label: 'Blacklist' },
  { id: 'settings', label: 'Settings' },
]

export default function App() {
  const [auth, setAuth] = useState<AuthState>('checking')
  const [username, setUsername] = useState('')
  const [tab, setTab] = useState<Tab>('dashboard')

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearToken()
      setAuth('out')
    })
    if (!getToken()) {
      setAuth('out')
      return
    }
    api
      .me()
      .then((r) => {
        setUsername(r.username)
        setAuth('in')
      })
      .catch(() => setAuth('out'))
  }, [])

  function onLoggedIn(name: string) {
    setUsername(name)
    setTab('dashboard')
    setAuth('in')
  }

  async function logout() {
    try {
      await api.logout()
    } catch {
      // ignore — clearing the token locally is enough
    }
    clearToken()
    setAuth('out')
  }

  if (auth === 'checking') {
    return (
      <div className="flex h-full items-center justify-center text-slate-400 text-sm">
        loading…
      </div>
    )
  }

  if (auth === 'out') {
    return <Login onLoggedIn={onLoggedIn} />
  }

  return (
    <div className="min-h-full">
      <header className="border-b border-slate-200 dark:border-slate-800 bg-white/70 dark:bg-slate-900/60 backdrop-blur sticky top-0 z-20">
        <div className="max-w-screen-2xl mx-auto px-4 h-14 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <img src="/appicon.png" alt="" className="w-7 h-7" />
            <span className="text-lg font-semibold tracking-tight">thorngate</span>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-slate-400 hidden sm:inline">
              signed in as <span className="text-slate-600 dark:text-slate-300 font-medium">{username}</span>
            </span>
            <button
              onClick={logout}
              className="px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              Sign out
            </button>
          </div>
        </div>
        <nav className="max-w-screen-2xl mx-auto px-4 flex gap-1">
          {TABS.map((t) => {
            const on = tab === t.id
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={
                  'px-4 py-2 text-sm font-medium border-b-2 -mb-px ' +
                  (on
                    ? 'border-emerald-500 text-emerald-600 dark:text-emerald-400'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200')
                }
              >
                {t.label}
              </button>
            )
          })}
        </nav>
      </header>

      <main className="max-w-screen-2xl mx-auto px-4 py-6">
        {tab === 'dashboard' && <Dashboard />}
        {tab === 'blacklist' && <Blacklist />}
        {tab === 'settings' && <Settings username={username} />}
      </main>
    </div>
  )
}
