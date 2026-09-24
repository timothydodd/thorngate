import { FormEvent, useEffect, useMemo, useState } from 'react'
import { api, clearToken, getToken, setMustChangeHandler, setUnauthorizedHandler } from './api'
import BanDialog from './components/BanDialog'
import Blacklist from './components/Blacklist'
import Dashboard from './components/Dashboard'
import IPPanel from './components/IPPanel'
import Login, { ForcePassword } from './components/Login'
import Requests, { DEFAULT_FILTER } from './components/Requests'
import Settings from './components/Settings'
import { Button, cx, inputClass } from './components/ui'
import { Nav, NavContext } from './nav'
import { RequestFilter } from './types'

type Tab = 'overview' | 'requests' | 'blacklist' | 'settings'
type AuthState = 'checking' | 'in' | 'out' | 'must-change'

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'requests', label: 'Requests' },
  { id: 'blacklist', label: 'Blacklist' },
  { id: 'settings', label: 'Settings' },
]

// looksLikeIP tells an address (or range) apart from free-text search.
const looksLikeIP = (s: string) => /^[0-9a-f:.]+(\/\d{1,3})?$/i.test(s) && (s.includes('.') || s.includes(':'))

export default function App() {
  const [auth, setAuth] = useState<AuthState>('checking')
  const [username, setUsername] = useState('')
  const [tab, setTab] = useState<Tab>('overview')
  const [filter, setFilter] = useState<RequestFilter>(DEFAULT_FILTER)
  const [panelIP, setPanelIP] = useState<string | null>(null)
  const [banTarget, setBanTarget] = useState<{ ip: string; onDone?: () => void } | null>(null)
  const [archive, setArchive] = useState(false)

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearToken()
      setAuth('out')
    })
    setMustChangeHandler(() => setAuth('must-change'))
    if (!getToken()) {
      setAuth('out')
      return
    }
    api
      .me()
      .then((r) => {
        setUsername(r.username)
        setAuth(r.must_change ? 'must-change' : 'in')
      })
      .catch(() => setAuth('out'))
  }, [])

  // Whether long history exists decides which ranges the views offer.
  useEffect(() => {
    if (auth !== 'in') return
    api
      .stats()
      .then((r) => setArchive(!!r.archive?.enabled))
      .catch(() => {})
  }, [auth])

  const nav: Nav = useMemo(
    () => ({
      openIP: (ip) => setPanelIP(ip),
      searchRequests: (f) => {
        setFilter({ ...DEFAULT_FILTER, ...f })
        setPanelIP(null)
        setTab('requests')
      },
      ban: (ip, onDone) => setBanTarget({ ip, onDone }),
      archive,
    }),
    [archive],
  )

  function onLoggedIn(name: string, mustChange: boolean) {
    setUsername(name)
    setTab('overview')
    setAuth(mustChange ? 'must-change' : 'in')
  }

  async function logout() {
    try {
      await api.logout()
    } catch {
      // ignore — clearing the token locally is enough
    }
    clearToken()
    setPanelIP(null)
    setAuth('out')
  }

  if (auth === 'checking') {
    return <div className="flex h-full items-center justify-center text-slate-400 text-sm">loading…</div>
  }
  if (auth === 'out') return <Login onLoggedIn={onLoggedIn} />
  if (auth === 'must-change') return <ForcePassword onDone={() => setAuth('in')} onSignOut={logout} />

  return (
    <NavContext.Provider value={nav}>
      <div className="min-h-full">
        <header className="border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/70 backdrop-blur sticky top-0 z-20">
          <div className="max-w-screen-2xl mx-auto px-4 h-14 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 shrink-0">
              <img src="/appicon.png" alt="" className="w-7 h-7" />
              <span className="text-lg font-semibold tracking-tight hidden sm:inline">thorngate</span>
            </div>
            <GlobalSearch nav={nav} />
            <div className="flex items-center gap-3 text-sm shrink-0">
              <span className="text-slate-400 hidden md:inline">
                signed in as <span className="text-slate-600 dark:text-slate-300 font-medium">{username}</span>
              </span>
              <Button onClick={logout}>Sign out</Button>
            </div>
          </div>
          <nav className="max-w-screen-2xl mx-auto px-4 flex gap-1 overflow-x-auto">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={cx(
                  'px-4 py-2 text-sm font-medium border-b-2 -mb-px whitespace-nowrap',
                  tab === t.id
                    ? 'border-emerald-500 text-emerald-600 dark:text-emerald-400'
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200',
                )}
              >
                {t.label}
              </button>
            ))}
          </nav>
        </header>

        <main className="max-w-screen-2xl mx-auto px-4 py-6">
          {tab === 'overview' && <Dashboard />}
          {tab === 'requests' && <Requests filter={filter} onFilter={setFilter} />}
          {tab === 'blacklist' && <Blacklist />}
          {tab === 'settings' && <Settings username={username} />}
        </main>

        {panelIP && <IPPanel ip={panelIP} onClose={() => setPanelIP(null)} />}
        {banTarget && (
          <BanDialog ip={banTarget.ip} onClose={() => setBanTarget(null)} onDone={() => banTarget.onDone?.()} />
        )}
      </div>
    </NavContext.Provider>
  )
}

// GlobalSearch opens the IP panel for an address, or searches the request log
// for anything else (a range filters by it).
function GlobalSearch({ nav }: { nav: Nav }) {
  const [q, setQ] = useState('')
  function submit(e: FormEvent) {
    e.preventDefault()
    const v = q.trim()
    if (!v) return
    if (looksLikeIP(v)) {
      if (v.includes('/')) nav.searchRequests({ ip: v, range: nav.archive ? '30d' : '24h' })
      else nav.openIP(v)
    } else {
      nav.searchRequests({ q: v })
    }
    setQ('')
  }
  return (
    <form onSubmit={submit} className="flex-1 max-w-md">
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Look up an IP, or search requests…"
        spellCheck={false}
        className={cx(inputClass, 'w-full')}
      />
    </form>
  )
}
