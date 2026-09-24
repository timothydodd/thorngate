// Thin fetch wrapper around the thorngate admin API. The SPA is served from the
// same origin as the API, so all paths are relative.

import type {
  BlacklistEntry,
  HourlyResponse,
  IPProfile,
  ImportResult,
  RequestFilter,
  RequestsResponse,
  StatsResponse,
  TopResponse,
  WhitelistEntry,
} from './types'

const TOKEN_KEY = 'tg_token'

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? ''
}
export function setToken(t: string) {
  localStorage.setItem(TOKEN_KEY, t)
}
export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

// onUnauthorized is invoked whenever the API returns 401, so the app can drop
// to the login screen no matter which call triggered it (e.g. an expired
// session caught by a background poll). onMustChange is invoked when the API
// refuses a call because the default password hasn't been changed yet.
let onUnauthorized: (() => void) | null = null
let onMustChange: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}
export function setMustChangeHandler(fn: () => void) {
  onMustChange = fn
}

async function send(method: string, path: string, body?: BodyInit, contentType?: string): Promise<Response> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = 'Bearer ' + token
  if (contentType) headers['Content-Type'] = contentType
  const res = await fetch(path, { method, headers, body })
  if (res.status === 401) {
    onUnauthorized?.()
    throw new ApiError(401, 'session expired — please sign in again')
  }
  return res
}

async function parse<T>(res: Response): Promise<T> {
  let data: any = null
  const text = await res.text()
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = text
    }
  }
  if (!res.ok) {
    if (res.status === 403 && data?.must_change) onMustChange?.()
    const msg = (data && data.error) || res.statusText || 'request failed'
    throw new ApiError(res.status, msg)
  }
  return data as T
}

function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const json = body !== undefined ? JSON.stringify(body) : undefined
  return send(method, path, json, json !== undefined ? 'application/json' : undefined).then((r) => parse<T>(r))
}

function query(params: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') q.set(k, String(v))
  }
  const s = q.toString()
  return s ? '?' + s : ''
}

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string; username: string; must_change: boolean }>('POST', '/admin/login', {
      username,
      password,
    }),
  logout: () => request<{ ok: boolean }>('POST', '/admin/logout'),
  me: () => request<{ username: string; must_change: boolean }>('GET', '/admin/me'),
  changePassword: (current_password: string, new_password: string) =>
    request<{ ok: boolean }>('POST', '/admin/password', { current_password, new_password }),

  stats: () => request<StatsResponse>('GET', '/admin/stats'),
  requests: (f: RequestFilter, page: number, pageSize: number) =>
    request<RequestsResponse>('GET', '/admin/requests' + query({ ...f, page, page_size: pageSize })),
  top: (range: string, n = 10) => request<TopResponse>('GET', '/admin/top' + query({ range, n })),
  hourly: (range: string) => request<HourlyResponse>('GET', '/admin/hourly' + query({ range })),
  ip: (ip: string) => request<IPProfile>('GET', '/admin/ip/' + encodeURIComponent(ip)),

  blacklist: () => request<BlacklistEntry[]>('GET', '/admin/blacklist'),
  ban: (ip: string, reason: string, duration = '') =>
    request<{ ip: string; added: boolean }>('POST', '/admin/blacklist', { ip, reason, duration }),
  unban: (ip: string) =>
    request<{ ip: string; removed: boolean }>('DELETE', '/admin/blacklist/' + encodeURIComponent(ip)),
  exportBlacklist: async (): Promise<Blob> => {
    const res = await send('GET', '/admin/blacklist/export')
    if (!res.ok) await parse(res)
    return res.blob()
  },
  importBlacklist: (text: string) =>
    send('POST', '/admin/blacklist/import', text, 'text/plain').then((r) => parse<ImportResult>(r)),
  whitelist: () => request<WhitelistEntry[]>('GET', '/admin/whitelist'),
  reload: () => request<{ ok: boolean; restart_required: string[] }>('POST', '/admin/reload'),
}
