// Thin fetch wrapper around the thorngate admin API. The SPA is served from the
// same origin as the API, so all paths are relative.

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
// session caught by the background stats poll).
let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  const token = getToken()
  if (token) headers['Authorization'] = 'Bearer ' + token
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const res = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (res.status === 401) {
    onUnauthorized?.()
    throw new ApiError(401, 'session expired — please sign in again')
  }

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
    const msg = (data && data.error) || res.statusText || 'request failed'
    throw new ApiError(res.status, msg)
  }
  return data as T
}

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string; username: string }>('POST', '/admin/login', { username, password }),
  logout: () => request<{ ok: boolean }>('POST', '/admin/logout'),
  me: () => request<{ username: string }>('GET', '/admin/me'),
  changePassword: (current_password: string, new_password: string) =>
    request<{ ok: boolean }>('POST', '/admin/password', { current_password, new_password }),

  stats: () => request<import('./types').StatsResponse>('GET', '/admin/stats'),
  recent: (page: number, pageSize: number) =>
    request<import('./types').RecentResponse>(
      'GET',
      `/admin/stats/recent?page=${page}&page_size=${pageSize}`,
    ),
  blacklist: () => request<import('./types').BlacklistEntry[]>('GET', '/admin/blacklist'),
  ban: (ip: string, reason: string) =>
    request<{ ip: string; added: boolean }>('POST', '/admin/blacklist', { ip, reason }),
  unban: (ip: string) =>
    request<{ ip: string; removed: boolean }>('DELETE', '/admin/blacklist/' + encodeURIComponent(ip)),
}
