import { t } from '@/i18n/zh-CN'
import { loginUrl } from './loginurl'
import type { CheckError, LedgerRecord } from './types'

export class ApiError extends Error {
  statusCode: number
  code: string
  errors: CheckError[]
  current?: LedgerRecord | null
  requestId?: string
  constructor(
    statusCode: number,
    code: string,
    message: string,
    extra: { errors?: CheckError[]; current?: LedgerRecord | null; requestId?: string } = {},
  ) {
    super(message)
    this.name = 'ApiError'
    this.statusCode = statusCode
    this.code = code
    this.errors = extra.errors ?? []
    this.current = extra.current
    this.requestId = extra.requestId
  }
  /** The server is not there (or a proxy in front of it says so). */
  get unreachable() {
    if (this.code === 'config_error' || this.code === 'history_rewritten' || this.code === 'repo_dirty' || this.code === 'repo_diverged') return false
    return this.statusCode === 0 || [502, 503, 504].includes(this.statusCode)
  }
}

export const API_BASE = '/api'

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  let res: Response
  try {
    res = await fetch(API_BASE + path, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init.method && init.method !== 'GET' ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw new ApiError(0, 'unreachable', t.errors.network)
  }
  const text = await res.text()
  let body: any = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      // A dev proxy or the SPA fallback answers with HTML when the API is down.
      throw new ApiError(res.ok ? 0 : res.status, 'bad_response', t.errors.network)
    }
  }
  if (!res.ok) {
    // Not logged in (or no longer): go to the login page and come back here.
    if (!window.location.pathname.startsWith('/auth/')) {
      if (res.status === 401 && body?.error === 'login_required') {
        window.location.assign(loginUrl({ error: body.reason === 'expired' ? 'expired' : undefined }))
      } else if (res.status === 403 && body?.error === 'no_role') {
        window.location.assign(loginUrl({ error: 'no_role', returnTo: '/' }))
      }
    }
    throw new ApiError(res.status, body?.error ?? 'error', body?.message ?? t.errors.generic, {
      errors: body?.errors,
      requestId: body?.request_id ?? body?.requestId ?? res.headers.get('X-Request-Id') ?? undefined,
      current: body?.current,
    })
  }
  return body as T
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.statusCode === 403) return t.errors.readOnly
    if (e.code === 'history_rewritten') return t.errors.historyRewritten
    if (e.code === 'config_error') return t.errors.configError
    if (e.unreachable) return t.errors.network
    if (e.statusCode === 409) {
      return e.current === null ? t.errors.conflictDeleted : t.errors.conflictChanged
    }
    if (e.statusCode === 422) {
      const lines = e.errors.map((x) => x.message).join('；')
      return lines ? `${t.errors.summaryTitle}：${lines}` : t.errors.summaryTitle
    }
    if (e.statusCode >= 500) return t.errors.server(e.message, e.requestId)
    return e.message
  }
  return e instanceof Error ? e.message : t.errors.generic
}
