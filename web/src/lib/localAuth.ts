// The local account endpoints (docs/design-local-accounts.md, 5 and 12): one-step sign-in, setup links, re-authentication.
// Passwords and codes only ever go in a JSON body, never in a URL.
import { useQuery } from '@tanstack/react-query'
import { t } from '@/i18n'
import type { LoginConfig } from '@/lib/auth'

export type Answer<T = Record<string, any>> = { ok: boolean; status: number; data: T }

/** POST JSON and read the answer. A network failure is status 0 with the code "network". */
export async function postJSON<T = Record<string, any>>(url: string, body: unknown): Promise<Answer<T>> {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    })
    const data = (await res.json().catch(() => ({}))) as T
    return { ok: res.ok, status: res.status, data }
  } catch {
    return { ok: false, status: 0, data: { error: 'network' } as T }
  }
}

/** The message for an answer's error code: the console's wording, in the current language. */
export function errorText(code: unknown): string {
  const m = t.auth.local.errors
  return (typeof code === 'string' && m[code]) || m.internal
}

async function loadConfig(): Promise<LoginConfig> {
  const res = await fetch('/auth/config', { headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error('config')
  return res.json()
}

export const authConfigQuery = { queryKey: ['auth', 'config'], queryFn: loadConfig, retry: 1 }

export function useAuthConfig() {
  return useQuery(authConfigQuery)
}

/** A page to go to after sign-in: a path of this site, never another origin. */
export function safeReturn(ret: unknown): string {
  if (typeof ret !== 'string' || !ret.startsWith('/') || ret.startsWith('//') || ret.startsWith('/\\') || ret.startsWith('/auth/')) return '/'
  return ret
}
