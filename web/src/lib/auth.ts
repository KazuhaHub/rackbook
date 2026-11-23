import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import type { Role } from '@/lib/types'

export type Passkey = { id: string; name: string; created: string }

export type Account = {
  id: string
  name?: string
  email?: string
  role: Role
  authMethod: string
  passkeysEnabled: boolean
  canEnrol: boolean
  /** until when a passkey can be added without logging in again (ISO time) */
  enrolUntil?: string
  passkeys: Passkey[]
  passkeyError?: string
  /** the language this person chose; absent = none chosen */
  locale?: string
}

export type ManagedUser = {
  id: string
  name?: string
  method?: string
  role: Role | 'none'
  /** on auth.auditors: a capability next to the role */
  auditor?: boolean
  /** logged in since the server started */
  seen: boolean
  lastSeen?: string
  passkeys: Passkey[]
}

export type UsersResponse = { users: ManagedUser[]; passkeysEnabled: boolean; passkeyError?: string }

export type LoginConfig = {
  oidc: boolean
  passkeys: boolean
  /** text of the sign-in button; empty = the generic one */
  label: string
  /** product name; empty = the default */
  name: string
  /** a custom logo is served at /branding/logo */
  logo: boolean
  /** the supported language that best matches the browser's Accept-Language (else defaultLocale) */
  locale?: string
  defaultLocale?: string
}

/** Methods that have a server-side session (and so a logout and an account page). */
export const hasSession = (method?: string) => method === 'oidc' || method === 'passkey'

export const accountQuery = {
  queryKey: ['rb', 'account'],
  queryFn: () => apiFetch<Account>('/account'),
}

export function useAccount(enabled: boolean) {
  return useQuery({ ...accountQuery, enabled })
}

export function useUsers() {
  return useQuery({ queryKey: ['rb', 'users'], queryFn: () => apiFetch<UsersResponse>('/admin/users') })
}

/** Ends the session on the server, then shows the login page. */
export async function logout(): Promise<void> {
  try {
    const res = await fetch('/auth/logout', { method: 'POST', headers: { Accept: 'application/json' } })
    const body = res.ok ? await res.json().catch(() => null) : null
    window.location.assign(body?.login ?? '/auth/login')
  } catch {
    window.location.assign('/auth/login')
  }
}
