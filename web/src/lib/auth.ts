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
  /** which kinds of entry in auth.roles grant the role: identity, group, app-role */
  roleFrom?: string[]
  /** the same for the auditor capability (auth.auditors) */
  auditorFrom?: string[]
  /** the role was read from claims at sign-in: seconds this session lasts at most, and when it ends */
  claimsAbsolute?: number
  sessionEnds?: string
  /** /infra through the group or app role of --infra-admins / --infra-auditors: group or app_role ('' or absent = not that way) */
  infraFrom?: string
  infraAuditorFrom?: string
  /** when that access lapses (ISO time) and how many seconds after sign-in it lasts */
  infraEnds?: string
  infraClaimsAbsolute?: number
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

/** A person who signs in through single sign-on (OIDC) has no passkey sign-in: the provider is their second factor. */
export const isSSO = (method?: string) => method === 'oidc'

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
