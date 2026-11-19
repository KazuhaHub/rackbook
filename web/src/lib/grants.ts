import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'

/** An MCP client a person authorized through the built-in authorization server. */
export type Grant = {
  id: string
  clientId: string
  clientName: string
  scopes: string[]
  canWrite: boolean
  created: string
  lastUsed: string
  /** admin list only */
  user?: string
  userName?: string
}

export type GrantScope = 'account' | 'admin'

export const grantsKey = (scope: GrantScope) => ['rb', 'grants', scope]

export function useGrants(scope: GrantScope, enabled = true) {
  return useQuery({
    queryKey: grantsKey(scope),
    queryFn: async () => (await apiFetch<{ grants: Grant[] }>(`/${scope}/grants`)).grants,
    enabled,
  })
}

export const revokeGrant = (scope: GrantScope, id: string) =>
  apiFetch(`/${scope}/grants/${encodeURIComponent(id)}`, { method: 'DELETE' })

export type ConsentInfo = {
  clientName: string
  clientId: string
  redirectUri: string
  redirectHost: string
  scopes: string[]
  /** the person's role, limited by the scopes, lets the client write */
  canWrite: boolean
  /** a host label starts with xn--: it may be shown as look-alike letters */
  punycode: boolean
  user: { id: string; name?: string }
}

export const consentInfo = (req: string) => apiFetch<ConsentInfo>(`/oauth/consent?req=${encodeURIComponent(req)}`)

/** Answers a consent request; the server returns where to send the browser. */
export const decideConsent = (req: string, approve: boolean) =>
  apiFetch<{ redirect: string }>('/oauth/consent', { method: 'POST', body: JSON.stringify({ req, approve }) })
