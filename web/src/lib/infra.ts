import { useQuery } from '@tanstack/react-query'
import { t } from '@/i18n'
import { apiFetch } from './api'

/** The state of the hub's status file: only "ok" means its data is current. */
export type HubState = 'ok' | 'stale' | 'missing' | 'invalid'
export type Hub = { state: HubState; error?: string; time?: string; ageSeconds: number }
export type RepoState = { branch: string; head?: string; syncedAt: string; error?: string }

export type FeatureResult = { name: string; result: string; message?: string }
export type Report = {
  appliedCommit?: string
  result: string
  message?: string
  time: string
  receivedAt?: string
  features?: FeatureResult[]
}

export type InfraHost = { name: string; groups: string[]; hasVars: boolean; features: string[]; report?: Report; behind: boolean }
export type HostList = { repo: RepoState; hub: Hub; hosts: InfraHost[] }

export type FeatureConf = { name: string; enabled: boolean; settings?: Record<string, unknown> }
export type HostDetail = { name: string; groups: string[]; hasVars: boolean; vars?: string; features: FeatureConf[]; hidden: number }
export type HostPage = { repo: RepoState; hub: Hub; host: HostDetail; report?: Report; behind: boolean }

export type Cert = { name: string; owner: string; notAfter?: string; failing: boolean; lastError?: string }
export type IPList = { name: string; version?: string; entries: number; warnings: string[] }
export type Commit = {
  hash: string
  author: string
  time: string
  subject: string
  files?: string[]
  revertible?: boolean
  reason?: string
  later?: string[]
}

const seg = (s: string) => encodeURIComponent(s)
const REFRESH = 30_000

function useInfra<T>(key: string[], path: string, enabled: boolean) {
  return useQuery({ queryKey: ['rb', 'infra', ...key], queryFn: () => apiFetch<T>(path), enabled, staleTime: 10_000, refetchInterval: REFRESH, retry: false })
}

export const useInfraHosts = (enabled: boolean) => useInfra<HostList>(['hosts'], '/infra/hosts', enabled)
export const useInfraHost = (name: string, enabled: boolean) => useInfra<HostPage>(['host', name], `/infra/hosts/${seg(name)}`, enabled)
export const useInfraCerts = (enabled: boolean) => useInfra<{ hub: Hub; certs: Cert[] }>(['certs'], '/infra/certs', enabled)
export const useInfraIPLists = (enabled: boolean) => useInfra<{ hub: Hub; lists: IPList[] }>(['iplists'], '/infra/iplists', enabled)
export const useInfraCommits = (enabled: boolean) => useInfra<{ repo: RepoState; commits: Commit[]; canRevert?: boolean }>(['commits'], '/infra/commits', enabled)

/** "30 seconds ago", "5 minutes ago", ... in the current language. */
export function agoText(seconds: number): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return t.infra.seconds(s)
  if (s < 3600) return t.time.minutes(Math.floor(s / 60))
  if (s < 86400) return t.time.hours(Math.floor(s / 3600))
  return t.time.days(Math.floor(s / 86400))
}

/** The first seven characters of a commit. */
export const shortHash = (h?: string) => (h ? h.slice(0, 7) : '')
