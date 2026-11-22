import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { t } from '@/i18n'
import { apiFetch } from './api'

export type ActivityArea = 'ledger' | 'infra' | 'audit'
export const AREAS: ActivityArea[] = ['ledger', 'infra', 'audit']

/** One row of the timeline: a commit or an audit event (GET /api/activity). */
export type ActivityItem = {
  time: string
  area: ActivityArea
  /** "commit" or the audit event's name */
  kind: string
  hash?: string
  short?: string
  identity?: string
  name?: string
  method?: string
  via?: string
  subject?: string
  records?: string[]
  /** the audit log confirms this server made the commit */
  verified?: boolean
  /** the API token the commit was made with */
  token?: string
  /** the commit touches .rackbook/ (administrators only) */
  state?: 'only' | 'some'
  seq?: number
  event?: string
  reason?: string
  code?: string
  role?: string
  addr?: string
  outcome?: string
  action?: string
  host?: string
  files?: string[]
  detail?: string[]
}

export type ActivityPage = { items: ActivityItem[]; cursor?: string; areas: ActivityArea[]; audit: boolean; /** commits and log lines looked at to make this page */ scanned?: number }

export type DiffFile = { status: string; path: string; patch?: string; truncated?: boolean; hidden?: boolean }
export type CommitDiff = { area: ActivityArea; hash: string; files: DiffFile[]; moreFiles?: boolean }

export type AuditProblem = { kind: string; seq: number; file?: string; detail?: string; recordedAt?: number }
export type AuditStatus = { enabled: boolean; ok: boolean; problems: AuditProblem[]; lastSeq: number; failed?: string }

/** The filters of the page, as they are in the URL. */
export type ActivityFilters = {
  identity: string
  areas: ActivityArea[]
  collection: string
  id: string
  since: string
  until: string
}

export function filtersFromParams(sp: URLSearchParams): ActivityFilters {
  const areas = sp
    .getAll('area')
    .flatMap((a) => a.split(','))
    .filter((a): a is ActivityArea => (AREAS as string[]).includes(a))
  return {
    identity: sp.get('identity') ?? '',
    areas: [...new Set(areas)],
    collection: sp.get('collection') ?? '',
    id: sp.get('collection') ? (sp.get('id') ?? '') : '',
    since: sp.get('since') ?? '',
    until: sp.get('until') ?? '',
  }
}

/** The query string of the filters; the same for the page URL, the API and the export link. */
export function filterQuery(f: ActivityFilters): URLSearchParams {
  const q = new URLSearchParams()
  if (f.identity) q.set('identity', f.identity)
  for (const a of f.areas) q.append('area', a)
  if (f.collection) q.set('collection', f.collection)
  if (f.collection && f.id) q.set('id', f.id)
  if (f.since) q.set('since', f.since)
  if (f.until) q.set('until', f.until)
  return q
}

export const exportHref = (f: ActivityFilters) => {
  const q = filterQuery(f)
  q.set('format', 'jsonl')
  return `/api/activity?${q}`
}

export function useActivity(f: ActivityFilters) {
  const key = filterQuery(f).toString()
  return useInfiniteQuery({
    queryKey: ['rb', 'activity', key],
    initialPageParam: '',
    queryFn: ({ pageParam }) => {
      const q = filterQuery(f)
      if (pageParam) q.set('cursor', pageParam)
      return apiFetch<ActivityPage>(`/activity?${q}`)
    },
    getNextPageParam: (last) => last.cursor || undefined,
    staleTime: 15_000,
    retry: false,
  })
}

export function useCommitDiff(area: ActivityArea, hash: string, enabled: boolean) {
  return useQuery({
    queryKey: ['rb', 'activity-diff', area, hash],
    queryFn: () => apiFetch<CommitDiff>(`/activity/commit/${area}/${hash}`),
    enabled,
    staleTime: Infinity,
    retry: false,
  })
}

export function useAuditStatus(enabled: boolean) {
  return useQuery({ queryKey: ['rb', 'audit-status'], queryFn: () => apiFetch<AuditStatus>('/audit/status'), enabled, staleTime: 10_000, retry: false })
}

export const acknowledgeAudit = (through: number) => apiFetch<AuditStatus>('/audit/ack', { method: 'POST', body: JSON.stringify({ through }) })

/** The highest line the admin acknowledges: the last recorded problem the status lists. */
export const ackThrough = (s: AuditStatus | undefined) => Math.max(0, ...(s?.problems ?? []).map((p) => p.recordedAt ?? 0))

const detailValue = (it: ActivityItem, key: string) => it.detail?.find((d) => d.startsWith(key))?.slice(key.length)

/** An audit event as a sentence without its subject (the row shows who). */
export function eventSentence(it: ActivityItem): string {
  const e = t.activity.events
  const role = (it.role && t.auth.role[it.role]) || it.role || ''
  const method = (it.method && t.auth.method[it.method]) || it.method || ''
  switch (it.kind) {
    case 'login':
      return e.login(role, method)
    case 'logout':
      return e.logout
    case 'login_refused':
      return e.loginRefused(e.reasons[it.reason ?? ''] ?? it.reason ?? '')
    case 'role_changed':
      return e.roleChanged
    case 'write_refused':
      return e.writeRefused(it.area === 'infra' ? t.activity.filters.area.infra : t.activity.filters.area.ledger, e.codes[it.code ?? ''] ?? it.code ?? '')
    case 'secret_revealed':
      return e.secretRevealed(it.host ?? '')
    case 'secret_reveal_refused':
      return e.secretRevealRefused(it.host ?? '')
    case 'reencrypted':
      return e.reencrypted(it.host ?? '')
    case 'accept_remote':
      return e.acceptRemote
    case 'history_rewritten':
      return e.historyRewritten
    case 'chain_problem':
      return e.chainProblem(it.code ?? '', detailValue(it, 'seq=') ?? '')
    case 'chain_problem_ack':
      return e.chainProblemAck(detailValue(it, 'through:') ?? '')
    default:
      return e.other(it.kind, it.code ?? it.reason ?? '')
  }
}
