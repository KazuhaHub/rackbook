import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { apiFetch } from './api'
import type { ActivityItem } from './activity'
import type { FieldChange } from './versionValue'

const seg = (s: string) => encodeURIComponent(s)

/** One version of a record: the commit as the Activity page shows it, and what it changed. */
export type RecordVersion = ActivityItem & {
  change: 'created' | 'changed' | 'deleted' | 'renamed'
  renamedFrom?: string
  renamedTo?: string
  /** the record's hash at this commit; "" when the commit deleted it */
  recordHash: string
  changes: FieldChange[]
  moreChanges?: boolean
  /** the file is too large, cannot be read or does not parse at that commit: nothing is said */
  unreadable?: boolean
  /** that commit's collection settings could not be read; today's were used */
  approximate?: boolean
}

export type VersionsPage = { id: string; versions: RecordVersion[]; cursor?: string; audit: boolean; /** commits of the history this page looked at */ scanned?: number }

export type VersionDetail = {
  id: string
  commit: ActivityItem
  recordHash: string
  /** the record at that commit, without the values the secret scan flags */
  data: Record<string, unknown>
  hidden: number
  /** that commit's collection settings could not be read; today's were used */
  approximate?: boolean
  exists: boolean
  current: boolean
  /** what a restore would change: from today's record to this version */
  changes: FieldChange[]
  moreChanges?: boolean
}

export type DeletedItem = ActivityItem & {
  id: string
  /** the commit that still had the record: what Restore takes it from */
  last: string
  deletedAt: string
  summary: { field: string; value: string }[]
}

export type DeletedPage = { records: DeletedItem[]; complete: boolean; more: boolean; audit: boolean }

export function useVersions(collection: string, id: string) {
  return useInfiniteQuery({
    queryKey: ['rb', 'versions', collection, id],
    initialPageParam: '',
    queryFn: ({ pageParam }) => apiFetch<VersionsPage>(`/c/${seg(collection)}/${seg(id)}/history${pageParam ? `?cursor=${seg(pageParam)}` : ''}`),
    getNextPageParam: (last) => last.cursor || undefined,
    staleTime: 15_000,
    retry: false,
  })
}

export function useVersionDetail(collection: string, id: string, commit: string, enabled = true) {
  return useQuery({
    queryKey: ['rb', 'version', collection, id, commit],
    queryFn: () => apiFetch<VersionDetail>(`/c/${seg(collection)}/${seg(id)}/history/${seg(commit)}`),
    enabled,
    staleTime: 5_000,
    retry: false,
  })
}

/** The deleted records of a collection; while the server is still reading the history the list is asked for again. */
export function useDeleted(collection: string) {
  return useQuery({
    queryKey: ['rb', 'deleted', collection],
    queryFn: () => apiFetch<DeletedPage>(`/c/${seg(collection)}/deleted`),
    refetchInterval: (q) => (q.state.data && !q.state.data.complete ? 1500 : false),
    staleTime: 10_000,
    retry: false,
  })
}

export type RestoreResult = { id: string; hash: string; commit?: string; pullRequest?: boolean; restoredFrom: string }

/** Restores the version at `commit`; `hash` is the current record's hash ("" for a record that was deleted). */
export function restoreVersion(collection: string, id: string, commit: string, hash: string, confirmNotSecret: boolean) {
  return apiFetch<RestoreResult>(`/c/${seg(collection)}/${seg(id)}/restore`, {
    method: 'POST',
    body: JSON.stringify({ commit, hash, ...(confirmNotSecret ? { confirm_not_secret: true } : {}) }),
  })
}
