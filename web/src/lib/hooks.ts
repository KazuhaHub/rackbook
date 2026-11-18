import { useMemo } from 'react'
import { useQueries, useQuery } from '@tanstack/react-query'
import { dataProvider } from '@/providers/dataProvider'
import type { Collection, Commit, LedgerRecord } from './types'
import { str } from './ledger'

const recordsQuery = (name: string) => ({
  queryKey: ['rb', 'records', name],
  queryFn: async () => (await dataProvider.getList({ resource: name })).data as unknown as LedgerRecord[],
  staleTime: 30_000,
})

export function useRecords(name: string | undefined, enabled = true) {
  return useQuery({ ...recordsQuery(name ?? ''), enabled: enabled && !!name })
}

export function useAllRecords(names: string[], enabled: boolean) {
  return useQueries({ queries: names.map((n) => ({ ...recordsQuery(n), enabled })) })
}

export type RefLookup = { to: string; map: Map<string, string>; allow: string[] }

/** field -> (referenced value -> record id) so reference cells can link to the record. */
export function useRefLookups(col: Collection): Record<string, RefLookup> {
  const refs = col.refs ?? []
  const results = useQueries({ queries: refs.map((r) => recordsQuery(r.to)) })
  const stamp = results.map((r) => r.dataUpdatedAt).join(',')
  return useMemo(() => {
    const out: Record<string, RefLookup> = {}
    refs.forEach((r, i) => {
      const map = new Map<string, string>()
      for (const rec of results[i]?.data ?? []) map.set(str(rec.data[r.toField]), rec.id)
      out[r.field] = { to: r.to, map, allow: r.allow ?? [] }
    })
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [col, stamp])
}

export function useHistory(collection: string | undefined, limit: number) {
  return useQuery({
    queryKey: ['rb', 'history', collection ?? '', limit],
    queryFn: async () =>
      (
        await dataProvider.custom!({ url: '/history', method: 'get', query: { limit, collection } })
      ).data.commits as Commit[],
    staleTime: 30_000,
  })
}
