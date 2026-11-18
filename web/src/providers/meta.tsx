import { createContext, useContext, useMemo, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { dataProvider } from './dataProvider'
import { ApiError } from '@/lib/api'
import type { CheckResult, Collection, Meta } from '@/lib/types'

type MetaCtx = {
  meta: Meta
  byName: Map<string, Collection>
  refresh: () => Promise<void>
}
const Ctx = createContext<MetaCtx | null>(null)

export const metaQuery = {
  queryKey: ['rb', 'meta'],
  queryFn: async () => (await dataProvider.custom!({ url: '/meta', method: 'get' })).data as Meta,
  staleTime: 30_000,
  retry: (n: number, e: unknown) => !(e instanceof ApiError && e.unreachable) && n < 1,
}

export function MetaProvider({
  children,
  loading,
  failed,
}: {
  children: ReactNode
  loading: ReactNode
  failed: (e: unknown, retry: () => void) => ReactNode
}) {
  const qc = useQueryClient()
  const q = useQuery(metaQuery)
  const value = useMemo<MetaCtx | null>(() => {
    if (!q.data) return null
    return {
      meta: q.data,
      byName: new Map(q.data.collections.map((c) => [c.name, c])),
      refresh: () => qc.invalidateQueries({ queryKey: ['rb'] }),
    }
  }, [q.data, qc])
  if (q.isPending) return <>{loading}</>
  if (!value) return <>{failed(q.error, () => void q.refetch())}</>
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useMeta() {
  const v = useContext(Ctx)
  if (!v) throw new Error('useMeta outside MetaProvider')
  return v
}

export function useCollection(name: string | undefined): Collection | undefined {
  return useMeta().byName.get(name ?? '')
}

export function useCheck() {
  return useQuery({
    queryKey: ['rb', 'check'],
    queryFn: async () => (await dataProvider.custom!({ url: '/check', method: 'get' })).data as CheckResult,
    staleTime: 30_000,
  })
}

export function useAfterWrite() {
  const qc = useQueryClient()
  // counts (meta), check status, history and every cached list change after a write
  return () => qc.invalidateQueries({ queryKey: ['rb'] })
}
