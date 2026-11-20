import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './api'
import type { I18n, Migration, Plan, TypeDef, TypeList, TypeWrite } from './typedef'

const seg = (s: string) => encodeURIComponent(s)

export function useTypeList(enabled = true) {
  return useQuery({
    queryKey: ['rb', 'types'],
    queryFn: () => apiFetch<TypeList>('/types'),
    enabled,
    staleTime: 10_000,
  })
}

export type TypeDetail = { type: TypeDef; incoming: { collection: string; field: string; title?: string; i18n?: I18n<'title'> }[] }

export function useTypeDetail(name: string | undefined) {
  return useQuery({
    queryKey: ['rb', 'type', name ?? ''],
    queryFn: () => apiFetch<TypeDetail>(`/types/${seg(name!)}`),
    enabled: !!name,
    retry: false,
  })
}

/** The dry run: the same body as the save, nothing is written. */
export function planType(name: string, body: { type?: TypeDef; version?: string; migrations?: Migration[]; delete?: boolean }, signal?: AbortSignal) {
  return apiFetch<Plan>(`/types/${seg(name)}/plan`, { method: 'POST', body: JSON.stringify(body), signal })
}

export const createType = (type: TypeDef) => apiFetch<TypeWrite>('/types', { method: 'POST', body: JSON.stringify({ type }) })
export const updateType = (name: string, type: TypeDef, migrations: Migration[]) =>
  apiFetch<TypeWrite>(`/types/${seg(name)}`, { method: 'PUT', body: JSON.stringify({ type, migrations, version: type.version }) })
export const deleteType = (name: string, version: string | undefined) =>
  apiFetch<TypeWrite>(`/types/${seg(name)}?version=${encodeURIComponent(version ?? '')}`, { method: 'DELETE' })

export function useRefreshAll() {
  const qc = useQueryClient()
  return () => qc.invalidateQueries({ queryKey: ['rb'] })
}
