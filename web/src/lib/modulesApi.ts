import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './api'
import type { Impact, ModuleList, ModuleSettings } from './modules'

const seg = (s: string) => encodeURIComponent(s)

export const modulesKey = ['rb', 'modules'] as const

export function useModules(enabled = true, refetchMs?: number) {
  return useQuery({
    queryKey: modulesKey,
    queryFn: () => apiFetch<ModuleList>('/modules'),
    enabled,
    staleTime: 10_000,
    refetchInterval: refetchMs,
  })
}

export type SaveResult = { name: string; changed: boolean; commit?: string; pullRequest?: boolean; settings?: ModuleSettings; version?: string }

export const saveSettings = (name: string, version: string, settings: ModuleSettings, confirmImpact = false) =>
  apiFetch<SaveResult>(`/modules/${seg(name)}/settings`, {
    method: 'PUT',
    body: JSON.stringify({ version, settings, confirm_impact: confirmImpact }),
  })

/** What the change would do to the module's records; nothing is written. */
export const previewSettings = (name: string, settings: ModuleSettings) =>
  apiFetch<Impact>(`/modules/${seg(name)}/preview`, { method: 'POST', body: JSON.stringify({ settings }) })

export const requestRun = (name: string) => apiFetch<{ runRequest: { id: string } }>(`/modules/${seg(name)}/run-request`, { method: 'POST', body: '{}' })

export function useRequestRun(name: string) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: () => requestRun(name), onSuccess: () => qc.invalidateQueries({ queryKey: modulesKey }) })
}
