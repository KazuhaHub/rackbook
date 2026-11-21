import { useCallback, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { t } from '@/i18n'
import { ApiError, apiFetch } from './api'

export type Issue = {
  code: string
  severity: 'error' | 'confirm' | 'warning'
  file?: string
  path?: string
  params?: Record<string, string>
  message: string
}
export type FileDiff = { path: string; status: 'added' | 'modified' | 'removed'; diff: string }
export type Outcome = { commit?: string; diffs: FileDiff[]; issues: Issue[]; blocked: boolean }

export type FileState = { path: string; exists: boolean; base: string; content: string; hidden: number }
export type SettingSpec = {
  name: string
  type: 'string' | 'int' | 'bool' | 'enum'
  description?: string
  enum?: string[]
  default?: unknown
  required?: boolean
  requiredWhen?: Record<string, unknown>
  secret?: boolean
  pattern?: string
  min?: number
  max?: number
}
export type FeatureSpec = { name: string; description?: string; type?: string; settings: SettingSpec[] }
export type Membership = { groups: string[]; hosts: string[]; direct: Record<string, string[]> }
export type InventoryFile = { base: string; membership: Membership }
export type WriteState = { enabled: boolean; secrets?: boolean; fresh: boolean; signedInAt?: string; maxAgeSeconds: number }
export type SecretKey = { name: string; editable: boolean }
export type SecretsFile = {
  host: string
  path: string
  exists: boolean
  base: string
  keys: SecretKey[]
  recipients: string[]
  /** the recipients of the file's creation rule in .sops.yaml (null = no rule) */
  rule: string[] | null
  canDecrypt: boolean
  lastModified?: string
  problem?: string
}
export type SecretsPage = { file: SecretsFile; enabled: boolean; canWrite: boolean; publicKey: string }

const quiet = { staleTime: 0, refetchOnWindowFocus: false, refetchInterval: false as const, retry: false }

export const useWriteState = (enabled: boolean) =>
  useQuery({ queryKey: ['rb', 'infra', 'write'], queryFn: () => apiFetch<WriteState>('/infra/write'), enabled, ...quiet })
export const useHostVars = (host: string, enabled: boolean) =>
  useQuery({ queryKey: ['rb', 'infra', 'vars', host], queryFn: () => apiFetch<FileState>(`/infra/hosts/${encodeURIComponent(host)}/vars`), enabled, ...quiet })
export const useSecrets = (host: string, enabled: boolean) =>
  useQuery({ queryKey: ['rb', 'infra', 'secrets', host], queryFn: () => apiFetch<SecretsPage>(`/infra/hosts/${encodeURIComponent(host)}/secrets`), enabled, ...quiet })
export const useFeatureSpecs = (enabled: boolean) =>
  useQuery({ queryKey: ['rb', 'infra', 'features'], queryFn: () => apiFetch<{ features: FeatureSpec[]; invalid: string[] }>('/infra/features'), enabled, ...quiet })
export const useInfraGroups = (enabled: boolean) =>
  useQuery({ queryKey: ['rb', 'infra', 'groups'], queryFn: () => apiFetch<InventoryFile>('/infra/groups'), enabled, ...quiet })

/** The English-free text of an issue: the translation of its code, else the server's message. */
export function issueText(i: Issue): string {
  const f = t.infra.edit.issue.codes[i.code]
  let s = f ? f(i.params ?? {}) : i.message
  if (i.code === 'feature.bad_value' && i.params?.problem) {
    const d = t.infra.edit.issue.badValue[i.params.problem]
    if (d) s += t.common.colon + d
  }
  return s
}

/** What went wrong with a save, in the terms the editor shows it. */
export type EditProblem =
  | { kind: 'reauth'; maxAgeSeconds: number }
  | { kind: 'conflict'; diffs: FileDiff[]; later: string[]; reason: string }
  | { kind: 'invalid'; issues: Issue[] }
  | { kind: 'message'; message: string }

export function problemOf(e: unknown): EditProblem {
  if (e instanceof ApiError) {
    const b = e.body ?? {}
    if (e.statusCode === 403 && e.code === 'reauth_required') return { kind: 'reauth', maxAgeSeconds: b.maxAgeSeconds ?? 43200 }
    if (e.code === 'conflict') return { kind: 'conflict', diffs: b.diffs ?? [], later: b.later ?? [], reason: b.reason ?? 'changed' }
    if (e.code === 'invalid') return { kind: 'invalid', issues: b.issues ?? [] }
    if (e.code === 'busy') return { kind: 'message', message: t.infra.edit.busy }
    if (e.code === 'no_change') return { kind: 'message', message: t.infra.edit.noChange }
    if (e.code === 'rate_limited') return { kind: 'message', message: t.infra.secrets.rateLimited }
    if (e.code === 'revert_refused') return { kind: 'message', message: t.infra.commits.reasons[b.reason] ?? e.message }
    if (e.statusCode === 403) return { kind: 'message', message: e.message }
    return { kind: 'message', message: e.message }
  }
  return { kind: 'message', message: e instanceof Error ? e.message : t.infra.edit.failed }
}

export type FlowState = {
  phase: 'idle' | 'checking' | 'review' | 'committing' | 'done'
  /** the section that asked (a page can have several editors) */
  key?: string
  outcome?: Outcome
  problem?: EditProblem
}

/** The review-then-commit flow of every editor: POST with preview, show the diff and the checks, POST again to commit. */
export function useEditFlow() {
  const qc = useQueryClient()
  const [state, setState] = useState<FlowState>({ phase: 'idle' })
  const [last, setLast] = useState<{ path: string; body: Record<string, unknown> } | null>(null)

  const review = useCallback(async (key: string, path: string, body: Record<string, unknown>) => {
    setLast({ path, body })
    setState({ phase: 'checking', key })
    try {
      const outcome = await apiFetch<Outcome>(path, { method: 'POST', body: JSON.stringify({ ...body, preview: true }) })
      setState({ phase: 'review', key, outcome })
    } catch (e) {
      setState({ phase: 'idle', key, problem: problemOf(e) })
    }
  }, [])

  const commit = useCallback(
    async (confirmSecretScan: boolean) => {
      if (!last) return
      setState((s) => ({ ...s, phase: 'committing', problem: undefined }))
      try {
        const outcome = await apiFetch<Outcome>(last.path, { method: 'POST', body: JSON.stringify({ ...last.body, preview: false, confirmSecretScan }) })
        setState((s) => ({ phase: 'done', key: s.key, outcome }))
        await qc.invalidateQueries({ queryKey: ['rb', 'infra'] })
      } catch (e) {
        setState((s) => ({ phase: 'idle', key: s.key, problem: problemOf(e), outcome: undefined }))
      }
    },
    [last, qc],
  )

  const reset = useCallback(() => setState({ phase: 'idle' }), [])
  return { state, review, commit, reset }
}
