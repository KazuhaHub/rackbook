import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { rolesBody, type Draft, type EntryKind, type ListName } from '@/lib/rolesDraft'

export type EntryNote = {
  level: 'error' | 'warning'
  /** a stable code the console words in the current language; message is the server's English */
  code: string
  message: string
  /** an also_in note: the other list */
  also?: string
}

export type RoleEntry = { value: string; kind: EntryKind | ''; notes: EntryNote[] }

export type Annotated = Record<ListName, RoleEntry[]>

/** A person's role and auditor capability, and where they come from. */
export type RolesCap = {
  role: string
  auditor: boolean
  roleFrom: string[]
  auditorFrom: string[]
  /** the role that remains when only entries that name the person count */
  byIdentity: string
  auditorByIdentity: boolean
}

export type RolesView = {
  version: string
  /** rackbook.yml loads; false = the lists are those of the last good file and nothing can be saved */
  loads: boolean
  problem?: string
  explicit: boolean
  roles: { admin: RoleEntry[]; editor: RoleEntry[]; viewer: RoleEntry[] }
  auditors: RoleEntry[]
  file: string
  /** how a save reaches the repository */
  writeMode: 'push' | 'pr'
  readOnly: boolean
  sso: boolean
  /** how the server authenticates; 'none' = nobody signs in */
  authMode: string
  /** the v0.1 auth.editors list: read as editors, never changed here */
  editors: string[]
  /** /infra administrators and auditors exist (they are set by the deployment, not here) */
  infra: boolean
  /** the one group or app role each /infra flag names ("group:<id>", "app-role:<value>"), when it names one */
  infraClaims?: { admins?: string; auditors?: string; claimsAbsolute: number }
  you?: RolesCap
}

export type Refusal = { code: string; message: string; entries?: Annotated }

export type RolesWarning = { list: ListName; entry: string; note: EntryNote }

export type RolesPreview = {
  version: string
  changed: boolean
  file: string
  diff: string
  subject: string
  entries: Annotated
  warnings: RolesWarning[]
  you: { now?: RolesCap; after?: RolesCap }
  pullRequest: boolean
  readOnly: boolean
  refusal?: Refusal
}

export type RolesSaved = {
  changed: boolean
  pullRequest: boolean
  pullRequestUrl?: string
  commit?: string
  subject: string
  file: string
}

export const rolesKey = ['rb', 'admin-roles'] as const

export function useRoles(enabled: boolean) {
  return useQuery({ queryKey: rolesKey, queryFn: () => apiFetch<RolesView>('/admin/roles'), enabled })
}

export const previewRoles = (version: string, draft: Draft) =>
  apiFetch<RolesPreview>('/admin/roles/preview', { method: 'POST', body: JSON.stringify(rolesBody(version, draft)) })

export const saveRoles = (version: string, draft: Draft, message: string) =>
  apiFetch<RolesSaved>('/admin/roles', { method: 'POST', body: JSON.stringify(rolesBody(version, draft, message)) })

/** The lists of a view as a draft. */
export function viewDraft(v: Pick<RolesView, 'roles' | 'auditors'>): Draft {
  const vals = (l: RoleEntry[]) => l.map((e) => e.value)
  return { admin: vals(v.roles.admin), editor: vals(v.roles.editor), viewer: vals(v.roles.viewer), auditors: vals(v.auditors) }
}

/** The annotated entries of a view as one map by list. */
export function viewEntries(v: Pick<RolesView, 'roles' | 'auditors'>): Annotated {
  return { admin: v.roles.admin, editor: v.roles.editor, viewer: v.roles.viewer, auditors: v.auditors }
}
