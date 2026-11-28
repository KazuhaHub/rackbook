// The draft of the role editor (Users → Roles): the four lists as the person edits
// them, before anything is sent. The server is the authority on what an entry is
// (GET /api/admin/roles describes each one); the guesses here only label a new chip
// and catch the obvious slips before a round trip. They mirror internal/roles.

export const LISTS = ['admin', 'editor', 'viewer', 'auditors'] as const
export type ListName = (typeof LISTS)[number]
/** The three lists that grant a role; an entry can move between these. */
export const ROLE_LISTS = ['admin', 'editor', 'viewer'] as const

export type Draft = Record<ListName, string[]>

export type EntryKind = 'identity' | 'domain' | 'any' | 'group' | 'app-role' | 'oidc' | 'mcphub' | 'oauth' | 'local'

/** The kinds the add form offers, in the order it lists them. */
export const ADD_KINDS: EntryKind[] = ['identity', 'domain', 'group', 'app-role', 'oidc', 'mcphub', 'oauth', 'local', 'any']

const foldASCII = (s: string) => s.replace(/[A-Z]/g, (c) => c.toLowerCase())
// eslint-disable-next-line no-control-regex
const control = /[\u0000-\u001f\u007f]/

// Unicode format characters (zero-width, bidi overrides and isolates, BOM), line and paragraph separators and
// the C1 controls: the server refuses an entry that holds one, so two entries that look alike never differ.
const invisible = /[\p{Cf}\p{Zl}\p{Zp}\u0080-\u009f]/u

/** The kind of an entry as the parser reads it; '' when it does not parse. */
export function kindOf(entry: string): EntryKind | '' {
  if (invisible.test(entry) || control.test(entry)) return ''
  const trimmed = entry.trim()
  if (/^app-role:/i.test(trimmed)) {
    const v = trimmed.slice('app-role:'.length).trim()
    return v === '' || control.test(v) || v.includes('*') ? '' : 'app-role'
  }
  const s = foldASCII(trimmed)
  if (s === '') return ''
  if (s === '*') return 'any'
  // local:<username> or local:*; the username is the server's rule (internal/roles ValidLocalUsername)
  if (s.startsWith('local:')) return /^local:(\*|[a-z][a-z0-9._-]{0,31})$/.test(s) ? 'local' : ''
  if (s.startsWith('group:')) return s.slice(6).trim() ? 'group' : ''
  if (s.startsWith('oauth:')) {
    const rest = s.slice(6)
    const i = rest.indexOf(':')
    return i > 0 && rest.slice(0, i).trim() && rest.slice(i + 1).trim() ? 'oauth' : ''
  }
  if (s.startsWith('oidc:')) return s.slice(5).trim() ? 'oidc' : ''
  if (s === 'mcphub:*') return 'mcphub'
  if (s.startsWith('mcphub:')) return s.slice(7).trim() ? 'mcphub' : ''
  if (s.startsWith('*@')) {
    const d = s.slice(2)
    return d !== '' && !/[*@ ]/.test(d) ? 'domain' : ''
  }
  if (s.includes('*')) return ''
  return 'identity'
}

/** What two entries must have in common to be the same one: folded, except an app role's value. */
export function entryKey(entry: string): string {
  const t = entry.trim()
  return /^app-role:/i.test(t) ? 'app-role:' + t.slice('app-role:'.length).trim() : foldASCII(t)
}

export type BuildError = 'empty' | 'spaces' | 'wildcard' | 'domain' | 'oauth' | 'control' | 'invisible' | 'invalid'

/** The entry text for a kind and what the person typed, or what is wrong with it. */
export function buildEntry(kind: EntryKind, input: string): { value: string } | { error: BuildError } {
  const v = input.trim()
  if (invisible.test(v)) return { error: 'invisible' }
  let value: string
  switch (kind) {
    case 'any':
      value = '*'
      break
    case 'domain': {
      const d = v.replace(/^\*?@/, '')
      if (d === '') return { error: 'empty' }
      if (/[*@\s]/.test(d)) return { error: 'domain' }
      value = '*@' + d
      break
    }
    case 'identity':
      if (v === '') return { error: 'empty' }
      if (/\s/.test(v)) return { error: 'spaces' }
      if (v.includes('*')) return { error: 'wildcard' }
      value = v
      break
    case 'app-role':
      if (v === '') return { error: 'empty' }
      if (control.test(v)) return { error: 'control' }
      if (v.includes('*')) return { error: 'wildcard' }
      value = 'app-role:' + v
      break
    case 'oauth': {
      const i = v.indexOf(':')
      if (v === '') return { error: 'empty' }
      if (i <= 0 || !v.slice(i + 1).trim()) return { error: 'oauth' }
      if (/\s/.test(v)) return { error: 'spaces' }
      value = 'oauth:' + v
      break
    }
    default:
      if (v === '') return { error: 'empty' }
      if (/\s/.test(v)) return { error: 'spaces' }
      if (control.test(v)) return { error: 'control' }
      if (kind !== 'mcphub' && kind !== 'local' && v.includes('*')) return { error: 'wildcard' }
      value = `${kind}:${v}`
  }
  return kindOf(value) === '' ? { error: 'invalid' } : { value }
}

export const emptyDraft = (): Draft => ({ admin: [], editor: [], viewer: [], auditors: [] })

export function cloneDraft(d: Draft): Draft {
  return { admin: [...d.admin], editor: [...d.editor], viewer: [...d.viewer], auditors: [...d.auditors] }
}

/** Whether list already holds the entry (the same one by entryKey). */
export function hasEntry(d: Draft, list: ListName, value: string): boolean {
  const k = entryKey(value)
  return d[list].some((e) => entryKey(e) === k)
}

export function addEntry(d: Draft, list: ListName, value: string): Draft {
  if (hasEntry(d, list, value)) return d
  const out = cloneDraft(d)
  out[list].push(value)
  return out
}

export function removeEntry(d: Draft, list: ListName, value: string): Draft {
  const out = cloneDraft(d)
  const i = out[list].indexOf(value)
  if (i >= 0) out[list].splice(i, 1)
  return out
}

/** Takes the entry out of one list and puts it in another (no repeat if the other has it). */
export function moveEntry(d: Draft, from: ListName, to: ListName, value: string): Draft {
  if (from === to) return d
  return addEntry(removeEntry(d, from, value), to, value)
}

const sorted = (l: string[]) => [...l].sort()

/** Whether two drafts hold the same entries; the order of a list means nothing. */
export function sameDraft(a: Draft, b: Draft): boolean {
  return LISTS.every((n) => JSON.stringify(sorted(a[n])) === JSON.stringify(sorted(b[n])))
}

export type DraftChange = { list: ListName; op: 'add' | 'remove'; value: string }

/** What the draft adds to and removes from each list of the base. */
export function draftChanges(base: Draft, draft: Draft): DraftChange[] {
  const out: DraftChange[] = []
  for (const list of LISTS) {
    const left = new Map<string, number>()
    for (const e of base[list]) left.set(e, (left.get(e) ?? 0) + 1)
    for (const e of draft[list]) {
      const n = left.get(e) ?? 0
      if (n > 0) left.set(e, n - 1)
      else out.push({ list, op: 'add', value: e })
    }
    const right = new Map<string, number>()
    for (const e of draft[list]) right.set(e, (right.get(e) ?? 0) + 1)
    for (const e of base[list]) {
      const n = right.get(e) ?? 0
      if (n > 0) right.set(e, n - 1)
      else out.push({ list, op: 'remove', value: e })
    }
  }
  return out
}

/** The request body of a preview or a save. */
export function rolesBody(version: string, d: Draft, message?: string) {
  return {
    version,
    roles: { admin: d.admin, editor: d.editor, viewer: d.viewer },
    auditors: d.auditors,
    ...(message?.trim() ? { message: message.trim() } : {}),
  }
}
