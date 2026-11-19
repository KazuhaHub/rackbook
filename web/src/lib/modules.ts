// The modules panel: types of the API and the small pure rules the page needs.
// Nothing here imports the app, so scripts/check-modules.mts can run it with node.

export type RunStatus = 'ok' | 'failed' | 'skipped'
export type RunCounts = { created: number; updated: number; revoked: number; sent: number }
export type ModuleRun = {
  started: string
  finished: string
  status: RunStatus
  counts: RunCounts
  error?: string
  run_request?: string
}
export type ModuleSettings = Record<string, unknown>
export type ModuleType = '' | 'entra' | 'notify'
export type TokenState = 'active' | 'revoked' | 'expired' | 'missing'

export type ModuleView = {
  name: string
  type: ModuleType
  token: string
  tokenStatus: TokenState
  readOnly: boolean
  collection?: string
  fields: string[]
  directPush: boolean
  settings: ModuleSettings
  version: string
  paused: boolean
  status: RunStatus | 'never'
  lastRun: ModuleRun | null
  lastOk: string | null
  runs: ModuleRun[]
  runRequest: { id: string; requested: string; by?: string } | null
  schedule: { times: string[]; timezone: string; default: boolean }
  nextRun: string | null
  due: boolean
  keys: string[]
}
export type ModuleList = { modules: ModuleView[]; now: string; writeMode?: string; historyKept: boolean }

export type Affected = { id: string; label: string; expires?: string; effect: 'frozen' | 'maybe_revoked' }
export type Impact = { records: Affected[]; risky: boolean }

// ---- checks used by the form --------------------------------------------------

const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const EMAIL_RE = /^[^\s@<>,;"()[\]\\]+@[^\s@<>,;"()[\]\\]+\.[^\s@<>,;"()[\]\\]+$/

export const isTime = (s: string) => TIME_RE.test(s)
export const isAppId = (s: string) => UUID_RE.test(s)
export const isEmail = (s: string) => s.length <= 254 && EMAIL_RE.test(s)

/** The first entry of list that fails ok, or undefined. */
export const firstBad = (list: string[], ok: (s: string) => boolean) => list.find((s) => !ok(s))

/** Split a pasted list on commas, semicolons, spaces and line breaks (also the Chinese ones). */
export function splitList(text: string): string[] {
  const out: string[] = []
  for (const part of text.split(/[\s,;，；、]+/)) {
    const v = part.trim()
    if (v && !out.includes(v)) out.push(v)
  }
  return out
}

/** Whole numbers 0..3650, as the server accepts them; error names the first bad entry. */
export function parseThresholds(items: string[]): { values: number[]; error?: string } {
  const values: number[] = []
  for (const s of items) {
    if (!/^\d{1,4}$/.test(s) || Number(s) > 3650) return { values, error: s }
    const n = Number(s)
    if (!values.includes(n)) values.push(n)
  }
  return { values: values.sort((a, b) => b - a) }
}

/** The record defaults as text and back. A value is a string, number, boolean or list of strings. */
export function defaultsToText(d: unknown): string {
  return d && typeof d === 'object' && Object.keys(d as object).length ? JSON.stringify(d, null, 2) : ''
}
export function parseDefaults(text: string): { value?: Record<string, unknown>; error?: 'json' | 'object' | 'value' } {
  const s = text.trim()
  if (!s) return { value: undefined }
  let v: unknown
  try {
    v = JSON.parse(s)
  } catch {
    return { error: 'json' }
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return { error: 'object' }
  for (const x of Object.values(v as Record<string, unknown>)) {
    const scalar = ['string', 'number', 'boolean'].includes(typeof x)
    const list = Array.isArray(x) && x.every((e) => typeof e === 'string')
    if (!scalar && !list) return { error: 'value' }
  }
  return { value: v as Record<string, unknown> }
}

// ---- settings ----------------------------------------------------------------------

const empty = (v: unknown) =>
  v === undefined || v === null || v === '' || v === false || (Array.isArray(v) && v.length === 0) ||
  (typeof v === 'object' && !Array.isArray(v) && Object.keys(v as object).length === 0)

/** Settings without the values that mean "not set": what the server stores. */
export function cleanSettings(s: ModuleSettings): ModuleSettings {
  const out: ModuleSettings = {}
  for (const k of Object.keys(s).sort()) {
    const v = s[k]
    // service_principals and name_prefix keep an explicit false / empty string
    if (k === 'service_principals' && typeof v === 'boolean') out[k] = v
    else if (k === 'name_prefix' && typeof v === 'string') out[k] = v
    else if (!empty(v)) out[k] = v
  }
  return out
}

export const sameSettings = (a: ModuleSettings, b: ModuleSettings) => JSON.stringify(cleanSettings(a)) === JSON.stringify(cleanSettings(b))

/** Keys whose value differs. */
export function changedKeys(a: ModuleSettings, b: ModuleSettings): string[] {
  const x = cleanSettings(a)
  const y = cleanSettings(b)
  return [...new Set([...Object.keys(x), ...Object.keys(y)])].filter((k) => JSON.stringify(x[k]) !== JSON.stringify(y[k])).sort()
}

const lower = (l: unknown) => (Array.isArray(l) ? l.map((s) => String(s).toLowerCase()) : [])
const spOn = (s: ModuleSettings) => s.service_principals !== false

/** App ids the change adds to exclude_app_ids. */
export const addedExcludes = (was: ModuleSettings, next: ModuleSettings): string[] =>
  lower(next.exclude_app_ids).filter((id) => !lower(was.exclude_app_ids).includes(id))

/**
 * A change that can freeze or retire records (excluding an app, turning service
 * principals off): the console asks the server what it would affect first.
 */
export const isRiskyChange = (was: ModuleSettings, next: ModuleSettings) =>
  addedExcludes(was, next).length > 0 || (spOn(was) && !spOn(next))

// ---- how a module looks ------------------------------------------------------------

export type Tone = 'ok' | 'failed' | 'paused' | 'skipped' | 'never' | 'due'

/** The one badge a module gets: a failed last run is red, a pause beats everything else but a failure. */
export function tone(m: Pick<ModuleView, 'status' | 'paused'>): Tone {
  if (m.status === 'failed') return 'failed'
  if (m.paused) return 'paused'
  if (m.status === 'ok') return 'ok'
  if (m.status === 'skipped') return 'skipped'
  return 'never'
}

/** Modules that need a look: the last run failed. */
export const failedCount = (mods: Pick<ModuleView, 'status'>[]) => mods.filter((m) => m.status === 'failed').length

/** What a run did, for the module's kind: entra writes records, notify sends reminders. */
export function countParts(c: RunCounts, type: ModuleType): { key: 'created' | 'updated' | 'revoked' | 'sent'; n: number }[] {
  const keys: ('created' | 'updated' | 'revoked' | 'sent')[] = type === 'notify' ? ['sent'] : type === 'entra' ? ['created', 'updated', 'revoked'] : ['created', 'updated', 'revoked', 'sent']
  return keys.map((key) => ({ key, n: c[key] ?? 0 }))
}
