// Showing the values of a version diff, and how a restore ended. Free of imports,
// so that scripts/check-console-logic.mts can test it.

export type FieldChange = {
  /** where the field is: "a.b", "ports[2].proto" */
  path: string
  op: 'added' | 'removed' | 'changed'
  old: unknown
  new: unknown
  /** the value is left out: the secret scan flags it */
  hidden?: boolean
  /** the value is cut: it is longer than the server sends */
  truncated?: boolean
}

/** A value longer than this (or with several lines) is collapsed until it is opened. */
export const LONG_VALUE = 160

/** A value as text: a string as it is, anything else as JSON. */
export function valueText(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'string') return v
  return JSON.stringify(v)
}

export function isLongValue(text: string): boolean {
  return text.length > LONG_VALUE || text.split('\n').length > 3
}

/** The first part of a long value, on a character boundary and without a half line. */
export function shortValue(text: string): string {
  const firstLines = text.split('\n').slice(0, 3).join('\n')
  const cut = [...firstLines].slice(0, LONG_VALUE).join('')
  return cut.length < text.length ? cut + '…' : cut
}

/** The first part of a commit hash. */
export const shortHash = (h: string) => h.slice(0, 7)

export type RestoreStep = 'secret' | 'conflict' | 'edit' | 'refused' | 'unchanged' | 'failed'

/** What the console does with a refused restore. */
export function restoreStep(e: { statusCode: number; code: string }): RestoreStep {
  if (e.code === 'secret_suspected') return 'secret'
  if (e.code === 'restore_needs_edit') return 'edit'
  if (e.code === 'already_current') return 'unchanged'
  if (e.statusCode === 409) return 'conflict'
  if (e.statusCode === 403) return 'refused'
  return 'failed'
}

/** The segments of a JSON pointer ("" is the whole record). */
export function pointerSegments(p: string): string[] {
  if (p === '' || p === '/') return []
  return p
    .replace(/^\//, '')
    .split('/')
    .map((x) => x.replace(/~1/g, '/').replace(/~0/g, '~'))
}

/** The value at a path of a record, undefined when there is none. */
export function getAtPath(data: unknown, segs: string[]): unknown {
  let cur: unknown = data
  for (const seg of segs) {
    if (Array.isArray(cur)) cur = /^\d+$/.test(seg) ? cur[Number(seg)] : undefined
    else if (cur && typeof cur === 'object') cur = Object.hasOwn(cur, seg) ? (cur as Record<string, unknown>)[seg] : undefined
    else return undefined
  }
  return cur
}

/**
 * A copy of data with the value at the path set. Undefined removes the field of a map; an element of a list
 * is set to "" instead (the others keep their place). An empty path replaces the whole record.
 */
export function setAtPath<T>(data: T, segs: string[], value: unknown): T {
  if (segs.length === 0) return (value === undefined ? {} : structuredClone(value)) as T
  const [head, ...rest] = segs
  if (Array.isArray(data)) {
    const out = [...data]
    const i = Number(head)
    if (Number.isInteger(i) && i >= 0 && i < out.length) out[i] = rest.length ? setAtPath(out[i], rest, value) : value === undefined ? '' : structuredClone(value)
    return out as T
  }
  if (data && typeof data === 'object') {
    const out = { ...(data as Record<string, unknown>) }
    if (rest.length) out[head] = setAtPath(out[head], rest, value)
    else if (value === undefined) delete out[head]
    else out[head] = structuredClone(value)
    return out as T
  }
  return data
}

/** What a person decided about a value that the old version hid. */
export type HiddenChoice = 'keep' | 'empty'

/**
 * The hidden paths that still need a decision: those with no choice and a value in the form that is still what
 * the draft had (nothing was entered).
 */
export function unresolvedHidden(paths: string[], choices: Record<string, HiddenChoice>, data: unknown, draft: unknown): string[] {
  return paths.filter((p) => {
    if (choices[p]) return false
    const segs = pointerSegments(p)
    return JSON.stringify(getAtPath(data, segs) ?? null) === JSON.stringify(getAtPath(draft, segs) ?? null)
  })
}
