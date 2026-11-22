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
