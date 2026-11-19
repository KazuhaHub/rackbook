// Which records of a backref section apply to every record of the page's
// collection. A reference field may hold a literal the ref rule allows
// (refs[].allow, e.g. "all"): such a record is not "its own" record, it applies
// to all of them. Import-free so scripts/check-console-logic.mts can test it.

export type GenericRule = {
  /** the referencing field of the backref records */
  field: string
  /** literals the ref rule allows in that field */
  allow: string[]
  /** the value of the page's record that the field would name (its own value) */
  parentValue: string
}

function values(v: unknown): string[] {
  if (v === undefined || v === null || v === '') return []
  return (Array.isArray(v) ? v : [v]).map((x) => (typeof x === 'string' ? x : String(x)))
}

/**
 * A record is general when one of its referencing fields holds an allowed literal
 * (for an array field: contains one) and does not name the page's record itself.
 */
export function isGeneric(data: Record<string, unknown>, rules: GenericRule[]): boolean {
  return rules.some((r) => {
    const vs = values(data[r.field])
    return vs.some((v) => r.allow.includes(v)) && !vs.includes(r.parentValue)
  })
}

/** Splits records into the page record's own and the general ones, keeping the order. */
export function splitGeneric<T extends { data: Record<string, unknown> }>(
  records: T[],
  rules: GenericRule[],
): { own: T[]; generic: T[] } {
  const own: T[] = []
  const generic: T[] = []
  for (const r of records) (isGeneric(r.data, rules) ? generic : own).push(r)
  return { own, generic }
}

// The selected backref tab lives in the URL hash: "#<collection>" for a
// collection's own records, "#<collection>+generic" for its general ones.
// encodeURIComponent turns "+" into %2B, so the suffix cannot clash with a name.
const GENERIC_SUFFIX = '+generic'

export type TabKey = { collection: string; generic: boolean }

export function tabHash(k: TabKey): string {
  return '#' + encodeURIComponent(k.collection) + (k.generic ? GENERIC_SUFFIX : '')
}

export function parseTabHash(hash: string): TabKey | undefined {
  let h = hash.replace(/^#/, '')
  if (!h) return undefined
  const generic = h.endsWith(GENERIC_SUFFIX)
  if (generic) h = h.slice(0, -GENERIC_SUFFIX.length)
  try {
    return { collection: decodeURIComponent(h), generic }
  } catch {
    return undefined
  }
}
