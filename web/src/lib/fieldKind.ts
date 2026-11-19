// How the console treats a schema property in forms and in list cells.
// Import-free so scripts/check-console-logic.mts can test it.

export type Prop = { [k: string]: unknown }

export type FieldKind =
  | 'boolean'
  | 'textarea'
  | 'date'
  | 'enum' // one of a fixed list of strings
  | 'tags' // several of a fixed list of strings (array, items.enum)
  | 'list' // an array of free strings, each checked against items.pattern / items.format
  | 'suggest' // short free text with the values already used offered as a dropdown
  | 'plain'

/** "string" for type: "string" and for ["string", "null"]. */
export function baseType(p: Prop | undefined): string | undefined {
  const t = p?.type
  if (typeof t === 'string') return t
  if (Array.isArray(t)) return t.find((x) => x !== 'null') as string | undefined
  return undefined
}

function stringEnum(p: Prop | undefined): string[] | undefined {
  const e = p?.enum
  if (!Array.isArray(e)) return undefined
  const vals = e.filter((x) => x !== null)
  return vals.length && vals.every((x) => typeof x === 'string') ? (vals as string[]) : undefined
}

/** The allowed values of a string enum property. */
export function enumValues(p: Prop | undefined): string[] | undefined {
  return baseType(p) === 'string' ? stringEnum(p) : undefined
}

/** The allowed values of an array property whose items are a string enum. */
export function itemEnum(p: Prop | undefined): string[] | undefined {
  if (baseType(p) !== 'array') return undefined
  const items = p?.items as Prop | undefined
  return items && baseType(items) === 'string' ? stringEnum(items) : undefined
}

/** `"x-rackbook": {"suggest": true|false}` on the property; undefined when not set. */
export function suggestOption(p: Prop | undefined): boolean | undefined {
  const x = p?.['x-rackbook']
  if (x && typeof x === 'object') {
    const s = (x as Record<string, unknown>).suggest
    if (typeof s === 'boolean') return s
  }
  return undefined
}

export type FieldCtx = { isKey: boolean; isRef: boolean }

export function fieldKind(p: Prop | undefined, ctx: FieldCtx): FieldKind {
  if (!p || ctx.isRef) return 'plain'
  switch (baseType(p)) {
    case 'boolean':
      return 'boolean'
    case 'array': {
      if (itemEnum(p)) return 'tags'
      const items = p.items as Prop | undefined
      return items && baseType(items) === 'string' ? 'list' : 'plain'
    }
    case 'string': {
      if (stringEnum(p)) return 'enum'
      if (p.format === 'textarea') return 'textarea'
      if (p.format === 'date') return 'date'
      const opt = suggestOption(p)
      if (opt === false) return 'plain'
      if (opt === true) return 'suggest'
      return !p.format && !p.pattern && !ctx.isKey ? 'suggest' : 'plain'
    }
  }
  return 'plain'
}

/** Field kinds a list cell can edit in place. */
export type InlineKind = 'boolean' | 'enum' | 'tags' | 'date'

export function inlineKind(p: Prop | undefined, ctx: FieldCtx): InlineKind | null {
  const k = fieldKind(p, ctx)
  // key fields are the record id: changing one renames the record, which needs the form
  if (ctx.isKey) return null
  return k === 'boolean' || k === 'enum' || k === 'tags' || k === 'date' ? k : null
}

/** Distinct non-empty values already used in a field, most used first. */
export function suggestValues(records: { data: Record<string, unknown> }[], field: string, limit = 300): string[] {
  const counts = new Map<string, number>()
  for (const r of records) {
    const v = r.data[field]
    if (typeof v === 'string' && v.trim() !== '') counts.set(v, (counts.get(v) ?? 0) + 1)
  }
  return [...counts]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([v]) => v)
}

/** The port / port range pattern of the ports field of the ledger schemas. */
export const PORT_PATTERN = '^[0-9]{1,5}(-[0-9]{1,5})?$'
export const PORT_HINT = '端口或范围，如 443、20000-20018'

/** Error text for a port or range entry, undefined when it is fine. */
export function portEntryError(s: string): string | undefined {
  const m = /^([0-9]{1,5})(?:-([0-9]{1,5}))?$/.exec(s)
  if (!m) return PORT_HINT
  const lo = Number(m[1])
  const hi = m[2] === undefined ? lo : Number(m[2])
  if (lo > 65535 || hi > 65535) return '端口不能超过 65535'
  if (hi < lo) return '范围的起点不能大于终点'
  return undefined
}

/** What an entry of a list field must look like: the schema's description, else a hint for known patterns. */
export function listHint(items: Prop | undefined, description?: unknown): string | undefined {
  if (typeof description === 'string' && description) return description
  if (items?.pattern === PORT_PATTERN) return PORT_HINT
  if (typeof items?.pattern === 'string') return `需匹配 ${items.pattern}`
  return undefined
}

/**
 * Error text for one entry of a list field, undefined when it is fine. `formats`
 * checks items.format (the console's customFormats); the pattern is the
 * schema's, with the extra range checks for the port pattern.
 */
export function listEntryError(
  items: Prop | undefined,
  entry: string,
  formats: Record<string, (s: string) => boolean> = {},
  description?: unknown,
): string | undefined {
  const hint = listHint(items, description) ?? '格式不正确'
  if (typeof items?.pattern === 'string') {
    let re: RegExp | undefined
    try {
      re = new RegExp(items.pattern)
    } catch {
      re = undefined
    }
    if (re && !re.test(entry)) return hint
    if (items.pattern === PORT_PATTERN) return portEntryError(entry)
  }
  const f = typeof items?.format === 'string' ? formats[items.format] : undefined
  if (f && !f(entry)) return hint
  if (typeof items?.maxLength === 'number' && entry.length > items.maxLength) return `最多 ${items.maxLength} 个字符`
  return undefined
}
