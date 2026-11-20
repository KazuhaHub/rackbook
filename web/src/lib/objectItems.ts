// Arrays whose items are flat objects of scalar properties (for instance
// {protocol, port, note}). The form edits them as a table, lists show each item
// as a badge. Schema-driven: no property name is known here. Import-free so
// scripts/check-console-logic.mts can test it.

export type Prop = { [k: string]: unknown }

const SCALARS = ['string', 'number', 'integer', 'boolean']

function baseType(p: Prop | undefined): string | undefined {
  const t = p?.type
  if (typeof t === 'string') return t
  if (Array.isArray(t)) return t.find((x) => x !== 'null') as string | undefined
  return undefined
}

/** The item schema when `p` is an array of flat objects whose properties are all scalar; else undefined. */
export function objectItems(p: Prop | undefined): { props: [string, Prop][]; required: string[] } | undefined {
  if (baseType(p) !== 'array') return undefined
  const items = p?.items as Prop | undefined
  if (!items || baseType(items) !== 'object') return undefined
  const props = Object.entries((items.properties as Record<string, Prop> | undefined) ?? {})
  if (!props.length || !props.every(([, s]) => s && typeof s === 'object' && SCALARS.includes(baseType(s) ?? ''))) return undefined
  const required = Array.isArray(items.required) ? (items.required as string[]) : []
  return { props, required }
}

/** An optional free-text property (no enum, pattern or format): a note, not part of the item's identity. */
function isNote(s: Prop, name: string, required: string[]): boolean {
  return baseType(s) === 'string' && !required.includes(name) && !s.enum && !s.oneOf && !s.pattern && !s.format
}

function scalar(v: unknown): string {
  return v === undefined || v === null ? '' : String(v)
}

/** One item as text: its values in property order, notes left out ("TCP 443"), and the notes as a tooltip. */
export function formatItem(
  item: unknown,
  spec: { props: [string, Prop][]; required: string[] },
  /** how a value of a property reads (an enum code as its label); default: as stored */
  show: (s: Prop, v: string) => string = (_s, v) => v,
): { text: string; title?: string } {
  const rec = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>
  const main: string[] = []
  const notes: string[] = []
  for (const [name, s] of spec.props) {
    const raw = scalar(rec[name])
    if (raw === '') continue
    const v = show(s, raw)
    ;(isNote(s, name, spec.required) ? notes : main).push(v)
  }
  // an item that is only a note still shows
  const text = main.join(' ') || notes.join(' ')
  return { text, title: main.length && notes.length ? notes.join(' ') : undefined }
}

/** Items of an array value as text, without a schema: every scalar value, in order. */
export function formatPlain(item: unknown): string {
  if (item && typeof item === 'object') return Object.values(item).map(scalar).filter(Boolean).join(' ')
  return scalar(item)
}

export function isScalarObject(v: unknown): boolean {
  return !!v && typeof v === 'object' && !Array.isArray(v) && Object.values(v).every((x) => x === null || SCALARS.includes(typeof x))
}
