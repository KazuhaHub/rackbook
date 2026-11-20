// The text of configured things in the viewer's language: field titles and descriptions,
// enum labels and icons, collection and note titles, the ledger title.
//
// Lookup for language L: the L entry of `x-rackbook-i18n` (schema) or `i18n` (meta objects),
// else the standard text, which is in the configured default language. For an enum code the
// last step is the code itself. Call these at render time: they read the current language.
// Imports only relative .ts files so scripts/check-console-logic.mts can test it.
import { locale } from '../i18n/index.ts'
import { baseType, enumEntries, itemEntries, type Prop } from './fieldKind.ts'

export const PLACEHOLDER_TBD = 'tbd'

const I18N_KEY = 'x-rackbook-i18n'

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function nonEmpty(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined
}

/** `x-rackbook-i18n[L]` of a property (an object, possibly empty). */
function schemaText(p: Prop | undefined, loc: string): Record<string, unknown> {
  const all = p?.[I18N_KEY]
  const one = isObj(all) ? all[loc] : undefined
  return isObj(one) ? one : {}
}

export function fieldTitle(p: Prop | undefined, name: string, loc: string = locale): string {
  return nonEmpty(schemaText(p, loc).title) ?? nonEmpty(p?.title) ?? name
}

export function fieldDescription(p: Prop | undefined, loc: string = locale): string | undefined {
  return nonEmpty(schemaText(p, loc).description) ?? nonEmpty(p?.description)
}

/** The schema title of the whole record type (root of a collection's schema). */
export const schemaTitle = (p: Prop | undefined, fallback: string, loc: string = locale) => fieldTitle(p, fallback, loc)

/** The property schema an error path such as `.exposure[0]` or `.ports[1].protocol` points at; undefined when the path leaves the schema. */
export function propAt(root: Prop | undefined, path: string): Prop | undefined {
  let cur: Prop | undefined = root
  // RJSF writes array indexes as dot segments (".ports.2.protocol"); "[2]" is accepted too
  for (const seg of path.match(/[^.[\]]+/g) ?? []) {
    if (!cur) return undefined
    const props = cur.properties as Record<string, unknown> | undefined
    const next: unknown = props && Object.hasOwn(props, seg) ? props[seg] : /^\d+$/.test(seg) ? cur.items : undefined
    cur = isObj(next) ? next : undefined
  }
  return cur
}

/** "label (code)" for each allowed code in `loc`; just the label when it equals the code. */
export function enumChoices(p: Prop | undefined, codes: string[], loc: string = locale): string[] {
  return codes.map((c) => {
    const l = enumLabel(p, c, loc)
    return l === c ? c : `${l} (${c})`
  })
}

// ---- enums ------------------------------------------------------------------------------------

export type EnumOption = { value: string; label: string; icon?: string; color?: string }

/** The property whose `enum`/`oneOf` defines the options: the property, or the items of an array. */
function enumHosts(p: Prop | undefined): { entries: ReturnType<typeof enumEntries>; hosts: Prop[] } {
  if (!p) return { entries: undefined, hosts: [] }
  if (baseType(p) === 'array') {
    const items = p.items as Prop | undefined
    return { entries: itemEntries(p), hosts: items ? [items, p] : [p] }
  }
  return { entries: enumEntries(p), hosts: [p] }
}

function mapOf(hosts: Prop[], key: string): Record<string, unknown> {
  for (const h of hosts) {
    const m = h[key]
    if (isObj(m)) return m
  }
  return {}
}

/** Whether the property (or its items) is an enum, in either form. */
export function isEnumLike(p: Prop | undefined): boolean {
  return enumHosts(p).entries !== undefined
}

/** Label of one code in `loc`: the translation, else the `oneOf` title, else the code itself. */
function labelIn(hosts: Prop[], titles: Map<string, string | undefined>, code: string, loc: string): string {
  for (const h of hosts) {
    const en = schemaText(h, loc).enum
    const l = isObj(en) ? nonEmpty(en[code]) : undefined
    if (l) return l
  }
  return titles.get(code) ?? code
}

/** Options `{value, label, icon?, color?}` of an enum property (or an array of enum items) in the current language. */
export function enumOptions(p: Prop | undefined, loc: string = locale): EnumOption[] {
  const { entries, hosts } = enumHosts(p)
  if (!entries) return []
  const titles = new Map(entries.map((e) => [e.value, e.title]))
  const icons = mapOf(hosts, 'x-rackbook-enum-icons')
  const colors = mapOf(hosts, 'x-rackbook-enum-colors')
  return entries.map((e) => ({
    value: e.value,
    label: labelIn(hosts, titles, e.value, loc),
    icon: nonEmpty(icons[e.value]),
    color: nonEmpty(colors[e.value]),
  }))
}

/** The label of a stored value; a value the schema does not list (or a non-enum property) is shown as it is. */
export function enumLabel(p: Prop | undefined, value: string, loc: string = locale): string {
  const { entries, hosts } = enumHosts(p)
  const e = entries?.find((x) => x.value === value)
  return e ? labelIn(hosts, new Map([[e.value, e.title]]), value, loc) : value
}

/** The option of a stored value, with a plain fallback (no icon, no colour) for an unlisted value. */
export function enumOption(p: Prop | undefined, value: string, loc: string = locale): EnumOption {
  return enumOptions(p, loc).find((o) => o.value === value) ?? { value, label: value }
}

/** Every name a code goes by: the code, its standard title and its translation in each language. */
export function enumNames(p: Prop | undefined, value: string): string[] {
  const { entries, hosts } = enumHosts(p)
  const names = [value, entries?.find((e) => e.value === value)?.title]
  for (const h of hosts) {
    const i18n = h[I18N_KEY]
    if (!isObj(i18n)) continue
    for (const v of Object.values(i18n)) {
      const en = isObj(v) ? v.enum : undefined
      if (isObj(en)) names.push(nonEmpty(en[value]))
    }
  }
  return [...new Set(names.filter((n): n is string => n !== undefined))]
}

/**
 * The code a typed text stands for: the text is a code, or the label of a code in any language
 * (standard text or a translation). An exact match wins; failing that a match ignoring case.
 * undefined: not a known code or label, or ambiguous.
 */
export function codeForLabel(p: Prop | undefined, typed: string): string | undefined {
  const { entries } = enumHosts(p)
  const text = typed.trim()
  if (!entries || text === '') return undefined
  const find = (fold: (s: string) => string) =>
    entries.filter((e) => enumNames(p, e.value).some((n) => fold(n) === fold(text))).map((e) => e.value)
  const exact = find((s) => s)
  if (exact.length) return exact.length === 1 ? exact[0] : exact.find((v) => v === text)
  const loose = find((s) => s.toLowerCase())
  return loose.length === 1 ? loose[0] : undefined
}

/** Whether a search query matches a code by its code or any of its names (any case). */
export function enumMatches(p: Prop | undefined, value: string, query: string): boolean {
  const q = query.trim().toLowerCase()
  return q === '' || enumNames(p, value).some((n) => n.toLowerCase().includes(q))
}

/** Text a search should match for a code: the code and its label in the current language. */
export function enumSearchText(p: Prop | undefined, value: string, loc: string = locale): string {
  const label = enumLabel(p, value, loc)
  return label === value ? value : `${value} ${label}`
}

// ---- meta objects -----------------------------------------------------------------------------

type MetaI18n = Record<string, Record<string, string | undefined>> | undefined

function metaText(i18n: MetaI18n, loc: string, key: string): string | undefined {
  return nonEmpty(i18n?.[loc]?.[key])
}

type Titled = { title?: string; description?: string; group?: string; name?: string; i18n?: MetaI18n }

export const collectionTitle = (c: Titled, loc: string = locale) => metaText(c.i18n, loc, 'title') ?? nonEmpty(c.title) ?? c.name ?? ''
/** The title of a collection that may not exist (a reference to an unknown name): the name then. */
export const collectionTitleOf = (c: Titled | undefined, name: string, loc: string = locale) => (c ? collectionTitle(c, loc) : name)
export const collectionDescription = (c: Titled, loc: string = locale) => metaText(c.i18n, loc, 'description') ?? nonEmpty(c.description)
export const collectionGroup = (c: Titled, loc: string = locale) => metaText(c.i18n, loc, 'group') ?? nonEmpty(c.group)

export const ledgerTitle = (m: { title?: string; i18n?: MetaI18n }, loc: string = locale) => metaText(m.i18n, loc, 'title') ?? nonEmpty(m.title) ?? ''
export const ledgerDescription = (m: { description?: string; i18n?: MetaI18n }, loc: string = locale) =>
  metaText(m.i18n, loc, 'description') ?? nonEmpty(m.description)

export const noteTitle = (n: { title: string; i18n?: MetaI18n }, loc: string = locale) => metaText(n.i18n, loc, 'title') ?? n.title
export const backrefTitle = (b: { title?: string; i18n?: MetaI18n }, loc: string = locale) => metaText(b.i18n, loc, 'title') ?? nonEmpty(b.title)
