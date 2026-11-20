// A validation problem from the server, worded in the current language.
//
// The server sends each issue with `keyword` (what failed) and `params` (the
// values the message is made of; docs/api.md, GET /api/check) next to an English
// `message`. issueText words the known keywords from the translation files and
// falls back to `message` for anything else, or when a param it needs is
// missing. Like the rest of the console's copy, call it at render time.
// Imports only relative .ts files so scripts/check-console-logic.mts can test it.
import { t, locale } from '../i18n/index.ts'
import { formatNumber } from '../i18n/format.ts'
import { collectionTitle, enumChoices, enumLabel, fieldTitle } from './labels.ts'
import type { Prop } from './fieldKind.ts'

export type Issue = {
  collection?: string
  id?: string
  path?: string
  rule?: string
  message: string
  keyword?: string
  params?: Record<string, unknown>
}

/** What issueText needs to know about a collection to name its fields and enum labels. */
export type IssueCollection = { name: string; title?: string; i18n?: Record<string, Record<string, string | undefined>>; schema?: Prop }

const str = (v: unknown): v is string => typeof v === 'string'
const strs = (v: unknown): v is string[] => Array.isArray(v) && v.every(str)
const num = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)

/** A record value as the message shows it: strings in quotes, anything else as JSON. */
function shown(v: unknown): string {
  return str(v) ? t.issues.quote(v) : JSON.stringify(v) ?? String(v)
}

/** The schema property an issue's JSON pointer points at (undefined without a schema). */
function propOf(schema: Prop | undefined, pointer: string | undefined): Prop | undefined {
  if (!schema || !pointer) return undefined
  let cur: Prop | undefined = schema
  for (const raw of pointer.split('/').slice(1)) {
    const seg = raw.replace(/~1/g, '/').replace(/~0/g, '~')
    const props = cur.properties as Record<string, unknown> | undefined
    const next: unknown = props && Object.hasOwn(props, seg) ? props[seg] : /^\d+$/.test(seg) ? cur.items : undefined
    if (!next || typeof next !== 'object' || Array.isArray(next)) return undefined
    cur = next as Prop
  }
  return cur
}

/** The object property an issue's pointer points at; for required and the like, a field of it is named. */
function fieldsOf(schema: Prop | undefined, pointer: string | undefined, names: string[]): string[] {
  const obj = pointer ? propOf(schema, pointer) : schema
  const props = obj?.properties as Record<string, Prop> | undefined
  return names.map((n) => fieldTitle(props && Object.hasOwn(props, n) ? props[n] : undefined, n))
}

/** "collection.field" as "Collection title · field title" when the collection is known. */
function fieldRef(ref: string, byName: (name: string) => IssueCollection | undefined): string {
  const dot = ref.indexOf('.')
  if (dot < 0) return ref
  const c = byName(ref.slice(0, dot))
  if (!c) return ref
  const f = ref.slice(dot + 1)
  const props = c.schema?.properties as Record<string, Prop> | undefined
  return t.issues.fieldOf(collectionTitle(c), fieldTitle(props && Object.hasOwn(props, f) ? props[f] : undefined, f))
}

/** The rule's own message from rackbook.yml in the current language, if it has one. */
function ruleMessage(p: Record<string, unknown>): string | undefined {
  const tr = p.ruleMessageI18n
  const own = tr && typeof tr === 'object' ? (tr as Record<string, unknown>)[locale] : undefined
  if (str(own) && own) return own
  return str(p.ruleMessage) && p.ruleMessage ? p.ruleMessage : undefined
}

/**
 * The issue's message in the current language. collections names the fields
 * and enum codes with their labels; without it the codes and field keys show.
 */
export function issueText(issue: Issue, collections: IssueCollection[] = []): string {
  const p = issue.params ?? {}
  const byName = (n: string) => collections.find((c) => c.name === n)
  const schema = issue.collection ? byName(issue.collection)?.schema : undefined
  const v = t.validation
  const s = t.issues
  switch (issue.keyword) {
    case 'required':
      if (strs(p.missing)) return s.required(fieldsOf(schema, issue.path, p.missing))
      break
    case 'dependentRequired':
    case 'dependencies':
      if (str(p.property) && strs(p.missing)) return s.dependentRequired(fieldsOf(schema, issue.path, [p.property])[0], fieldsOf(schema, issue.path, p.missing))
      break
    case 'additionalProperties':
      if (strs(p.properties)) return v.additionalProperty(p.properties.join(t.common.listSep))
      break
    case 'type':
      if (strs(p.want)) return v.type(p.want.join(' / '))
      break
    case 'enum': {
      const prop = propOf(schema, issue.path)
      if (str(p.use)) return s.useCode(shown(p.value), p.use, enumLabel(prop, p.use))
      if (strs(p.allowed)) return v.enum(enumChoices(prop, p.allowed))
      break
    }
    case 'const':
      if ('want' in p) return s.const(shown(p.want))
      break
    case 'format':
      if (str(p.format)) return Object.hasOwn(v.formats, p.format) ? v.formats[p.format] : v.formatFallback(p.format)
      break
    case 'pattern':
      if (str(p.pattern)) return v.pattern(p.pattern)
      break
    case 'minLength':
      if (num(p.limit)) return v.minLength(p.limit)
      break
    case 'maxLength':
      if (num(p.limit)) return v.maxLength(p.limit)
      break
    case 'minItems':
      if (num(p.limit)) return s.minItems(p.limit)
      break
    case 'maxItems':
      if (num(p.limit)) return s.maxItems(p.limit)
      break
    case 'minimum':
      if (num(p.limit)) return v.minimum(formatNumber(p.limit))
      break
    case 'maximum':
      if (num(p.limit)) return v.maximum(formatNumber(p.limit))
      break
    case 'exclusiveMinimum':
      if (num(p.limit)) return s.exclusiveMinimum(formatNumber(p.limit))
      break
    case 'exclusiveMaximum':
      if (num(p.limit)) return s.exclusiveMaximum(formatNumber(p.limit))
      break
    case 'multipleOf':
      if (num(p.limit)) return s.multipleOf(formatNumber(p.limit))
      break
    case 'uniqueItems':
      if (num(p.first) && num(p.second)) return s.uniqueItems(p.first + 1, p.second + 1)
      break
    case 'unique':
      if (strs(p.values) && strs(p.fields)) {
        const names = fieldsOf(schema, '', p.fields)
        const vals = p.values.map((x) => s.quote(x)).join(' / ')
        return p.key === true ? s.duplicateKey(vals, names) : s.duplicateValues(vals, names)
      }
      break
    case 'ref':
      if (str(p.value) && str(p.target)) return s.withRule(ruleMessage(p), s.unknownRef(s.quote(p.value), fieldRef(p.target, byName)))
      break
    case 'same_set':
      if (str(p.value) && str(p.left) && str(p.right) && (p.side === 'left' || p.side === 'right')) {
        const left = fieldRef(p.left, byName)
        const rule = ruleMessage(p) ?? s.sameSetRule(left, p.right)
        const val = s.quote(p.value)
        return s.withRule(rule, p.side === 'left' ? s.onlyLeft(val, p.right) : s.onlyRight(val, p.right))
      }
      break
  }
  return issue.message
}
