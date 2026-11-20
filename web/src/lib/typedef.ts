// Data type management (docs/design-v0.2.md section 3): shapes of /api/types.
import { t } from '@/i18n'

export type FieldType =
  | 'text'
  | 'textarea'
  | 'integer'
  | 'number'
  | 'ip'
  | 'ipv4'
  | 'ipv6'
  | 'cidr'
  | 'port'
  | 'port-spec'
  | 'hostname'
  | 'url'
  | 'enum'
  | 'bool'
  | 'date'
  | 'ref'
  | 'advanced'

export type EnumItem = { value: string; color?: string }
export type RefSpec = {
  to: string
  toField: string
  allow?: string[]
  many?: boolean
  message?: string
  backrefTitle?: string
  backrefColumns?: string[]
}
export type Extra = { key: string; value: unknown }

export type FieldDef = {
  name: string
  title?: string
  description?: string
  type: FieldType
  required: boolean
  unique: boolean
  default?: unknown
  minLength?: number
  maxLength?: number
  pattern?: string
  examples?: string[]
  min?: number
  max?: number
  enum?: EnumItem[]
  ref?: RefSpec
  advanced?: boolean
  extras?: Extra[]
}

export type FacetDef = { field: string; match: 'exact' | 'contains' | 'prefix'; values: string[] }

export type TypeDef = {
  name: string
  title: string
  description?: string
  group?: string
  icon?: string
  file: string
  path?: string
  schemaFile: string
  key: string[]
  label?: string
  list: string[]
  facets: FacetDef[]
  fields: FieldDef[]
  unique: string[][]
  extras?: Extra[]
  sameSet?: { message?: string; left: string; right: string }[]
  count: number
  /** Identifies the schema and config entry this type was read from; sent back with every change and delete. */
  version?: string
}

export type TypeSummary = {
  name: string
  title: string
  description?: string
  group?: string
  icon?: string
  file: string
  path?: string
  schemaFile: string
  count: number
  fields: number
  problems: number
}

export type TypeList = {
  types: TypeSummary[]
  fieldTypes: FieldType[]
  formats: string[]
  dataDir: string
  schemaDir: string
  writeMode: string
}

export type Migration = { kind: 'remove-field' | 'fill-default'; field: string; value?: unknown }
export type Offer = { kind: Migration['kind']; field: string; count: number; records: string[]; default?: unknown; applied: boolean }
export type Refusal = { code: string; field?: string; message: string; records?: string[]; count?: number }
export type PlanIssue = { collection: string; id: string; path: string; rule: string; message: string }
export type PlanFile = { path: string; status: 'added' | 'modified' | 'removed'; diff: string }
export type BackrefChange = { collection: string; from: string; change: 'gained' | 'lost' }

export type Plan = {
  op: 'create' | 'update' | 'delete'
  name: string
  clean: boolean
  changed: boolean
  subject: string
  files: PlanFile[]
  invalid: PlanIssue[]
  dangling: PlanIssue[]
  other: PlanIssue[]
  backrefs: BackrefChange[]
  migrations: Offer[]
  refusals: Refusal[]
  type?: TypeDef
  truncated?: boolean
}

export type TypeWrite = { name: string; commit: string; files: string[]; changed: boolean }

/** The console types, in the order the field dialog offers them. */
const FIELD_TYPE_ORDER: Exclude<FieldType, 'advanced'>[] = [
  'text', 'textarea', 'integer', 'number', 'ip', 'ipv4', 'ipv6', 'cidr', 'port', 'port-spec', 'hostname', 'url', 'enum', 'bool', 'date', 'ref',
]

/** Console types with their label and hint in the current language (call at render time). */
export function fieldTypes(): { type: FieldType; label: string; hint: string }[] {
  return FIELD_TYPE_ORDER.map((type) => ({ type, ...t.types.fieldTypes[type] }))
}

export function fieldTypeLabel(type: FieldType): string {
  return (t.types.fieldTypes as Record<string, { label: string }>)[type]?.label ?? t.types.fieldTypeAdvanced
}

export const EMPTY_FIELD: FieldDef = { name: '', type: 'text', required: false, unique: false }

export function emptyType(): TypeDef {
  return {
    name: '',
    title: '',
    file: '',
    schemaFile: '',
    key: [],
    list: [],
    facets: [],
    fields: [],
    unique: [],
    count: 0,
  }
}

/** Stable JSON used to tell whether a draft differs from what is saved. */
export const stable = (v: unknown) => JSON.stringify(v)
