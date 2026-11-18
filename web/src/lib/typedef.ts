// Data type management (docs/design-v0.2.md section 3): shapes of /api/types.

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

/** Console types in the order the field dialog offers them. */
export const FIELD_TYPES: { type: FieldType; label: string; hint: string }[] = [
  { type: 'text', label: '文本', hint: '短文本，可限制长度、正则，给出输入建议' },
  { type: 'textarea', label: '长文本', hint: '多行文字，如备注' },
  { type: 'integer', label: '整数', hint: '整数，可限制范围' },
  { type: 'number', label: '数字', hint: '小数或整数，可限制范围' },
  { type: 'ip', label: 'IP 地址', hint: 'IPv4 或 IPv6' },
  { type: 'ipv4', label: 'IPv4 地址', hint: '只接受 IPv4' },
  { type: 'ipv6', label: 'IPv6 地址', hint: '只接受 IPv6' },
  { type: 'cidr', label: '网段（CIDR）', hint: '如 10.0.0.0/24、fd00::/64' },
  { type: 'port', label: '端口', hint: '整数 1–65535' },
  { type: 'port-spec', label: '端口 + 协议', hint: '如 TCP 443、UDP 41641' },
  { type: 'hostname', label: '域名', hint: '主机名或域名' },
  { type: 'url', label: 'URL', hint: '如 https://example.com' },
  { type: 'enum', label: '枚举', hint: '从固定的几个值中选一个，可配颜色' },
  { type: 'bool', label: '布尔', hint: '是 / 否' },
  { type: 'date', label: '日期', hint: 'YYYY-MM-DD' },
  { type: 'ref', label: '引用', hint: '指向另一个集合的记录' },
]

export function fieldTypeLabel(type: FieldType): string {
  return FIELD_TYPES.find((x) => x.type === type)?.label ?? '高级'
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
