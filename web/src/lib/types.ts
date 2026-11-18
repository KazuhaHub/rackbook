export type JsonSchema = {
  type?: string | string[]
  title?: string
  description?: string
  format?: string
  default?: unknown
  examples?: unknown[]
  enum?: unknown[]
  required?: string[]
  properties?: Record<string, JsonSchema>
  items?: JsonSchema
  [k: string]: unknown
}

export type Facet = { field: string; match: 'exact' | 'contains' | 'prefix'; values: string[] }
export type Ref = { field: string; to: string; toField: string; allow?: string[]; many?: boolean }
export type Backref = { collection: string; field: string }
export type Note = { title: string; text: string }

export type Collection = {
  name: string
  title: string
  description?: string
  group?: string
  key?: string[]
  label?: string
  list?: string[]
  facets?: Facet[]
  schema: JsonSchema
  refs?: Ref[]
  backrefs?: Backref[]
  notes?: Note[]
  count: number
}

export type MetaUser = { email?: string; name?: string; canEdit: boolean }
export type Meta = {
  title: string
  description?: string
  readOnly: boolean
  writeMode?: string
  user: MetaUser | null
  collections: Collection[]
}

export type LedgerRecord = {
  id: string
  hash: string
  data: Record<string, unknown>
}
export type RecordWithBackrefs = LedgerRecord & { backrefs?: Record<string, LedgerRecord[]> }

export type CheckError = {
  collection?: string
  id?: string
  path?: string
  rule?: string
  message: string
}
export type CheckResult = { ok: boolean; errors: CheckError[] }

export type Commit = { hash: string; author: string; email?: string; date: string; subject: string }
