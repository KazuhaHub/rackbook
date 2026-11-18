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
export type Backref = { collection: string; field: string; title?: string; columns?: string[] }
export type Note = { title: string; text: string }

export type Collection = {
  name: string
  title: string
  description?: string
  group?: string
  /** optional lucide icon name; unknown names are ignored */
  icon?: string
  file?: string
  path?: string
  schemaFile?: string
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

export type Role = 'admin' | 'editor' | 'viewer'
export type MetaUser = {
  id?: string
  email?: string
  name?: string
  role?: Role
  authMethod?: string
  /** role is editor or higher and the server is not read-only */
  canEdit: boolean
  canAdmin?: boolean
}
/** Shown as a banner while the server pauses writes. */
export type MetaAlert =
  | { kind: 'history_rewritten'; lastGood: string; remote: string }
  /** rackbook.yml does not load: the last good config is served read-only */
  | { kind: 'config_error'; message: string }
export type Meta = {
  title: string
  description?: string
  readOnly: boolean
  writeMode?: string
  user: MetaUser | null
  alert?: MetaAlert
  branding?: { name: string; logo: boolean }
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

export type ApiToken = {
  name: string
  prefix: string
  scope: 'read' | 'write'
  collections?: string[]
  actions?: string[]
  writeMode?: 'push'
  createdBy: string
  created: string
  expires?: string
  revoked?: string
  revokedBy?: string
  status: 'active' | 'revoked' | 'expired'
  lastUsed?: string
  creatorRole: string
  warnings: string[]
}
export type CreatedToken = {
  token: ApiToken
  secret: string
  pullRequest?: boolean
  snippet: unknown
  claudeCode: string
}
