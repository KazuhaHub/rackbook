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

/** Text of other languages, keyed by locale tag (raw from /api/meta; the console picks by its language). */
export type MetaI18n = Record<string, Record<string, string | undefined>>

export type Facet = { field: string; match: 'exact' | 'contains' | 'prefix'; values: string[] }
export type Ref = { field: string; to: string; toField: string; allow?: string[]; many?: boolean }
export type Backref = { collection: string; field: string; title?: string; columns?: string[]; i18n?: MetaI18n }
export type Note = { title: string; text: string; i18n?: MetaI18n }

export type Collection = {
  name: string
  title: string
  description?: string
  group?: string
  i18n?: MetaI18n
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
  /** the schema field marked as the expiry date; empty or absent when none */
  expiryField?: string
  /** the schema field marked as the revoked date; empty or absent when none */
  revokedField?: string
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
  /** on auth.auditors: reads the audit areas of Activity and the audit status; a capability next to the role, no write */
  auditor?: boolean
  /** may see the read-only /infra pages (listed in --infra-admins, signed in with the console login) */
  canInfra?: boolean
  /** may also edit it: the editors are on and the server is not read-only (a recent sign-in is still needed per save) */
  canInfraWrite?: boolean
  /** listed in --infra-auditors: reads /infra without secrets, edits nothing */
  infraAuditor?: boolean
  /** the language this person chose (server-side preference); absent = none chosen */
  locale?: string
}
/** Shown as a banner while the server pauses writes. */
export type MetaAlert =
  | { kind: 'history_rewritten'; lastGood: string; remote: string }
  /** rackbook.yml does not load: the last good config is served read-only */
  | { kind: 'config_error'; message: string }
/** A module allowed to write one collection (rackbook.yml `modules:`, without token names). */
export type ModuleInfo = {
  name: string
  /** entra or notify; absent for a module without settings in the console */
  type?: string
  /** the module may not write records (no collection) */
  readOnly?: boolean
  collection: string
  fields: string[]
  directPush: boolean
}
export type Meta = {
  title: string
  description?: string
  i18n?: MetaI18n
  readOnly: boolean
  writeMode?: string
  user: MetaUser | null
  alert?: MetaAlert
  /** administrators only: the audit log has recorded problems nobody has acknowledged */
  auditAlert?: { problems: number; firstSeq: number }
  branding?: { name: string; logo: boolean }
  collections: Collection[]
  modules?: ModuleInfo[]
  /** the built-in OAuth authorization server is on: grants can be listed and revoked */
  oauthServer?: boolean
  /** the supported language that best matches the browser's Accept-Language (else defaultLocale) */
  locale?: string
  /** rackbook.yml i18n.default */
  defaultLocale?: string
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
  /** what failed and the values of the message (lib/issues.ts words them); message is the English fallback */
  keyword?: string
  params?: Record<string, unknown>
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
  /** the module (rackbook.yml modules:) that uses this token */
  module?: string
  warnings: string[]
}
export type CreatedToken = {
  token: ApiToken
  secret: string
  pullRequest?: boolean
  snippet: unknown
  claudeCode: string
}

export type ExpiryStatus = 'expired' | 'expiring' | 'unknown'
export type ExpiringItem = {
  collection: string
  id: string
  label: string
  expires: string
  daysLeft: number | null
  status: ExpiryStatus
  /** empty for hand-made records, else the module that wrote it */
  source: string
}
export type ExpiringResult = { today: string; days: number; items: ExpiringItem[] }
