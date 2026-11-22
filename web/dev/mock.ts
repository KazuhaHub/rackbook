// Dev-only mock of docs/api.md, served from the example ledger YAML.
// Enabled by `npm run dev:mock` (vite --mode mock); never imported by a production build.
// Writes are kept in memory and are lost on restart. MOCK_READONLY=1 simulates read-only mode,
// MOCK_PROBLEMS=1 seeds records that fail validation.
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { parse } from 'yaml'
import type { Plugin } from 'vite'
import { isCountryCode } from '../src/lib/countries.ts'

type Data = Record<string, any>
type Rec = { id: string; hash: string; data: Data }
type CheckErr = { collection: string; id: string; path: string; rule: string; message: string; keyword?: string; params?: Record<string, unknown> }
type RefRule = {
  collection: string
  field: string
  to: string
  toField: string
  allow: string[]
  many: boolean
  title?: string
  message?: string
  i18n?: Record<string, Record<string, string>>
}
type Coll = {
  name: string
  cfg: any
  schema: any
  rows: Data[]
  validate: (d: unknown) => boolean
  validateFn: any
}

const escId = (s: string) => s.replace(/%/g, '%25').replace(/\//g, '%2F')
const canon = (v: any): any =>
  Array.isArray(v)
    ? v.map(canon)
    : v && typeof v === 'object'
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, canon(v[k])]),
        )
      : v
/** A backref carries its title only: the rule's backref_title of each language, as `title`. */
const backrefI18n = (i18n: Record<string, Record<string, string>> | undefined) =>
  Object.fromEntries(Object.entries(i18n ?? {}).filter(([, v]) => v.backref_title).map(([loc, v]) => [loc, { title: v.backref_title }]))
const hashOf = (d: Data) => createHash('sha256').update(JSON.stringify(canon(d))).digest('hex').slice(0, 16)
const dig = (o: any, p: string) => (p ? p.split('.').reduce((a, k) => a?.[k], o) : o)

// rackbook.yml i18n blocks hold the default language next to the locale tags; the API sends only the tags.
const localeTags = ['zh-CN', 'zh-TW', 'en-US']
const tagsOnly = (i18n: any): Record<string, Record<string, string>> | undefined => {
  const out = Object.fromEntries(Object.entries<any>(i18n ?? {}).filter(([k, v]) => localeTags.includes(k) && v && typeof v === 'object'))
  return Object.keys(out).length ? out : undefined
}
/** Only some keys of each locale entry (a backref carries its title only). */
const pickKeys = (i18n: Record<string, Record<string, string>> | undefined, ...keys: string[]) => {
  if (!i18n) return undefined
  const out = Object.fromEntries(
    Object.entries(i18n)
      .map(([loc, v]) => [loc, Object.fromEntries(keys.filter((k) => v[k] !== undefined).map((k) => [k, v[k]]))] as const)
      .filter(([, v]) => Object.keys(v).length),
  )
  return Object.keys(out).length ? out : undefined
}

// "static" -> `"静态" is not allowed; use code "static"` and one issue for a value of no enum code,
// the way the server words it (the noisy oneOf sub-errors are dropped).
// the message and the structured form (keyword + params) of an enum failure, as the server words it
function enumIssue(e: any): { message: string; params: Record<string, unknown> } | undefined {
  const codes: string[] | undefined =
    e.keyword === 'enum'
      ? e.params.allowedValues.filter((x: unknown) => typeof x === 'string')
      : e.keyword === 'oneOf' && Array.isArray(e.schema) && e.schema.every((x: any) => typeof x?.const === 'string')
        ? e.schema.map((x: any) => x.const)
        : undefined
  if (!codes || typeof e.data !== 'string') return undefined
  const names = (code: string) => {
    const out = [code, ...(Array.isArray(e.parentSchema?.oneOf) ? e.parentSchema.oneOf.filter((x: any) => x.const === code).map((x: any) => x.title) : [])]
    for (const v of Object.values<any>(e.parentSchema?.['x-rackbook-i18n'] ?? {})) out.push(v?.enum?.[code])
    return out.filter(Boolean) as string[]
  }
  const hit = codes.find((c) => names(c).some((n) => n === e.data || n.toLowerCase() === e.data.toLowerCase()))
  return hit
    ? { message: `"${e.data}" is not allowed; use code "${hit}"`, params: { value: e.data, use: hit } }
    : { message: `"${e.data}" is not one of: ${codes.join(', ')}`, params: { value: e.data, allowed: codes } }
}

export function mockApi(root: string): Plugin {
  const readOnly = process.env.MOCK_READONLY === '1'
  const cfg = parse(readFileSync(path.join(root, 'rackbook.yml'), 'utf8'))
  const ajv = new Ajv2020({ strict: false, allErrors: true, verbose: true })
  ajv.addFormat('textarea', true)
  // the two Rackbook formats the example uses (src/lib/formats.ts has the same rules)
  ajv.addFormat('country', (v: string) => v === 'tbd' || isCountryCode(v))
  ajv.addFormat('subdivision', (v: string) => v === 'tbd' || (/^[A-Z]{2}-[A-Z0-9]{1,3}$/.test(v) && isCountryCode(v.slice(0, 2))))

  const docs = new Map<string, any>()
  const load = (file: string) => {
    if (!docs.has(file)) docs.set(file, parse(readFileSync(path.join(root, file), 'utf8')))
    return docs.get(file)
  }

  const colls = new Map<string, Coll>()
  for (const [name, c] of Object.entries<any>(cfg.collections)) {
    const schema = JSON.parse(readFileSync(path.join(root, c.schema), 'utf8'))
    const rows: Data[] = structuredClone(dig(load(c.file), c.path ?? '') ?? [])
    const validateFn = ajv.compile(schema)
    colls.set(name, { name, cfg: c, schema, rows, validate: validateFn as any, validateFn })
  }

  // A credentials collection with expiry dates and a module, so the expiry pages have data.
  const dayOffset = (n: number) => new Date(Date.now() + n * 86400000).toISOString().slice(0, 10)
  const credSchema = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    type: 'object',
    required: ['name', 'kind', 'expires'],
    additionalProperties: false,
    properties: {
      name: { type: 'string', title: '名称', 'x-rackbook-i18n': { 'en-US': { title: 'Name' }, 'zh-TW': { title: '名稱' } } },
      kind: {
        type: 'string',
        title: '类型',
        oneOf: [
          { const: 'certificate', title: '证书' },
          { const: 'key', title: '密钥' },
          { const: 'app-credential', title: '应用凭据' },
        ],
        'x-rackbook-enum-icons': { certificate: 'shield-check', key: 'key-round', 'app-credential': 'puzzle' },
        'x-rackbook-i18n': {
          'en-US': { title: 'Kind', enum: { certificate: 'Certificate', key: 'Key', 'app-credential': 'App credential' } },
          'zh-TW': { title: '類型', enum: { certificate: '憑證', key: '金鑰', 'app-credential': '應用憑證' } },
        },
      },
      purpose: { type: 'string', title: '用途', 'x-rackbook-i18n': { 'en-US': { title: 'Purpose' }, 'zh-TW': { title: '用途' } } },
      expires: { type: 'string', title: '到期日', 'x-rackbook-i18n': { 'en-US': { title: 'Expires' }, 'zh-TW': { title: '到期日' } } },
      revoked: { type: 'string', title: '吊销日', 'x-rackbook-i18n': { 'en-US': { title: 'Revoked' }, 'zh-TW': { title: '吊銷日' } } },
      source: { type: 'string', title: '来源', 'x-rackbook-i18n': { 'en-US': { title: 'Source' }, 'zh-TW': { title: '來源' } } },
    },
  }
  const credCfg = {
    title: '凭据',
    group: '安全',
    i18n: { 'en-US': { title: 'Credentials', group: 'Security' }, 'zh-TW': { title: '憑證', group: '安全' } },
    key: ['name'],
    label: 'name',
    list: ['name', 'kind', 'purpose', 'expires', 'source'],
  }
  const credRows: Data[] = [
    { name: 'tls-www', kind: 'certificate', purpose: '官网 HTTPS', expires: dayOffset(-8) },
    { name: 'tls-grafana', kind: 'certificate', purpose: '监控面板', expires: dayOffset(0) },
    { name: 'entra-rackbook-1a2b3c4d', kind: 'app-credential', purpose: 'Entra 应用 rackbook', expires: dayOffset(13), source: 'entra' },
    { name: 'entra-rackbook-9f8e7d6c', kind: 'app-credential', purpose: 'Entra 应用 rackbook', expires: dayOffset(-2), source: 'entra' },
    { name: 'backup-signing-key', kind: 'key', purpose: '备份签名', expires: dayOffset(75) },
    { name: 'vpn-ca', kind: 'certificate', purpose: 'VPN 根证书', expires: dayOffset(300) },
    { name: 'legacy-api-key', kind: 'key', purpose: '旧接口', expires: 'tbd' },
    { name: 'old-cert', kind: 'certificate', purpose: '已吊销', expires: dayOffset(-30), revoked: dayOffset(-40) },
  ]
  colls.set('credentials', {
    name: 'credentials',
    cfg: credCfg,
    schema: credSchema,
    rows: credRows,
    validate: ajv.compile(credSchema) as any,
    validateFn: ajv.compile(credSchema),
  })
  const expiryFields: Record<string, { expiryField: string; revokedField: string }> = {
    credentials: { expiryField: 'expires', revokedField: 'revoked' },
  }
  const infraHead = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678'
  const modules = [
    { name: 'entra', collection: 'credentials', fields: ['kind', 'purpose', 'expires', 'revoked'], directPush: true },
  ]

  // MOCK_PROBLEMS=1 seeds broken records so the problems page has something to show.
  if (process.env.MOCK_PROBLEMS === '1') {
    colls.get('services')!.rows.push({ device: 'ghost-host', service: 'Demo', port: 'TCP 1' })
    colls.get('devices')!.rows.push({ name: 'broken-device' })
  }

  const refRules: RefRule[] = (cfg.rules ?? [])
    .filter((r: any) => r.ref)
    .map((r: any) => {
      const [fc, ff] = r.ref.from.split('.')
      const [tc, tf] = r.ref.to.split('.')
      return {
        collection: fc,
        field: ff,
        to: tc,
        toField: tf,
        allow: r.ref.allow ?? [],
        many: !!r.ref.many,
        title: r.ref.backref_title,
        message: r.ref.message,
        i18n: tagsOnly(r.ref.i18n),
      }
    })

  const idOf = (c: Coll, d: Data, index: number) =>
    c.cfg.key?.length ? c.cfg.key.map((k: string) => escId(String(d[k] ?? ''))).join('/') : `#${index}`
  const records = (c: Coll): Rec[] => c.rows.map((d, i) => ({ id: idOf(c, d, i), hash: hashOf(d), data: d }))

  const normFacet = (f: any) => {
    if (typeof f === 'string') return { field: f, match: 'exact', values: [] }
    if (f.contains) return { field: f.field, match: 'contains', values: f.contains }
    return { field: f.field, match: f.match ?? 'exact', values: f.values ?? [] }
  }

  function check(): CheckErr[] {
    const errs: CheckErr[] = []
    for (const c of colls.values()) {
      const seen = new Set<string>()
      records(c).forEach((r) => {
        if (!c.validateFn(r.data)) {
          // a oneOf enum reports one issue per const; keep a single enum-level message instead
          for (const e of (c.validateFn.errors ?? []).filter((x: any) => !/\/oneOf\/\d+\//.test(x.schemaPath))) {
            const p =
              e.keyword === 'additionalProperties'
                ? `${e.instancePath}/${e.params.additionalProperty}`
                : e.keyword === 'required'
                  ? `${e.instancePath}/${e.params.missingProperty}`
                  : e.instancePath
            const en = enumIssue(e)
            errs.push(
              en
                ? { collection: c.name, id: r.id, path: p, rule: 'schema', message: en.message, keyword: 'enum', params: en.params }
                : { collection: c.name, id: r.id, path: p, rule: 'schema', message: e.message ?? 'invalid' },
            )
          }
        }
        if (c.cfg.key?.length) {
          if (seen.has(r.id)) errs.push({ collection: c.name, id: r.id, path: '', rule: 'unique', message: `duplicate key ${r.id}`, keyword: 'unique', params: { fields: c.cfg.key, values: c.cfg.key.map((k: string) => String(r.data[k] ?? '')), key: true } })
          seen.add(r.id)
        }
      })
    }
    for (const rr of refRules) {
      const from = colls.get(rr.collection)!
      const targets = new Set(colls.get(rr.to)!.rows.map((d) => String(d[rr.toField])))
      records(from).forEach((r) => {
        const vals = rr.many ? [].concat(r.data[rr.field] ?? []) : r.data[rr.field] === undefined ? [] : [r.data[rr.field]]
        for (const v of vals) {
          if (!targets.has(String(v)) && !rr.allow.includes(String(v)))
            errs.push({
              collection: rr.collection,
              id: r.id,
              path: `/${rr.field}`,
              rule: 'ref',
              message: (rr.message ? `${rr.message}: ` : '') + `unknown ${rr.to}.${rr.toField} "${v}"`,
              keyword: 'ref',
              params: ruleParams({ value: String(v), target: `${rr.to}.${rr.toField}` }, rr.message, rr.i18n),
            })
        }
      })
    }
    for (const rule of cfg.rules ?? []) {
      if (!rule.same_set) continue
      const { left, right, message } = rule.same_set
      const lset = new Set(
        colls.get(left.collection)!.rows.filter((d) => Object.entries(left.where ?? {}).every(([k, v]) => d[k] === v)).map((d) => String(d[left.field])),
      )
      const rraw = dig(load(right.file), right.path)
      const rset = new Set<string>(right.take === 'keys' ? Object.keys(rraw ?? {}) : (rraw ?? []).map(String))
      const diff = [...lset].filter((x) => !rset.has(x)).concat([...rset].filter((x) => !lset.has(x)))
      if (diff.length) errs.push({ collection: left.collection, id: '', path: '', rule: 'same_set', message: `${message}: ${diff.join(', ')}` })
    }
    return errs
  }
  const errKey = (e: CheckErr) => `${e.collection}|${e.id}|${e.path}|${e.rule}|${e.message}`
  let baseline = new Set(check().map(errKey))

  const history: { hash: string; author: string; email: string; date: string; subject: string; collection: string }[] = [
    ['devices', 'edit web-hostco-ashburn-va-us-dc', 3],
    ['services', 'add web-hostco-ashburn-va-us-dc/网络台账（Rackbook）', 26],
    ['addresses', 'edit gw-example-springfield-or-us-home/tailscale', 50],
    ['todo', 'edit 所有服务器 SSH 改到 10511', 24 * 6 * 60],
    ['sites', 'add 下一个站点', 24 * 20 * 60],
  ].map(([collection, what, minsAgo], i) => ({
    hash: createHash('sha1').update(`seed${i}`).digest('hex').slice(0, 7),
    author: 'Mock Editor',
    email: 'editor@example.com',
    date: new Date(Date.now() - (minsAgo as number) * 60000).toISOString(),
    subject: `ledger(${collection}): ${what}`,
    collection: collection as string,
  }))

  // MOCK_LOGIN=1 pretends to be logged in with the built-in login (oidc), with a passkey and a user list,
  // so the login, account and users pages can be seen without a server.
  const login = process.env.MOCK_LOGIN === '1'
  const passkeys: { id: string; name: string; created: string }[] = [
    { id: 'pk1', name: 'MacBook Pro', created: new Date(Date.now() - 3 * 86400000).toISOString() },
  ]
  const user = readOnly
    ? { id: 'viewer@example.com', email: 'viewer@example.com', name: 'viewer', role: 'viewer', authMethod: 'none', canEdit: false, canAdmin: false, canInfra: false }
    : { id: 'editor@example.com', email: 'editor@example.com', name: 'Mock Editor', role: 'admin', authMethod: login ? 'oidc' : 'none', canEdit: true, canAdmin: true, canInfra: true, canInfraWrite: true }
  // MOCK_ALERT=1 shows the "history rewritten" banner until it is accepted.
  let alert: { kind: string; lastGood: string; remote: string } | undefined =
    process.env.MOCK_ALERT === '1'
      ? { kind: 'history_rewritten', lastGood: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678', remote: '9f8e7d6c5b4a39281706f5e4d3c2b1a098765432' }
      : undefined

  // MOCK_AUDIT=1 shows the "audit log problems" banner until an admin acknowledges it.
  let auditProblem = process.env.MOCK_AUDIT === '1'

  // The language preference of the mock user (PUT /api/account/preferences), and a
  // rough Accept-Language match like the server's (internal/locale).
  let userLocale: string | undefined
  const matchLocale = (h: string | undefined) => {
    for (const part of (h ?? '').split(',')) {
      const tag = part.split(';')[0].trim().toLowerCase()
      if (tag === 'zh-tw' || tag === 'zh-hk' || tag === 'zh-mo' || tag.startsWith('zh-hant')) return 'zh-TW'
      if (tag.startsWith('zh')) return 'zh-CN'
      if (tag.startsWith('en')) return 'en-US'
    }
    return 'zh-CN'
  }

  // ---- record history, restore and deleted records (docs/design-audit.md, 3.3) ----
  // Every record has a made-up timeline: a hand edit nobody vouches for (unverified), a restore, nested
  // changes, a hidden value and the creation. Restoring the version whose commit ends in "ee" is refused
  // as "needs an edit" (it opens in the editor) and the one ending in "ff" asks for the secret-scan
  // confirmation. Every collection has two deleted records (one deleted by a commit nobody vouches for).
  const fakeHash = (seed: string, tail = '') => (createHash('sha1').update(seed).digest('hex') + createHash('sha1').update(seed + 'x').digest('hex')).slice(0, 40 - tail.length) + tail
  type MockVersion = { hash: string; minsAgo: number; verified: boolean; who: string; subject: string; change: string; changes: any[]; recordHash: string; restoredFrom?: string; renamedFrom?: string; unreadable?: boolean; approximate?: boolean }
  const restored = new Map<string, MockVersion[]>() // restores made in this session, newest first
  const firstHash = new Map<string, string>()
  const deleted = new Map<string, { id: string; data: Data; last: string; hash: string; minsAgo: number; verified: boolean }[]>()
  const textKeys = (c: Coll, d: Data) => Object.keys(d).filter((k) => typeof d[k] === 'string' && !(c.cfg.key ?? []).includes(k))
  const older = (v: unknown) => `${String(v)} (earlier)`
  const commitItem = (c: Coll, v: { hash: string; minsAgo: number; verified: boolean; who: string; subject: string; restoredFrom?: string }, id: string) => ({
    time: new Date(Date.now() - v.minsAgo * 60000).toISOString(), area: 'ledger', kind: 'commit', hash: v.hash, short: v.hash.slice(0, 7), subject: v.subject,
    identity: v.verified ? user.id : 'lap@example.com', name: v.who, via: 'rackbook (oidc)', verified: v.verified, records: [`${c.name}/${id}`], ...(v.restoredFrom ? { restoredFrom: v.restoredFrom } : {}),
  })
  function timeline(c: Coll, rec: Rec): MockVersion[] {
    const key = `${c.name}/${rec.id}`
    if (!firstHash.has(key)) firstHash.set(key, rec.hash)
    const [k1, k2] = textKeys(c, rec.data)
    const first = (rec.data && k1) || 'notes'
    const v1 = fakeHash(key + '1', 'ff')
    const list: MockVersion[] = [
      ...(restored.get(key) ?? []),
      {
        hash: fakeHash(key + '4'), minsAgo: 40, verified: false, who: 'Lap Top', subject: 'tidy up the notes', change: 'changed', recordHash: firstHash.get(key)!,
        changes: [
          { path: first, op: 'changed', old: older(rec.data[first]), new: rec.data[first] },
          { path: 'notes', op: 'removed', old: 'A long note that nobody needs any more. '.repeat(8) + '\nSecond line\nThird line\nFourth line', new: null },
        ],
      },
      {
        hash: fakeHash(key + '3'), minsAgo: 3 * 60, verified: true, who: user.name, subject: `ledger(${c.name}): restore ${rec.id}`, change: 'changed', restoredFrom: v1, recordHash: fakeHash(key + 'h3').slice(0, 16),
        changes: [
          { path: k2 ?? first, op: 'changed', old: 'something else', new: rec.data[k2 ?? first] ?? 'value' },
          { path: 'meta.owner', op: 'added', old: null, new: 'ann' },
        ],
      },
      {
        hash: fakeHash(key + '2', 'ee'), minsAgo: 26 * 60, verified: true, who: user.name, subject: `ledger(${c.name}): edit ${rec.id}`, change: 'changed', recordHash: fakeHash(key + 'h2').slice(0, 16),
        changes: [
          { path: 'ports[2].proto', op: 'changed', old: 'tcp', new: 'udp' },
          { path: 'ports[3]', op: 'added', old: null, new: { port: 443, proto: 'tcp' } },
          { path: 'meta.tags', op: 'removed', old: ['a', 'b'], new: null },
          { path: 'token', op: 'changed', old: '(hidden)', new: '(hidden)', hidden: true },
        ],
      },
      {
        hash: fakeHash(key + 'u'), minsAgo: 3 * 24 * 60, verified: false, who: 'Lap Top', subject: 'import the whole inventory', change: 'changed', unreadable: true, changes: [], recordHash: '',
      },
      {
        hash: v1, minsAgo: 5 * 24 * 60, verified: true, approximate: true, who: 'Mock Editor', subject: `ledger(${c.name}): add ${rec.id}`, change: 'created', recordHash: fakeHash(key + 'h1').slice(0, 16),
        changes: textKeys(c, rec.data).slice(0, 3).map((k) => ({ path: k, op: 'added', old: null, new: older(rec.data[k]) })),
      },
    ]
    return list
  }
  function deletedOf(c: Coll) {
    if (!deleted.has(c.name)) {
      const base = c.rows.slice(-2)
      deleted.set(c.name, base.map((row, i) => {
        const data = structuredClone(row)
        for (const k of c.cfg.key ?? []) if (typeof data[k] === 'string') data[k] = `${data[k]} (old)`
        return { id: idOf(c, data, 0), data, last: fakeHash(`${c.name}last${i}`), hash: fakeHash(`${c.name}del${i}`), minsAgo: (i + 1) * 90, verified: i === 0 }
      }))
    }
    return deleted.get(c.name)!
  }

  function meta(req: IncomingMessage) {
    return {
      locale: matchLocale(req.headers['accept-language']),
      defaultLocale: cfg.i18n?.default ?? 'zh-CN',
      title: cfg.title,
      description: cfg.description ?? '',
      ...(tagsOnly(cfg.i18n) ? { i18n: pickKeys(tagsOnly(cfg.i18n), 'title', 'description') } : {}),
      readOnly,
      writeMode: cfg.write?.mode ?? 'push',
      user: { ...user, ...(userLocale ? { locale: userLocale } : {}) },
      ...(alert ? { alert } : {}),
      ...(auditProblem ? { auditAlert: { problems: 1, firstSeq: 41 } } : {}),
      modules,
      collections: [...colls.values()].map((c) => ({
        expiryField: expiryFields[c.name]?.expiryField ?? '',
        revokedField: expiryFields[c.name]?.revokedField ?? '',
        name: c.name,
        title: c.cfg.title ?? c.name,
        description: c.cfg.description ?? '',
        group: c.cfg.group ?? '',
        ...(tagsOnly(c.cfg.i18n) ? { i18n: pickKeys(tagsOnly(c.cfg.i18n), 'title', 'description', 'group') } : {}),
        key: c.cfg.key ?? [],
        label: c.cfg.label ?? '',
        list: c.cfg.list ?? [],
        facets: (c.cfg.facets ?? []).map(normFacet),
        schema: c.schema,
        refs: refRules.filter((r) => r.collection === c.name).map((r) => ({ field: r.field, to: r.to, toField: r.toField, allow: r.allow, many: r.many })),
        backrefs: refRules
          .filter((r) => r.to === c.name)
          .map((r) => ({ collection: r.collection, field: r.field, ...(r.title ? { title: r.title } : {}), ...(pickKeys(r.i18n, 'backref_title') ? { i18n: backrefI18n(r.i18n) } : {}) })),
        notes: (cfg.notes ?? [])
          .filter((n: any) => n.collection === c.name)
          .map((n: any) => ({ title: n.title, ...(tagsOnly(n.i18n) ? { i18n: pickKeys(tagsOnly(n.i18n), 'title') } : {}), text: String(dig(load(n.file), n.path) ?? '').trim() })),
        count: c.rows.length,
      })),
    }
  }

  const send = (res: ServerResponse, status: number, body: unknown) => {
    res.statusCode = status
    res.setHeader('Content-Type', 'application/json; charset=utf-8')
    res.end(JSON.stringify(body))
  }
  const readBody = (req: IncomingMessage) =>
    new Promise<any>((resolve) => {
      let s = ''
      req.on('data', (d) => (s += d))
      req.on('end', () => resolve(s ? JSON.parse(s) : {}))
    })

  const commit = (c: Coll, action: string, id: string) => {
    const hash = createHash('sha1').update(`${Date.now()}${Math.random()}`).digest('hex').slice(0, 7)
    history.unshift({ hash, author: user.name, email: user.email, date: new Date().toISOString(), subject: `ledger(${c.name}): ${action} ${id}`, collection: c.name })
    return hash
  }

  /** Apply `mutate` to a copy of the rows, validate, keep it only when nothing new breaks. */
  function tryWrite(c: Coll, mutate: (rows: Data[]) => void): CheckErr[] {
    const before = c.rows
    c.rows = structuredClone(before)
    mutate(c.rows)
    const introduced = check().filter((e) => !baseline.has(errKey(e)))
    if (introduced.length) c.rows = before
    return introduced
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const url = new URL(req.url ?? '/', 'http://x')
    const p = url.pathname
    const method = req.method ?? 'GET'
    if (p === '/export.json') {
      send(res, 200, { title: cfg.title, collections: Object.fromEntries([...colls.values()].map((c) => [c.name, c.rows])), notes: [] })
      return true
    }
    if (p === '/auth/config') {
      return send(res, 200, { oidc: true, provider: 'microsoft', passkeys: true, locale: matchLocale(req.headers['accept-language']), defaultLocale: cfg.i18n?.default ?? 'zh-CN' }), true
    }
    if (p === '/auth/logout') return send(res, 200, { login: '/auth/login?error=logged_out' }), true
    if (!p.startsWith('/api/')) return false
    const parts = p.slice(5).split('/').filter(Boolean).map(decodeURIComponent)
    // decodeURIComponent above turns %2F inside an id into "/" after splitting, which is what the id is.
    const [head, cname, ...rest] = parts
    const rid = rest.length ? rest.join('/') : undefined
    if (head === 'meta' && method === 'GET') return send(res, 200, meta(req)), true
    if (head === 'account' && cname === 'preferences' && method === 'PUT') {
      const body = await readBody(req)
      const l = String(body.locale ?? '')
      if (l && !['zh-CN', 'zh-TW', 'en-US'].includes(l)) return send(res, 400, { error: 'invalid_locale', message: 'unsupported locale' }), true
      userLocale = l || undefined
      return send(res, 200, { locale: l }), true
    }
    if (login && head === 'account' && !cname && method === 'GET') {
      return send(res, 200, { id: user.id, name: user.name, email: user.email, role: user.role, authMethod: 'oidc', ...(userLocale ? { locale: userLocale } : {}), passkeysEnabled: true, canEnrol: true, enrolUntil: new Date(Date.now() + 600000).toISOString(), passkeys }), true
    }
    if (login && head === 'account' && cname === 'passkeys' && method === 'DELETE') {
      const i = passkeys.findIndex((k) => k.id === rest[0])
      if (i >= 0) passkeys.splice(i, 1)
      return send(res, 200, { ok: true }), true
    }
    if (login && head === 'admin' && cname === 'users' && method === 'GET') {
      return send(res, 200, {
        passkeysEnabled: true,
        users: [
          { id: user.id, name: user.name, method: 'oidc', role: 'admin', seen: true, lastSeen: new Date().toISOString(), passkeys },
          { id: 'ed@kazuha.org', name: 'Ed', method: 'passkey', role: 'editor', seen: true, lastSeen: new Date(Date.now() - 3600000).toISOString(), passkeys: [] },
          { id: 'former@example.com', role: 'none', seen: false, passkeys: [{ id: 'pk9', name: 'old phone', created: new Date(Date.now() - 40 * 86400000).toISOString() }] },
        ],
      }), true
    }
    if (head === 'admin' && cname === 'accept-remote' && method === 'POST') {
      const body = await readBody(req)
      if (!alert || body.commit !== alert.remote) return send(res, 409, { error: 'not_remote_tip', message: 'not the remote tip' }), true
      alert = undefined
      return send(res, 200, { ok: true }), true
    }
    if (head === 'infra' && method === 'POST' && user.canInfra) {
      const body = await readBody(req)
      const preview = body.preview === true
      if (cname === 'hosts' && rest[1] === 'secrets' && rest[2] === 'reveal') return send(res, 200, { key: body.key, value: 'mock-secret-value' }), true
      const path = cname === 'groups' ? 'inventory/hosts.yml' : 'inventory/host_vars/alpha-host.yml'
      return send(res, 200, {
        ...(preview ? {} : { commit: infraHead }),
        blocked: false,
        diffs: [{ path, status: 'modified', diff: '--- a/' + path + '\n+++ b/' + path + '\n@@ -1,3 +1,3 @@\n tailscale_ip: 100.64.0.1\n-features: {}\n+features:\n+  beszel-agent: {}\n' }],
        issues: [{ code: 'inventory.no_secrets', severity: 'warning', file: 'secrets/gamma-host.sops.yaml', params: { host: 'gamma-host' }, message: 'managed host gamma-host has no secrets file' }],
      }), true
    }
    if (head === 'infra' && method === 'GET' && user.canInfra) {
      const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString()
      const hub = { state: 'ok', ageSeconds: 12, time: ago(12) }
      const repo = { branch: 'main', head: infraHead, syncedAt: ago(40) }
      const report = (applied: string, result: string, message: string) => ({
        appliedCommit: applied, result, message, time: ago(300), receivedAt: ago(299),
        features: [{ name: 'beszel-agent', result: 'ok' }],
      })
      const hosts = [
        { name: 'alpha-host', groups: ['hub', 'managed'], hasVars: true, features: ['beszel-agent'], report: report(infraHead, 'ok', 'applied'), behind: false },
        { name: 'beta-host', groups: ['managed'], hasVars: true, features: [], report: report('0123456789abcdef0123456789abcdef01234567', 'failed', 'feature beszel-agent failed'), behind: true },
        { name: 'gamma-host', groups: [], hasVars: false, features: [], behind: false },
      ]
      if (cname === 'hosts' && rest[1] === 'vars') return send(res, 200, { path: 'inventory/host_vars/' + rest[0] + '.yml', exists: true, base: 'a'.repeat(40), hidden: 0, content: 'tailscale_ip: 100.64.0.1\nfeatures: {}\n' }), true
      if (cname === 'hosts' && rest[1] === 'secrets') {
        const pub = 'age1nat457r4f36vu5h6v48g4t4g39lua8md7er754fzvnxxrmhdh6mzpwl58u'
        return send(res, 200, {
          enabled: true, canWrite: true, publicKey: pub,
          file: {
            host: rest[0], path: 'secrets/' + rest[0] + '.sops.yaml', exists: true, base: 'c'.repeat(40),
            keys: [{ name: 'cloudflare_dns_token', editable: true }, { name: 'feature_beszel-agent_token', editable: true }, { name: 'Legacy_Key', editable: false }],
            recipients: [pub, 'age1uyhyewqasw0dgv8zalj57qd3jq3r5s5dlzd5wnvquzrazsk2k5ms3qpjck'], rule: [pub, 'age1cpazu35npqzx56ky54mwlsq2xqc8z4fl9httz6cwtk9vkuqsga6dagg0zd'], canDecrypt: true, lastModified: ago(3600),
          },
        }), true
      }
      if (cname === 'hosts' && rest[0] === undefined) return send(res, 200, { repo, hub, hosts }), true
      if (cname === 'hosts') {
        const h = hosts.find((x) => x.name === rest[0])
        if (!h) return send(res, 404, { error: 'not_found', message: 'no such host' }), true
        return send(res, 200, {
          repo, hub, behind: h.behind, ...(h.report ? { report: h.report } : {}),
          host: {
            name: h.name, groups: h.groups, hasVars: h.hasVars,
            vars: h.hasVars ? 'tailscale_ip: 100.64.0.1\nfeatures:\n  beszel-agent:\n    mode: websocket\n    token: (hidden)\n' : undefined,
            hidden: h.hasVars ? 1 : 0,
            features: h.features.map((n) => ({ name: n, enabled: true })).concat([{ name: 'old-feature', enabled: false }]),
          },
        }), true
      }
      if (cname === 'certs') return send(res, 200, { hub, certs: [
        { name: 'alpha.example.org', owner: 'alpha-host', notAfter: ago(-86400 * 60), failing: false },
        { name: 'beta.example.org', owner: 'beta-host', notAfter: ago(-86400 * 3), failing: true, lastError: 'DNS challenge failed' },
      ] }), true
      if (cname === 'iplists') return send(res, 200, { hub, lists: [
        { name: 'cloudflare', version: 'v42', entries: 22, warnings: [] },
        { name: 'office', version: 'v7', entries: 3, warnings: ['the list shrank by 40%'] },
      ] }), true
      if (cname === 'write') return send(res, 200, { enabled: true, secrets: true, fresh: true, maxAgeSeconds: 43200, signedInAt: ago(600) }), true
      if (cname === 'features') return send(res, 200, { invalid: [], features: [{ name: 'beszel-agent', description: 'Monitoring agent', settings: [
        { name: 'mode', type: 'enum', enum: ['websocket', 'listen'], default: 'websocket', description: 'How the agent connects' },
        { name: 'hub_url', type: 'string', description: 'Address of the hub', required: true },
        { name: 'port', type: 'int', min: 1, max: 65535 },
        { name: 'docker_stats', type: 'bool', default: false },
        { name: 'token', type: 'string', secret: true },
      ] }] }), true
      if (cname === 'groups') return send(res, 200, { base: 'b'.repeat(40), membership: { groups: ['hub', 'managed'], hosts: ['alpha-host', 'beta-host'], direct: { 'alpha-host': ['hub', 'managed'], 'beta-host': ['managed'] } } }), true
      if (cname === 'hosts' && rest[1] === 'vars') return send(res, 200, { path: 'inventory/host_vars/' + rest[0] + '.yml', exists: true, base: 'a'.repeat(40), hidden: 0, content: 'tailscale_ip: 100.64.0.1\nfeatures: {}\n' }), true
      if (cname === 'commits') return send(res, 200, { repo, canRevert: true, commits: [
        { hash: infraHead, author: 'Mock Editor', time: ago(3600), subject: 'infra(host_vars/alpha-host): enable beszel-agent', files: ['inventory/host_vars/alpha-host.yml'], revertible: true },
        { hash: '0123456789abcdef0123456789abcdef01234567', author: 'Mock Editor', time: ago(86400 * 2), subject: 'certs: add beta.example.org', files: ['roles/hub/files/certs.yml'], revertible: false, reason: 'not_editable' },
      ] }), true
    }
    if (head === 'expiring' && method === 'GET') {
      const days = Number(url.searchParams.get('days') ?? 30)
      const only = url.searchParams.getAll('collection')
      const withUnknown = url.searchParams.get('unknown') === 'true'
      const today = new Date().toISOString().slice(0, 10)
      const dayNum = (d: string) => Math.round(Date.parse(d + 'T00:00:00Z') / 86400000)
      const items: any[] = []
      for (const c of colls.values()) {
        const f = expiryFields[c.name]
        if (!f || (only.length && !only.includes(c.name))) continue
        for (const r of records(c)) {
          if (r.data[f.revokedField]) continue
          const v = r.data[f.expiryField]
          if (v === undefined || v === '') continue
          const label = String(r.data[c.cfg.label] ?? r.id)
          const source = String(r.data.source ?? '')
          if (!/^\d{4}-\d{2}-\d{2}$/.test(String(v))) {
            if (withUnknown) items.push({ collection: c.name, id: r.id, label, expires: String(v), daysLeft: null, status: 'unknown', source })
            continue
          }
          const daysLeft = dayNum(String(v)) - dayNum(today)
          if (daysLeft > days) continue
          items.push({ collection: c.name, id: r.id, label, expires: String(v), daysLeft, status: daysLeft < 0 ? 'expired' : 'expiring', source })
        }
      }
      items.sort((a, b) => (a.daysLeft ?? Infinity) - (b.daysLeft ?? Infinity))
      return send(res, 200, { today, days, items }), true
    }
    if (head === 'check' && method === 'GET') {
      const errors = check()
      return send(res, 200, { ok: errors.length === 0, errors }), true
    }
    if (head === 'history' && method === 'GET') {
      const limit = Number(url.searchParams.get('limit') ?? 20)
      const col = url.searchParams.get('collection')
      const commits = history.filter((h) => !col || h.collection === col).slice(0, limit).map((h) => ({ hash: h.hash, author: h.author, email: h.email, date: h.date, subject: h.subject }))
      return send(res, 200, { commits }), true
    }
    if (head === 'audit' && cname === 'status' && method === 'GET') {
      const problems = auditProblem ? [{ kind: 'cut_from_end', seq: 41, file: 'audit-2026-11.jsonl', recordedAt: 44 }] : []
      return send(res, 200, { enabled: true, ok: !auditProblem, problems, lastSeq: 52 }), true
    }
    if (head === 'audit' && cname === 'ack' && method === 'POST') {
      auditProblem = false
      return send(res, 200, { enabled: true, ok: true, problems: [], lastSeq: 53 }), true
    }
    if (head === 'activity' && cname === 'commit' && method === 'GET') {
      const diff = '--- a/docs/ledger/todo.yml\n+++ b/docs/ledger/todo.yml\n@@ -1,3 +1,3 @@\n - item: 示例\n-  status: 待办\n+  status: 完成\n   notes: ""\n'
      return send(res, 200, {
        area: rest[0],
        hash: rest[1],
        files: [
          { status: 'M', path: 'docs/ledger/todo.yml', patch: diff },
          { status: 'A', path: 'secrets/alpha.sops.yaml', hidden: true },
          { status: 'M', path: 'docs/ledger/big.yml', patch: diff, truncated: true },
        ],
        moreFiles: true,
      }), true
    }
    if (head === 'activity' && method === 'GET') {
      const q = url.searchParams
      const ago = (m: number) => new Date(Date.now() - m * 60000).toISOString()
      const areas = q.getAll('area').flatMap((a) => a.split(','))
      let items: Record<string, unknown>[] = history.map((h, i) => ({
        time: h.date, area: 'ledger', kind: 'commit', hash: h.hash.padEnd(40, '0'), short: h.hash, subject: h.subject,
        identity: i === 3 ? 'mallory@example.com' : user.id, name: i === 3 ? 'Mallory' : user.name, verified: i !== 3, via: 'rackbook (oidc)',
        records: [`${h.collection}/${h.subject.split(' ').slice(2).join(' ')}`], ...(i === 1 ? { token: 'ci-bot' } : {}), collection: h.collection,
      }))
      items.push(
        { time: ago(2), area: 'audit', kind: 'login', seq: 51, identity: user.id, name: user.name, method: 'oidc', role: 'admin', addr: '203.0.113.0' },
        { time: ago(40), area: 'audit', kind: 'login_refused', seq: 50, identity: 'guest@example.com', reason: 'no_role', method: 'oidc' },
        { time: ago(26 * 60), area: 'audit', kind: 'chain_problem', seq: 44, code: 'cut_from_end', detail: ['seq=41'] },
        { time: ago(26 * 60 - 5), area: 'infra', kind: 'secret_revealed', seq: 45, identity: user.id, name: user.name, host: 'alpha-host' },
        { time: ago(30 * 60), area: 'infra', kind: 'commit', hash: 'e5f6a7b8'.padEnd(40, '1'), short: 'e5f6a7b', subject: 'infra(host_vars/alpha-host): enable beszel-agent', identity: user.id, name: user.name, verified: true },
        { time: ago(24 * 60), area: 'ledger', kind: 'commit', hash: 'c0ffee1'.padEnd(40, '2'), short: 'c0ffee1', subject: 'rackbook(auth): add passkey', identity: user.id, name: user.name, verified: true, state: 'only' },
      )
      const col = q.get('collection')
      const who = q.get('identity')
      items = items
        .filter((it) => (!areas.length || areas.includes(String(it.area))) && (!col || it.collection === col) && (!who || (it.identity === who && it.verified !== false)))
        .sort((a, b) => String(b.time).localeCompare(String(a.time)))
      const start = Number(q.get('cursor') || 0)
      const page = items.slice(start, start + 5)
      return send(res, 200, { items: page, areas: ['ledger', 'infra', 'audit'], audit: true, ...(start + 5 < items.length ? { cursor: String(start + 5) } : {}) }), true
    }
    if (head === 'c' && cname && parts.length >= 3) {
      const hc = colls.get(cname)
      const [, , a, b, d] = parts
      if (hc && method === 'GET' && a === 'deleted' && parts.length === 3) {
        const list = deletedOf(hc).map((x) => ({
          ...commitItem(hc, { hash: x.hash, minsAgo: x.minsAgo, verified: x.verified, who: x.verified ? user.name : 'Lap Top', subject: `ledger(${hc.name}): delete ${x.id}` }, x.id),
          id: x.id, last: x.last, deletedAt: new Date(Date.now() - x.minsAgo * 60000).toISOString(),
          summary: (hc.cfg.list ?? Object.keys(x.data)).slice(0, 3).filter((k: string) => x.data[k] !== undefined).map((k: string) => ({ field: k, value: String(x.data[k]) })),
        }))
        return send(res, 200, { records: list, complete: true, more: false, audit: true }), true
      }
      if (hc && method === 'GET' && b === 'history' && parts.length <= 5) {
        const rec = records(hc).find((r) => r.id === a)
        const gone = deletedOf(hc).find((x) => x.id === a)
        if (d === undefined) {
          if (!rec) return send(res, 200, { id: a, versions: [], audit: true }), true
          const all = timeline(hc, rec).map((v) => ({ ...commitItem(hc, v, rec.id), change: v.change, recordHash: v.recordHash, changes: v.changes, ...(v.unreadable ? { unreadable: true } : {}), ...(v.approximate ? { approximate: true } : {}) }))
          const start = Number(url.searchParams.get('cursor') || 0)
          const page = all.slice(start, start + 3)
          return send(res, 200, { id: rec.id, versions: page, audit: true, ...(start + 3 < all.length ? { cursor: String(start + 3) } : {}) }), true
        }
        if (gone && d === gone.last) {
          return send(res, 200, { id: gone.id, commit: commitItem(hc, { hash: gone.last, minsAgo: gone.minsAgo + 60, verified: true, who: user.name, subject: `ledger(${hc.name}): edit ${gone.id}` }, gone.id), recordHash: hashOf(gone.data), data: gone.data, hidden: 0, exists: false, current: false, changes: [] }), true
        }
        if (!rec) return send(res, 404, { error: 'not_found', message: 'no such version of this record' }), true
        const v = timeline(hc, rec).find((x) => x.hash === d)
        if (!v) return send(res, 404, { error: 'not_found', message: 'no such version of this record' }), true
        const [k1] = textKeys(hc, rec.data)
        const data = k1 ? { ...rec.data, [k1]: older(rec.data[k1]) } : { ...rec.data }
        return send(res, 200, {
          id: rec.id, commit: commitItem(hc, v, rec.id), recordHash: v.recordHash, data, hidden: 0, exists: true, current: v.recordHash === rec.hash,
          changes: k1 ? [{ path: k1, op: 'changed', old: rec.data[k1], new: older(rec.data[k1]) }, { path: 'meta.owner', op: 'removed', old: 'ann', new: null }] : [],
        }), true
      }
      if (hc && method === 'POST' && b === 'restore' && parts.length === 4) {
        if (readOnly || !user.canEdit) return send(res, 403, { error: 'read_only', message: 'read-only' }), true
        const body = await readBody(req)
        const rec = records(hc).find((r) => r.id === a)
        const key = `${hc.name}/${a}`
        const commitHash = String(body.commit ?? '')
        if (!rec) {
          const gone = deletedOf(hc).find((x) => x.id === a && x.last === commitHash)
          if (!gone) return send(res, 404, { error: 'not_found', message: 'the record did not exist in that commit' }), true
          if (body.hash) return send(res, 409, { error: 'conflict', message: 'record no longer exists', current: null }), true
          const errors = tryWrite(hc, (rows) => void rows.push(structuredClone(gone.data)))
          if (errors.length) return send(res, 409, { error: 'restore_needs_edit', message: 'that version no longer fits', data: gone.data, hidden: 0, hiddenPaths: [], commit: commitHash, errors }), true
          deleted.set(hc.name, deletedOf(hc).filter((x) => x !== gone))
          return send(res, 201, { id: gone.id, hash: hashOf(gone.data), data: gone.data, commit: commit(hc, 'restore', gone.id), restoredFrom: commitHash }), true
        }
        if (rec.hash !== body.hash) return send(res, 409, { error: 'conflict', message: 'record changed', current: rec }), true
        const [k1] = textKeys(hc, rec.data)
        const data = k1 ? { ...rec.data, [k1]: older(rec.data[k1]) } : { ...rec.data }
        if (commitHash.endsWith('ee'))
          return send(res, 409, { error: 'restore_needs_edit', message: 'that version no longer fits', data, hidden: 1, hiddenPaths: ['/token'], commit: commitHash, errors: k1 ? [{ collection: hc.name, id: rec.id, path: '/' + k1, rule: 'schema', message: 'no longer valid', keyword: 'format', params: {} }] : [] }), true
        if (commitHash.endsWith('ff') && !body.confirm_not_secret)
          return send(res, 422, { error: 'secret_suspected', message: 'looks like a secret', findings: [{ collection: hc.name, id: rec.id, path: '/' + (k1 ?? 'notes'), rule: 'secret-assignment', excerpt: 'pass…', tier: 'confirm' }] }), true
        const idx = hc.rows.indexOf(rec.data)
        const errors = tryWrite(hc, (rows) => void (rows[idx] = data))
        if (errors.length) return send(res, 422, { error: 'invalid', message: 'invalid record', errors }), true
        const sha = commit(hc, 'restore', rec.id)
        restored.set(key, [{ hash: fakeHash(key + sha), minsAgo: 0, verified: true, who: user.name, subject: `ledger(${hc.name}): restore ${rec.id}`, change: 'changed', restoredFrom: commitHash, recordHash: hashOf(data), changes: k1 ? [{ path: k1, op: 'changed', old: rec.data[k1], new: data[k1] }] : [] }, ...(restored.get(key) ?? [])])
        firstHash.set(key, fakeHash(key + 'old').slice(0, 16))
        return send(res, 200, { id: rec.id, hash: hashOf(data), data, commit: sha, restoredFrom: commitHash }), true
      }
    }
    if (head !== 'c') return send(res, 404, { error: 'not_found', message: 'no such endpoint' }), true
    const c = colls.get(cname)
    if (!c) return send(res, 404, { error: 'not_found', message: `unknown collection ${cname}` }), true

    if (method === 'GET' && rid === undefined) return send(res, 200, { records: records(c) }), true
    if (method === 'GET') {
      const rec = records(c).find((r) => r.id === rid)
      if (!rec) return send(res, 404, { error: 'not_found', message: 'record not found' }), true
      const backrefs: Record<string, Rec[]> = {}
      for (const br of refRules.filter((r) => r.to === c.name)) {
        const from = colls.get(br.collection)!
        backrefs[br.collection] = (backrefs[br.collection] ?? []).concat(
          records(from).filter((r) => {
            const v = r.data[br.field]
            const vs = br.many ? [].concat(v ?? []) : [v]
            return vs.some((x) => x === rec.data[br.toField] || br.allow.includes(String(x)))
          }),
        )
      }
      return send(res, 200, { ...rec, backrefs }), true
    }

    if (readOnly || !user.canEdit) return send(res, 403, { error: 'read_only', message: 'read-only' }), true
    if (alert) return send(res, 503, { error: 'history_rewritten', message: 'writes are paused', lastGood: alert.lastGood, remote: alert.remote }), true

    if (method === 'POST' && rid === undefined) {
      const { data } = await readBody(req)
      const id = idOf(c, data, c.rows.length)
      const dup = records(c).find((r) => r.id === id)
      if (dup && c.cfg.key?.length) return send(res, 409, { error: 'conflict', message: 'record exists', current: dup }), true
      const errors = tryWrite(c, (rows) => rows.push(data))
      if (errors.length) return send(res, 422, { error: 'invalid', message: 'invalid record', errors }), true
      const sha = commit(c, 'add', id)
      return send(res, 201, { id, hash: hashOf(data), data, commit: sha }), true
    }
    if (method === 'PUT' && rid !== undefined) {
      const { data, hash } = await readBody(req)
      const cur = records(c).find((r) => r.id === rid)
      if (!cur) return send(res, 409, { error: 'conflict', message: 'record was deleted', current: null }), true
      if (cur.hash !== hash) return send(res, 409, { error: 'conflict', message: 'record changed', current: cur }), true
      const idx = c.rows.indexOf(cur.data)
      const newId = idOf(c, data, idx)
      const clash = newId !== rid && records(c).find((r) => r.id === newId)
      if (clash) return send(res, 409, { error: 'conflict', message: 'record exists', current: clash }), true
      const errors = tryWrite(c, (rows) => void (rows[idx] = data))
      if (errors.length) return send(res, 422, { error: 'invalid', message: 'invalid record', errors }), true
      const sha = commit(c, 'edit', rid)
      return send(res, 200, { id: newId, hash: hashOf(data), data, commit: sha }), true
    }
    if (method === 'DELETE' && rid !== undefined) {
      const cur = records(c).find((r) => r.id === rid)
      if (!cur) return send(res, 409, { error: 'conflict', message: 'record was deleted', current: null }), true
      if (cur.hash !== url.searchParams.get('hash')) return send(res, 409, { error: 'conflict', message: 'record changed', current: cur }), true
      const idx = c.rows.indexOf(cur.data)
      const errors = tryWrite(c, (rows) => void rows.splice(idx, 1))
      if (errors.length) return send(res, 422, { error: 'invalid', message: 'invalid after delete', errors }), true
      return send(res, 200, { commit: commit(c, 'delete', rid) }), true
    }
    return send(res, 404, { error: 'not_found', message: 'no such endpoint' }), true
  }

  return {
    name: 'rackbook-mock-api',
    apply: 'serve',
    configureServer(server) {
      baseline = new Set(check().map(errKey))
      server.middlewares.use((req, res, next) => {
        handle(req, res).then(
          (done) => {
            if (!done) next()
          },
          (e) => send(res, 500, { error: 'internal', message: String(e) }),
        )
      })
    },
  }
}

/** A rule's own message and its translations in the params of its issues (as the server sends them). */
function ruleParams(params: Record<string, unknown>, message: string | undefined, i18n: Record<string, Record<string, string>> | undefined) {
  if (message) params.ruleMessage = message
  const tr = Object.fromEntries(Object.entries(i18n ?? {}).flatMap(([l, v]) => (v?.message ? [[l, v.message]] : [])))
  if (Object.keys(tr).length) params.ruleMessageI18n = tr
  return params
}
