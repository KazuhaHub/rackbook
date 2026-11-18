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

type Data = Record<string, any>
type Rec = { id: string; hash: string; data: Data }
type CheckErr = { collection: string; id: string; path: string; rule: string; message: string }
type RefRule = { collection: string; field: string; to: string; toField: string; allow: string[]; many: boolean }
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
const hashOf = (d: Data) => createHash('sha256').update(JSON.stringify(canon(d))).digest('hex').slice(0, 16)
const dig = (o: any, p: string) => (p ? p.split('.').reduce((a, k) => a?.[k], o) : o)

export function mockApi(root: string): Plugin {
  const readOnly = process.env.MOCK_READONLY === '1'
  const cfg = parse(readFileSync(path.join(root, 'rackbook.yml'), 'utf8'))
  const ajv = new Ajv2020({ strict: false, allErrors: true })
  ajv.addFormat('textarea', true)

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
      return { collection: fc, field: ff, to: tc, toField: tf, allow: r.ref.allow ?? [], many: !!r.ref.many }
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
          for (const e of c.validateFn.errors ?? []) {
            const p =
              e.keyword === 'additionalProperties'
                ? `${e.instancePath}/${e.params.additionalProperty}`
                : e.keyword === 'required'
                  ? `${e.instancePath}/${e.params.missingProperty}`
                  : e.instancePath
            errs.push({ collection: c.name, id: r.id, path: p, rule: 'schema', message: e.message ?? 'invalid' })
          }
        }
        if (c.cfg.key?.length) {
          if (seen.has(r.id)) errs.push({ collection: c.name, id: r.id, path: '', rule: 'unique', message: `duplicate key ${r.id}` })
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
            errs.push({ collection: rr.collection, id: r.id, path: `/${rr.field}`, rule: 'ref', message: `unknown ${rr.to}.${rr.toField} "${v}"` })
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
    ['addresses', 'edit gw-example-springfield-or-us-home/Tailscale', 50],
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
    ? { id: 'viewer@example.com', email: 'viewer@example.com', name: 'viewer', role: 'viewer', authMethod: 'none', canEdit: false, canAdmin: false }
    : { id: 'editor@example.com', email: 'editor@example.com', name: 'Mock Editor', role: 'admin', authMethod: login ? 'oidc' : 'none', canEdit: true, canAdmin: true }
  // MOCK_ALERT=1 shows the "history rewritten" banner until it is accepted.
  let alert: { kind: string; lastGood: string; remote: string } | undefined =
    process.env.MOCK_ALERT === '1'
      ? { kind: 'history_rewritten', lastGood: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678', remote: '9f8e7d6c5b4a39281706f5e4d3c2b1a098765432' }
      : undefined

  function meta() {
    return {
      title: cfg.title,
      description: cfg.description ?? '',
      readOnly,
      writeMode: cfg.write?.mode ?? 'push',
      user,
      ...(alert ? { alert } : {}),
      collections: [...colls.values()].map((c) => ({
        name: c.name,
        title: c.cfg.title ?? c.name,
        description: c.cfg.description ?? '',
        group: c.cfg.group ?? '',
        key: c.cfg.key ?? [],
        label: c.cfg.label ?? '',
        list: c.cfg.list ?? [],
        facets: (c.cfg.facets ?? []).map(normFacet),
        schema: c.schema,
        refs: refRules.filter((r) => r.collection === c.name).map((r) => ({ field: r.field, to: r.to, toField: r.toField, allow: r.allow, many: r.many })),
        backrefs: refRules.filter((r) => r.to === c.name).map((r) => ({ collection: r.collection, field: r.field })),
        notes: (cfg.notes ?? [])
          .filter((n: any) => n.collection === c.name)
          .map((n: any) => ({ title: n.title, text: String(dig(load(n.file), n.path) ?? '').trim() })),
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
    if (p === '/auth/config') return send(res, 200, { oidc: true, provider: 'microsoft', passkeys: true }), true
    if (p === '/auth/logout') return send(res, 200, { login: '/auth/login?error=logged_out' }), true
    if (!p.startsWith('/api/')) return false
    const parts = p.slice(5).split('/').filter(Boolean).map(decodeURIComponent)
    // decodeURIComponent above turns %2F inside an id into "/" after splitting, which is what the id is.
    const [head, cname, ...rest] = parts
    const rid = rest.length ? rest.join('/') : undefined
    if (head === 'meta' && method === 'GET') return send(res, 200, meta()), true
    if (login && head === 'account' && !cname && method === 'GET') {
      return send(res, 200, { id: user.id, name: user.name, email: user.email, role: user.role, authMethod: 'oidc', passkeysEnabled: true, canEnrol: true, enrolUntil: new Date(Date.now() + 600000).toISOString(), passkeys }), true
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
