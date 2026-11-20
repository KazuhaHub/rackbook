// Switching the language leaves no text of the old one on the page.
//
// For each page and each pair of languages (A -> B) this loads the page fresh
// in B, then loads it in A and switches to B the way the language menu does.
// Any message of A that B words differently, found as a whole text piece on
// either B page, is copy that did not follow the language: read before the
// switch (stale), or read while the modules loaded, before the boot picked the
// language (frozen in zh-CN). Pieces are whole text nodes and labels, so a
// message word inside the ledger's own data (a note title) does not count.
//
// Runs the console with the mock API (vite --mode mock) and a headless Chrome
// driven over the DevTools protocol. CHROME=<path> picks the browser
// (default google-chrome); PORT the dev server port (default 5199); CPU_THROTTLE
// slows the page down (e.g. 6) to check it does not depend on timing.
import { spawn, type ChildProcess } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import zhCN from '../src/i18n/zh-CN.ts'
import zhTW from '../src/i18n/zh-TW.ts'
import enUS from '../src/i18n/en-US.ts'

const root = path.resolve(import.meta.dirname, '..')
const PORT = Number(process.env.PORT ?? 5199)
const DEBUG_PORT = PORT + 1
const BASE = `http://127.0.0.1:${PORT}`
const messages: Record<string, unknown> = { 'zh-CN': zhCN, 'zh-TW': zhTW, 'en-US': enUS }
const pairs: [string, string][] = [
  ['zh-CN', 'en-US'],
  ['en-US', 'zh-TW'],
  ['zh-TW', 'zh-CN'],
  ['en-US', 'zh-CN'],
]

/** Every text message of a language (trimmed, two characters or more). */
function texts(m: unknown, out = new Set<string>()): Set<string> {
  if (typeof m === 'string') {
    if (m.trim().length >= 2) out.add(m.trim())
  } else if (m && typeof m === 'object') {
    for (const v of Object.values(m)) texts(v, out)
  }
  return out
}

/** The texts of a that are not a text of b anywhere (zh-CN and zh-TW share many words). */
function differing(a: unknown, b: unknown): Set<string> {
  const other = texts(b)
  return new Set([...texts(a)].filter((s) => !other.has(s)))
}

// Each child runs in its own process group, so cleanup also ends what it started.
const procs: ChildProcess[] = []
const cleanup = () => {
  for (const p of procs) {
    try {
      if (p.pid) process.kill(-p.pid, 'SIGTERM')
    } catch {
      // already gone
    }
  }
}
process.on('exit', cleanup)
for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => process.exit(130))

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function waitFor(url: string, tries = 100): Promise<Response> {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url)
      if (r.ok) return r
    } catch {
      // not up yet
    }
    await sleep(200)
  }
  throw new Error(`${url} did not come up`)
}

// --- the console with the mock API ---------------------------------------------
// A server already on the port would be tested instead of this checkout (and its mock state).
// The same for Chrome's debugging port (PORT + 1): another browser there would be driven instead.
const inUse = (url: string) =>
  fetch(url).then(
    () => true,
    () => false,
  )
for (const [port, url] of [[PORT, `${BASE}/`], [DEBUG_PORT, `http://127.0.0.1:${DEBUG_PORT}/json/version`]] as const) {
  if (await inUse(url)) {
    console.error(`port ${port} is in use; set PORT to a free one (the script uses PORT and PORT + 1)`)
    process.exit(2)
  }
}
const vite = spawn(path.join(root, 'node_modules', '.bin', 'vite'), ['--mode', 'mock', '--host', '127.0.0.1', '--port', String(PORT), '--strictPort'], {
  cwd: root,
  env: { ...process.env, MOCK_LOGIN: '1' },
  stdio: 'ignore',
  detached: true,
})
procs.push(vite)
await waitFor(`${BASE}/api/meta`)

// --- headless Chrome --------------------------------------------------------------
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'rb-i18n-'))
const chrome = spawn(
  process.env.CHROME ?? 'google-chrome',
  ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', `--remote-debugging-port=${DEBUG_PORT}`, `--user-data-dir=${profile}`, 'about:blank'],
  { stdio: 'ignore', detached: true },
)
procs.push(chrome)
process.on('exit', () => {
  try {
    // Chrome may still be writing its profile as it exits
    fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
  } catch {
    // a temporary directory: the system cleans it up
  }
})
const targets = (await (await waitFor(`http://127.0.0.1:${DEBUG_PORT}/json/list`)).json()) as { type: string; webSocketDebuggerUrl: string }[]
const page = targets.find((x) => x.type === 'page')
if (!page) throw new Error('no page target')

const ws = new WebSocket(page.webSocketDebuggerUrl)
await new Promise((r, j) => {
  ws.onopen = r
  ws.onerror = j
})
let nextId = 0
const pending = new Map<number, (v: any) => void>()
ws.onmessage = (ev) => {
  const msg = JSON.parse(String(ev.data))
  if (msg.id !== undefined) pending.get(msg.id)?.(msg)
}
function cdp(method: string, params: Record<string, unknown> = {}): Promise<any> {
  const id = ++nextId
  ws.send(JSON.stringify({ id, method, params }))
  return new Promise((resolve, reject) =>
    pending.set(id, (m) => (m.error ? reject(new Error(`${method}: ${m.error.message}`)) : resolve(m.result))),
  )
}
async function evaluate<T>(expression: string): Promise<T> {
  const r = await cdp('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
  if (r.exceptionDetails) throw new Error(`${expression}: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`)
  return r.result.value as T
}
await cdp('Page.enable')
await cdp('Runtime.enable')
// CPU_THROTTLE=6 slows the page down like a busy CI runner, to shake out timing assumptions
if (process.env.CPU_THROTTLE) await cdp('Emulation.setCPUThrottlingRate', { rate: Number(process.env.CPU_THROTTLE) })

/** Waits until the page has stopped changing (lazy chunks, queries). */
async function settle() {
  let last = ''
  for (let i = 0; i < 40; i++) {
    await sleep(250)
    const now = await evaluate<string>('(document.body ? document.body.innerText.length : -1) + ":" + document.querySelectorAll("*").length')
    if (now === last && !now.startsWith("-1")) return
    last = now
  }
}

/**
 * The page's text pieces: every text node, the title and the labels a screen
 * reader reads, each trimmed. Messages are compared with whole pieces, so a
 * message word inside the ledger's own data (a note title) does not count.
 */
const TEXT = `(() => {
  const out = [document.title]
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
  for (let n = w.nextNode(); n; n = w.nextNode()) out.push(n.nodeValue)
  for (const el of document.querySelectorAll('[title],[aria-label],[placeholder],[alt]'))
    for (const a of ['title', 'aria-label', 'placeholder', 'alt']) { const v = el.getAttribute(a); if (v) out.push(v) }
  return out.map((s) => s.trim()).filter(Boolean)
})()`

/**
 * Waits until the page has applied what the server says about the language
 * (saved preference, Accept-Language): a switch made before that could be
 * undone by it, and a text sample taken before it would be in another language.
 */
async function synced() {
  for (let i = 0; i < 100; i++) {
    if (await evaluate<boolean>('window.__rbLocaleSynced === true && typeof window.__rbChooseLocale === "function"')) return
    await sleep(100)
  }
  throw new Error('the page never synced its language')
}

async function open(url: string, lang: string) {
  await cdp('Page.navigate', { url: `${BASE}/` })
  await settle()
  // the browser's choice and the signed-in person's saved preference (which wins)
  await evaluate(`localStorage.setItem('rackbook.locale', ${JSON.stringify(lang)})`)
  await evaluate(
    `fetch('/api/account/preferences', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ locale: ${JSON.stringify(lang)} }) }).then((r) => r.status)`,
  )
  await cdp('Page.navigate', { url })
  await settle()
  await synced()
  await settle()
}

// --- the pages -----------------------------------------------------------------------
const meta = (await (await fetch(`${BASE}/api/meta`)).json()) as { collections: { name: string }[]; modules?: { name: string }[] }
const first = meta.collections[0]?.name
const rec = first ? ((await (await fetch(`${BASE}/api/c/${first}`)).json()) as { records: { id: string }[] }).records[0] : undefined
const pages = [
  '/',
  ...(first ? [`/c/${first}`, `/c/${first}/-/new`] : []),
  ...(first && rec ? [`/c/${first}/${encodeURIComponent(rec.id)}`, `/c/${first}/${encodeURIComponent(rec.id)}/edit`] : []),
  '/check',
  '/expiring',
  '/account',
  '/admin/users',
  '/admin/tokens',
  '/admin/grants',
  '/types',
  '/types/-/new',
  ...(first ? [`/types/${first}`] : []),
  '/modules',
  ...(meta.modules?.[0] ? [`/modules/${meta.modules[0].name}`] : []),
  '/auth/login',
  '/auth/login?error=expired',
]

// Text that comes from the ledger itself (schema titles, record values, notes) is
// content, shown as written: collect it from the API and leave it out.
const data = new Set<string>()
const collect = (v: unknown) => {
  if (typeof v === 'string') data.add(v.trim())
  else if (v && typeof v === 'object') Object.values(v).forEach(collect)
}
collect(meta)
for (const c of meta.collections) collect(await (await fetch(`${BASE}/api/c/${c.name}`)).json())
for (const extra of ['/api/expiring', '/api/check']) collect(await (await fetch(BASE + extra)).json())

let failures = 0
for (const [a, b] of pairs) {
  const old = new Set([...differing(messages[a], messages[b])].filter((s) => !data.has(s)))
  for (const p of pages) {
    const url = BASE + p
    await open(url, b)
    const fresh = new Set(await evaluate<string[]>(TEXT))
    await open(url, a)
    await evaluate(`window.__rbChooseLocale(${JSON.stringify(b)})`)
    await settle()
    const switched = new Set(await evaluate<string[]>(TEXT))
    const lang = await evaluate<string>('document.documentElement.lang')
    if (lang !== b) {
      console.log(`${a} -> ${b} ${p}: <html lang> is ${lang}`)
      failures++
    }
    for (const s of old) {
      if (fresh.has(s)) console.log(`${b} ${p}: ${JSON.stringify(s)} (${a}) on a fresh load`)
      else if (switched.has(s)) console.log(`${a} -> ${b} ${p}: stale ${JSON.stringify(s)}`)
      else continue
      failures++
    }
  }
}
console.log(`${pages.length} pages x ${pairs.length} switches, failures ${failures}`)
ws.close()
cleanup()
process.exit(failures ? 1 : 0)
