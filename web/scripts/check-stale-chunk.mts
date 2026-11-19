import { isChunkLoadError, reloadOnce, RELOAD_KEY, RELOAD_WINDOW_MS } from '../src/lib/staleChunk.ts'

let failed = 0
function expect(name: string, ok: boolean) {
  if (!ok) {
    console.error('FAIL', name)
    failed++
  }
}

for (const m of [
  'Failed to fetch dynamically imported module: https://rackbook.example/assets/Tokens-Oxym_gca.js',
  'error loading dynamically imported module: https://x/assets/a.js',
  'Importing a module script failed.',
  'Unable to preload CSS for /assets/index-abc.css',
]) expect(`chunk error: ${m}`, isChunkLoadError(new Error(m)))
for (const m of ['Cannot read properties of undefined', 'Failed to fetch']) expect(`not a chunk error: ${m}`, !isChunkLoadError(new Error(m)))
expect('non-error value', !isChunkLoadError(undefined))

function mem(): Storage {
  const m = new Map<string, string>()
  return { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v) } as Storage
}

let reloads = 0
const reload = () => void reloads++
const s = mem()
expect('first failure reloads', reloadOnce(s, reload, 1_000_000) && reloads === 1 && s.getItem(RELOAD_KEY) === '1000000')
expect('failure right after the reload shows the error', !reloadOnce(s, reload, 1_000_000 + 2_000) && reloads === 1)
expect('a later release reloads again', reloadOnce(s, reload, 1_000_000 + RELOAD_WINDOW_MS) && reloads === 2)
expect('no storage: no reload', !reloadOnce(null, reload, 5) && reloads === 2)
const throwing = { getItem: () => { throw new Error('blocked') }, setItem: () => {} } as unknown as Storage
expect('blocked storage: no reload', !reloadOnce(throwing, reload, 5) && reloads === 2)

if (failed) process.exit(1)
console.log('stale chunk: ok')
