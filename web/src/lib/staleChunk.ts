// After a release, a tab opened on the old build still asks for the old
// hashed chunks, which are gone (404). One full reload fetches the new
// index.html and its new chunk names. The timestamp in sessionStorage stops a
// reload loop: if a reload already happened in the last RELOAD_WINDOW_MS and
// loading still fails, the error page is shown instead.

export const RELOAD_KEY = 'rackbook:stale-chunk-reload'
export const RELOAD_WINDOW_MS = 10_000

/** True for the errors browsers and Vite raise when a code-split chunk cannot be loaded. */
export function isChunkLoadError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : typeof err === 'string' ? err : ''
  return /Failed to fetch dynamically imported module|error loading dynamically imported module|Importing a module script failed|Unable to preload CSS/i.test(msg)
}

type Store = Pick<Storage, 'getItem' | 'setItem'>

/**
 * Reloads the page unless it was already reloaded for this reason within the
 * last RELOAD_WINDOW_MS. Returns true when a reload was started.
 */
export function reloadOnce(store: Store | null, reload: () => void, now = Date.now()): boolean {
  try {
    const last = Number(store?.getItem(RELOAD_KEY) ?? 0)
    if (last && now - last >= 0 && now - last < RELOAD_WINDOW_MS) return false
    store?.setItem(RELOAD_KEY, String(now))
  } catch {
    // Storage blocked: without a guard a reload could loop, so don't reload.
    return false
  }
  if (!store) return false
  reload()
  return true
}

function session(): Store | null {
  try {
    return window.sessionStorage
  } catch {
    return null
  }
}

/** reloadOnce with the real sessionStorage and location.reload. */
export function reloadForStaleChunk(): boolean {
  return reloadOnce(session(), () => window.location.reload())
}

/**
 * Wraps a lazy-route import: a chunk that no longer exists triggers one reload
 * (and a promise that never settles, so nothing renders meanwhile); otherwise
 * the error is rethrown for the error page.
 */
export function retryImport<T>(load: () => Promise<T>): () => Promise<T> {
  return () =>
    load().catch((err: unknown) => {
      if (isChunkLoadError(err) && reloadForStaleChunk()) return new Promise<T>(() => {})
      throw err
    })
}
