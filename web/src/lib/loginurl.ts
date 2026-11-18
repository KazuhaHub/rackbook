/** Where to send the browser to log in again, coming back to the current page. */
export function loginUrl(opts: { error?: string; returnTo?: string } = {}): string {
  const p = new URLSearchParams()
  const ret = opts.returnTo ?? window.location.pathname + window.location.search
  if (ret && ret !== '/' && !ret.startsWith('/auth/')) p.set('return', ret)
  if (opts.error) p.set('error', opts.error)
  const q = p.toString()
  return '/auth/login' + (q ? '?' + q : '')
}

