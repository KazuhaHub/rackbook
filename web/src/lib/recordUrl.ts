// Record URLs. An id is the key values joined with "/", where "/" and "%"
// inside a value are written %2F and %25 (see EscapeIDPart in internal/ledger).
// The URL segment is that id passed through encodeURIComponent, so a "/" in a
// key shows up as %252F. Keep both helpers here, free of imports, so
// scripts/check-record-urls.mts can test them.

/**
 * The record id from the URL. React Router decodes params and re-encodes "/", which
 * corrupts ids that contain %2F or %25, so decode the raw path segment exactly once.
 */
export function idFromPath(pathname: string): string | undefined {
  const seg = pathname.split('/')[3]
  if (seg === undefined || seg === '') return undefined
  try {
    return decodeURIComponent(seg)
  } catch {
    return seg
  }
}

export const recordHref = (collection: string, id: string) =>
  `/c/${encodeURIComponent(collection)}/${encodeURIComponent(id)}`
