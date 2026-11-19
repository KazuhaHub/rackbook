// Record ids as people read them. The id of a record is its key values joined
// with "/", where "/" and "%" inside a value are written %2F and %25 (see
// EscapeIDPart in internal/ledger). URLs and the API keep that form; anything
// shown on screen goes through displayId. Import-free so
// scripts/check-console-logic.mts can test it.

/** One key part with %2F -> "/" and %25 -> "%" (a single pass, so %252F becomes %2F). */
export function unescapeIdPart(part: string): string {
  return part.replace(/%(2F|25)/gi, (_, c: string) => (c === '25' ? '%' : '/'))
}

/** The key parts of an id, unescaped. */
export function idParts(id: string): string[] {
  return id.split('/').map(unescapeIdPart)
}

/** An id for display: the key parts, unescaped, joined with " / ". */
export function displayId(id: string): string {
  return idParts(id).join(' / ')
}
