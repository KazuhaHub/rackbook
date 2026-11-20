// The string formats the console validates itself. They mirror
// internal/validate/formats.go rule for rule, so the form and the server agree.
import { t } from '../i18n/index.ts'
import { isCountryCode } from './countries.ts'

const IPV4 = /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/

export function isIPv4(s: string): boolean {
  return IPV4.test(s) && s.split('.').every((p) => Number(p) <= 255)
}

export function isIPv6(s: string): boolean {
  if (!s.includes(':') || s.includes('%') || /[^0-9a-fA-F:.]/.test(s)) return false
  let head = s
  const dot = s.lastIndexOf(':')
  if (s.slice(dot + 1).includes('.')) {
    if (!isIPv4(s.slice(dot + 1))) return false
    head = s.slice(0, dot + 1) + '0:0' // the embedded IPv4 takes two groups
  }
  const parts = head.split('::')
  if (parts.length > 2) return false
  const groups = (p: string) => (p === '' ? [] : p.split(':'))
  const ok = (g: string[]) => g.every((x) => /^[0-9a-fA-F]{1,4}$/.test(x))
  if (parts.length === 1) {
    const g = groups(parts[0])
    return g.length === 8 && ok(g)
  }
  const a = groups(parts[0])
  const b = groups(parts[1])
  return ok(a) && ok(b) && a.length + b.length <= 7
}

export const isIP = (s: string) => isIPv4(s) || isIPv6(s)

export function isCIDR(s: string): boolean {
  const i = s.indexOf('/')
  if (i < 0 || s.indexOf('/', i + 1) >= 0) return false
  const addr = s.slice(0, i)
  const bits = s.slice(i + 1)
  if (!/^(?:0|[1-9][0-9]*)$/.test(bits)) return false
  if (isIPv4(addr)) return Number(bits) <= 32
  return isIPv6(addr) && Number(bits) <= 128
}

const PORT_SPEC = /^(?:TCP|UDP)(?:\/(?:TCP|UDP))? +[0-9]+(?:-[0-9]+)?(?:, *[0-9]+(?:-[0-9]+)?)*$/i

export function isPortSpec(s: string): boolean {
  if (!PORT_SPEC.test(s)) return false
  const ports = s.slice(s.indexOf(' ') + 1)
  return ports.split(',').every((part) => {
    const [lo, hi] = part.trim().split('-').map(Number)
    if (!(lo >= 1 && lo <= 65535)) return false
    return hi === undefined || (hi >= 1 && hi <= 65535 && hi >= lo)
  })
}

export function isDate(s: string): boolean {
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/.exec(s)
  if (!m) return false
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])]
  // Date.UTC maps years 0-99 to 1900-1999, so set the full year explicitly;
  // Go's time.Parse accepts years 0000-9999.
  const t = new Date(0)
  t.setUTCFullYear(y, mo - 1, d)
  return t.getUTCFullYear() === y && t.getUTCMonth() === mo - 1 && t.getUTCDate() === d
}

export function isHostname(s: string): boolean {
  if (s === '' || s.length > 253) return false
  return s.split('.').every((l) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(l))
}

// eslint-disable-next-line no-control-regex
const URI = /^[A-Za-z][A-Za-z0-9+.-]*:[^\t\n\f\r \x00-\x1f\x7f]+$/
export const isURI = (s: string) => URI.test(s)

/** An assigned ISO 3166-1 alpha-2 code in upper case, or the placeholder `tbd`. */
export const isCountry = (s: string) => s === 'tbd' || isCountryCode(s)

/** ISO 3166-2 shape XX-YYY (XX an assigned country code, YYY one to three upper-case letters or digits), or `tbd`. */
export function isSubdivision(s: string): boolean {
  if (s === 'tbd') return true
  const m = /^([A-Z]{2})-[A-Z0-9]{1,3}$/.exec(s)
  return !!m && isCountryCode(m[1])
}

/** customFormats for the form's Ajv. */
export const customFormats: Record<string, (s: string) => boolean> = {
  ip: isIP,
  ipv4: isIPv4,
  ipv6: isIPv6,
  cidr: isCIDR,
  'port-spec': isPortSpec,
  date: isDate,
  textarea: () => true,
  hostname: isHostname,
  uri: isURI,
  country: isCountry,
  subdivision: isSubdivision,
}

/** Shown under a field whose value fails a format (current language), undefined for an unknown format. */
export function formatHint(format: string): string | undefined {
  return t.validation.formats[format]
}
