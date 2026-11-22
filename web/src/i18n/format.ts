// Dates, numbers and sorting in the current language. Formatters are cached per
// language; always call these at render time, never at module load.
import { locale } from './index.ts'

const dtCache = new Map<string, Intl.DateTimeFormat>()

function dateTime(opts: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  const key = locale + JSON.stringify(opts)
  let f = dtCache.get(key)
  if (!f) {
    f = new Intl.DateTimeFormat(locale, opts)
    dtCache.set(key, f)
  }
  return f
}

function parse(v: string | number | Date): Date | null {
  const d = v instanceof Date ? v : new Date(v)
  return Number.isNaN(d.getTime()) ? null : d
}

/** A date such as 2026/11/20 or 11/20/2026; the input as it is when it is not a date. */
export function formatDate(v: string | number | Date): string {
  const d = parse(v)
  return d ? dateTime({ year: 'numeric', month: '2-digit', day: '2-digit' }).format(d) : String(v)
}

/**
 * Date and time on a 24-hour clock, optionally in a time zone (an unknown
 * zone falls back to the browser's).
 */
export function formatDateTime(v: string | number | Date, timeZone?: string): string {
  const d = parse(v)
  if (!d) return String(v)
  const opts: Intl.DateTimeFormatOptions = {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }
  try {
    return dateTime(timeZone ? { ...opts, timeZone } : opts).format(d)
  } catch {
    return dateTime(opts).format(d)
  }
}

/** The time of day on a 24-hour clock, such as 14:05:09. */
export function formatTime(v: string | number | Date): string {
  const d = parse(v)
  return d ? dateTime({ hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).format(d) : String(v)
}

/** A day written out with its weekday, for a heading. */
export function formatDay(v: string | number | Date): string {
  const d = parse(v)
  return d ? dateTime({ year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' }).format(d) : String(v)
}

const numCache = new Map<string, Intl.NumberFormat>()

export function formatNumber(n: number, opts: Intl.NumberFormatOptions = {}): string {
  const key = locale + JSON.stringify(opts)
  let f = numCache.get(key)
  if (!f) {
    f = new Intl.NumberFormat(locale, opts)
    numCache.set(key, f)
  }
  return f.format(n)
}

const collators = new Map<string, Intl.Collator>()

/** A collator for the current language (numeric, case-insensitive), with English as the second. */
export function collator(): Intl.Collator {
  let c = collators.get(locale)
  if (!c) {
    c = new Intl.Collator([locale, 'en'], { numeric: true, sensitivity: 'base' })
    collators.set(locale, c)
  }
  return c
}

const plurals = new Map<string, Intl.PluralRules>()

/** The plural category of n in the current language (for en-US: one / other). */
export function plural(n: number): Intl.LDMLPluralRule {
  let p = plurals.get(locale)
  if (!p) {
    p = new Intl.PluralRules(locale)
    plurals.set(locale, p)
  }
  return p.select(n)
}
