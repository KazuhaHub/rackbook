import { t } from '@/i18n/zh-CN'
import type { Collection, JsonSchema, LedgerRecord, Meta } from './types'

export function schemaProps(col: Collection): [string, JsonSchema][] {
  return Object.entries(col.schema.properties ?? {})
}

export function fieldTitle(col: Collection, field: string): string {
  return col.schema.properties?.[field]?.title || field
}

/** Columns shown by default: `list` from the config, else every schema property. */
export function defaultColumns(col: Collection): string[] {
  const all = schemaProps(col).map(([k]) => k)
  return col.list && col.list.length ? col.list : all
}

/** Every column the table can offer: all schema properties plus any extra data keys. */
export function allColumns(col: Collection, records: LedgerRecord[] = []): string[] {
  const cols = schemaProps(col).map(([k]) => k)
  for (const r of records) for (const k of Object.keys(r.data)) if (!cols.includes(k)) cols.push(k)
  return cols
}

export function str(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (Array.isArray(v)) return v.map(str).join(', ')
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

export function recordLabel(col: Collection, rec: LedgerRecord): string {
  if (col.label && rec.data[col.label] !== undefined) return str(rec.data[col.label])
  if (col.key?.length) {
    const parts = col.key.map((k) => str(rec.data[k])).filter(Boolean)
    if (parts.length) return parts.join(' / ')
  }
  const first = schemaProps(col)[0]?.[0]
  return (first && str(rec.data[first])) || rec.id
}

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

export function canEdit(meta: Meta): boolean {
  if (meta.readOnly) return false
  return meta.user ? meta.user.canEdit : true
}

const IP = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-f:]{3,}(\/\d{1,3})?$/i
const PORT = /^(TCP|UDP)\s/i
const DOMAIN = /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/i
const HOSTNAME = /^[a-z0-9]+(-[a-z0-9]+){2,}$/
const RANGE = /^[\d.]+\s*[–-]\s*[\d.]+$/

/** IPs, CIDRs, ports, domains and host names read better in monospace. */
export function looksMono(v: string): boolean {
  if (v.length > 80) return false
  return IP.test(v) || PORT.test(v) || DOMAIN.test(v) || HOSTNAME.test(v) || RANGE.test(v)
}

export function relativeTime(iso: string, now = Date.now()): string {
  const ms = now - new Date(iso).getTime()
  if (Number.isNaN(ms)) return iso
  const m = Math.round(ms / 60000)
  if (m < 1) return t.time.justNow
  if (m < 60) return t.time.minutes(m)
  const h = Math.round(m / 60)
  if (h < 24) return t.time.hours(h)
  const d = Math.round(h / 24)
  if (d < 30) return t.time.days(d)
  return new Date(iso).toLocaleDateString('zh-CN')
}

/** JSON pointer (/a/b/0) -> path segments */
export function pointerToPath(p: string | undefined): string[] {
  if (!p) return []
  return p
    .split('/')
    .slice(1)
    .map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'))
}

/** True when some collection marks an expiry field. */
export function hasExpiry(meta: Meta): boolean {
  return meta.collections.some((c) => !!c.expiryField)
}

/** The module that maintains this record, when `source` names one allowed for the collection. */
export function moduleFor(meta: Meta, collection: string, source: unknown) {
  if (typeof source !== 'string' || source === '' || source === 'manual') return undefined
  return meta.modules?.find((m) => m.name === source && m.collection === collection)
}

/** 手动 for an empty or "manual" source, else the module name. */
export function sourceLabel(source: unknown): string {
  return typeof source === 'string' && source !== '' && source !== 'manual' ? source : t.expiring.sourceManual
}
