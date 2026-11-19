// Search and paging for the small tables on a detail page. Import-free so
// scripts/check-console-logic.mts can test it.

/** Rows whose text contains every whitespace-separated word of q (case-insensitive). */
export function filterRows<T>(rows: T[], textOf: (row: T) => string, q: string): T[] {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return rows
  return rows.filter((r) => {
    const text = textOf(r).toLowerCase()
    return words.every((w) => text.includes(w))
  })
}

/** Rows-per-page choices; 0 means all. */
export const PAGE_SIZES = [10, 25, 50, 0] as const
export const DEFAULT_PAGE_SIZE = 25

export function parsePageSize(raw: string | null | undefined): number {
  const n = Number(raw)
  return raw !== null && raw !== undefined && raw !== '' && (PAGE_SIZES as readonly number[]).includes(n) ? n : DEFAULT_PAGE_SIZE
}

export type Page<T> = {
  items: T[]
  /** current page, 1-based, clamped to the pages that exist */
  page: number
  pages: number
  total: number
  /** 1-based position of the first and last shown row; 0 when there are none */
  from: number
  to: number
}

export function paginate<T>(rows: T[], page: number, size: number): Page<T> {
  const total = rows.length
  const pages = size > 0 ? Math.max(1, Math.ceil(total / size)) : 1
  const p = Math.min(Math.max(1, Math.floor(page) || 1), pages)
  const start = size > 0 ? (p - 1) * size : 0
  const items = size > 0 ? rows.slice(start, start + size) : rows
  return { items, page: p, pages, total, from: total ? start + 1 : 0, to: total ? start + items.length : 0 }
}
