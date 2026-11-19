import { useState } from 'react'
import { DEFAULT_PAGE_SIZE, parsePageSize } from '@/lib/tableView'

/** Rows per page for one collection's tables, remembered in localStorage (which may be unavailable). */
export function usePageSize(collection: string): [number, (n: number) => void] {
  const key = `rackbook.pageSize.${collection}`
  const [size, setSize] = useState(() => {
    try {
      return parsePageSize(localStorage.getItem(key))
    } catch {
      return DEFAULT_PAGE_SIZE
    }
  })
  return [
    size,
    (n) => {
      setSize(n)
      try {
        localStorage.setItem(key, String(n))
      } catch {
        // private mode or storage disabled: the choice lasts for this visit only
      }
    },
  ]
}
