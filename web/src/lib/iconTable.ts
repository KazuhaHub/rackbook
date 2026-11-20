import { useCallback, useEffect, useSyncExternalStore, type ComponentType } from 'react'

export type IconComponent = ComponentType<{ className?: string; 'aria-hidden'?: boolean }>

// lucide's table of icon loaders (name -> () => import(that icon)). Each icon is its own small
// chunk, so a page downloads only the icons it shows; the table itself is one chunk, loaded when
// the first icon is needed.
type Loaders = Record<string, () => Promise<{ default: IconComponent }>>

/** The loader of an icon name, or undefined for anything the table does not list (own keys only: no "constructor", no non-icon export). */
export function iconLoader(table: Loaders | null, name: string | undefined): (() => Promise<{ default: IconComponent }>) | undefined {
  return table && name && Object.prototype.hasOwnProperty.call(table, name) ? table[name] : undefined
}

type Status = 'idle' | 'loading' | 'ready' | 'failed'
let table: Loaders | null = null
let status: Status = 'idle'
const icons = new Map<string, IconComponent | 'loading' | 'failed'>()
let version = 0
const listeners = new Set<() => void>()
const bump = () => {
  version++
  for (const fn of listeners) fn()
}
const subscribe = (fn: () => void) => {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

function loadTable() {
  if (status === 'loading' || status === 'ready') return
  status = 'loading'
  bump()
  import('lucide-react/dynamicIconImports').then(
    (m) => {
      table = m.default as unknown as Loaders
      status = 'ready'
      bump()
    },
    () => {
      status = 'failed' // retry() tries again
      bump()
    },
  )
}

function loadIcon(name: string) {
  if (icons.has(name)) return
  const load = iconLoader(table, name)
  if (!load) return
  icons.set(name, 'loading')
  load().then(
    (m) => {
      icons.set(name, m.default)
      bump()
    },
    () => {
      icons.set(name, 'failed')
      bump()
    },
  )
}

/** The icon component for a lucide name; undefined while it loads, for an unknown name and after a failed load (no icon is shown). */
export function useIcon(name: string | undefined): IconComponent | undefined {
  useSyncExternalStore(subscribe, () => version)
  useEffect(() => {
    if (!name) return
    if (!table) {
      if (status === 'idle') loadTable() // a failed table is not retried here, only through retry()
    } else loadIcon(name)
  })
  const hit = name ? icons.get(name) : undefined
  return typeof hit === 'function' || (typeof hit === 'object' && hit !== null) ? hit : undefined
}

/**
 * Whether icon names can be checked: `known(name)` once the table is there. `failed` says the table
 * could not be loaded, so a name cannot be checked; `retry` tries again.
 */
export function useIconNames(needed: boolean): { status: Status; known: (name: string) => boolean; retry: () => void } {
  useSyncExternalStore(subscribe, () => version)
  useEffect(() => {
    if (needed && status === 'idle') loadTable()
  }, [needed])
  const retry = useCallback(() => {
    if (status === 'failed') status = 'idle'
    loadTable()
  }, [])
  return { status, known: (name) => !!iconLoader(table, name), retry }
}
