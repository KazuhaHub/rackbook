import { createElement } from 'react'
import { collectionIcon } from '@/lib/icons'
import type { Collection } from '@/lib/types'

/** The lucide icon for a collection (optional `icon` from meta, else a keyword match, else a database). */
export function CollectionIcon({ col, className }: { col: Pick<Collection, 'name' | 'title' | 'icon'>; className?: string }) {
  return createElement(collectionIcon(col), { className, 'aria-hidden': true })
}
