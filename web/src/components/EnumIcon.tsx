import { createElement } from 'react'
import { useIcon } from '@/lib/iconTable'
import { cn } from '@/lib/utils'

/**
 * A lucide icon by kebab-case name, hidden from assistive technology: the label next to
 * it carries the meaning. An unknown name, or an icon that cannot be loaded, renders nothing.
 */
export function EnumIcon({ name, className }: { name?: string; className?: string }) {
  const icon = useIcon(name)
  return icon ? createElement(icon, { 'aria-hidden': true, className: cn('size-3.5 shrink-0', className) }) : null
}
