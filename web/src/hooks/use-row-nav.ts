import type { KeyboardEvent, MouseEvent } from 'react'
import { useNavigate } from 'react-router'

// Anything inside a row that does its own thing on click: links, buttons, form
// controls and the cells that edit in place.
const OWN_CLICK = 'a,button,input,select,textarea,label,[role="combobox"],[role="menuitem"],[data-no-row-click]'

/**
 * Props that make a table row open `href` when clicked or when Enter is pressed on
 * it, and move between rows with the arrow keys (Home / End jump to the first / last).
 * The first row is the tab stop; the others are reached with the arrows.
 * Links and buttons inside the row keep working, and so does selecting text.
 */
export function useRowNav() {
  const navigate = useNavigate()
  return (href: string, first = false) => ({
    tabIndex: first ? 0 : -1,
    'data-row': '',
    onClick(e: MouseEvent<HTMLElement>) {
      // a click in a popover rendered in a portal bubbles through React but is not in the row
      if (e.defaultPrevented || e.button !== 0 || !e.currentTarget.contains(e.target as Node)) return
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
      if ((e.target as HTMLElement).closest(OWN_CLICK)) return
      const sel = window.getSelection()
      if (sel && !sel.isCollapsed && sel.anchorNode && e.currentTarget.contains(sel.anchorNode)) return
      navigate(href)
    },
    onKeyDown(e: KeyboardEvent<HTMLElement>) {
      if (e.target !== e.currentTarget || e.defaultPrevented) return
      if (e.key === 'Enter') {
        e.preventDefault()
        navigate(href)
        return
      }
      const row = e.currentTarget
      let next: Element | null | undefined
      if (e.key === 'ArrowDown') next = row.nextElementSibling
      else if (e.key === 'ArrowUp') next = row.previousElementSibling
      else if (e.key === 'Home') next = row.parentElement?.firstElementChild
      else if (e.key === 'End') next = row.parentElement?.lastElementChild
      else return
      e.preventDefault()
      if (next instanceof HTMLElement && next.hasAttribute('data-row')) next.focus()
    },
  })
}

/** Class names for a navigable row: pointer, hover and a visible keyboard focus ring. */
export const rowClass =
  'cursor-pointer border-b transition-colors duration-150 last:border-0 even:bg-muted/25 hover:bg-brand/[0.07] focus-visible:bg-brand/[0.07] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring'
