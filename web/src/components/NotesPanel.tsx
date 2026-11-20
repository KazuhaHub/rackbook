import { useState } from 'react'
import { ChevronDown, StickyNote } from 'lucide-react'
import { t } from '@/i18n'
import type { Note } from '@/lib/types'
import { cn } from '@/lib/utils'
import { noteTitle } from '@/lib/labels'

export function NotesPanel({ notes }: { notes: Note[] }) {
  const [open, setOpen] = useState(true)
  if (!notes.length) return null
  return (
    <div className="mb-4 rounded-xl border bg-muted/30">
      <button
        type="button"
        className="flex w-full items-center gap-2 px-4 py-2.5 text-left text-sm font-medium"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <StickyNote className="size-4 text-muted-foreground" />
        <span className="flex-1">{t.list.notes}</span>
        <span className="text-xs font-normal text-muted-foreground">{open ? t.list.hideNotes : t.list.showNotes}</span>
        <ChevronDown className={cn('size-4 text-muted-foreground transition-transform', !open && '-rotate-90')} />
      </button>
      {open && (
        <div className="space-y-3 border-t px-4 py-3">
          {notes.map((n, i) => (
            <div key={i}>
              <div className="text-sm font-medium">{noteTitle(n)}</div>
              <p className="mt-0.5 text-sm whitespace-pre-wrap text-muted-foreground">{n.text}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
