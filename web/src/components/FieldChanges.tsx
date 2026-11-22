import { useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { t } from '@/i18n'
import { isLongValue, shortValue, valueText, type FieldChange } from '@/lib/versionValue'
import { cn } from '@/lib/utils'

/** What the server puts in place of a value the secret scan flags. */
const HIDDEN = '(hidden)'

/** One value of a change; a long one is collapsed until it is opened. */
function Value({ text, hidden, tone }: { text: string; hidden?: boolean; tone: 'old' | 'new' | 'plain' }) {
  const [open, setOpen] = useState(false)
  const cls = cn(
    'min-w-0 rounded px-1 py-0.5 text-xs break-words whitespace-pre-wrap',
    tone === 'old' && 'bg-red-500/10 text-red-700 line-through decoration-red-700/40 dark:text-red-300',
    tone === 'new' && 'bg-green-500/10 text-green-700 dark:text-green-300',
  )
  if (hidden) {
    return (
      <span className={cn(cls, 'font-mono italic no-underline')} title={t.history.hiddenHint}>
        {t.history.hidden}
      </span>
    )
  }
  if (text === '') return <span className={cn(cls, 'text-muted-foreground italic')}>{t.history.emptyValue}</span>
  const long = isLongValue(text)
  return (
    <span className="min-w-0">
      <span className={cn(cls, 'font-mono')}>{long && !open ? shortValue(text) : text}</span>
      {long && (
        <button type="button" className="ml-1 text-xs text-sky-700 underline underline-offset-2 dark:text-sky-300" aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? t.history.showLess : t.history.showAll}
        </button>
      )}
    </span>
  )
}

/** The field-level changes of a version: old struck through, new highlighted. */
export function FieldChanges({ changes, more }: { changes: FieldChange[]; more?: boolean }) {
  if (!changes.length) return <p className="text-xs text-muted-foreground">{t.history.noFieldChanges}</p>
  return (
    <div className="min-w-0">
      <ul className="divide-y rounded-lg border bg-muted/20">
        {changes.map((c, i) => (
          <li key={c.path + i} className="grid min-w-0 gap-1 px-3 py-2 sm:grid-cols-[minmax(7rem,12rem)_minmax(0,1fr)] sm:gap-x-4">
            <div className="flex min-w-0 flex-wrap items-center gap-1.5">
              <code className="min-w-0 font-mono text-xs break-all">{c.path}</code>
              <Badge variant="outline" className="shrink-0">
                {t.history.op[c.op] ?? c.op}
              </Badge>
            </div>
            <div className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1">
              {c.op !== 'added' && <Value text={valueText(c.old)} hidden={c.hidden && c.old === HIDDEN} tone="old" />}
              {c.op === 'changed' && <span aria-hidden className="text-muted-foreground">→</span>}
              {c.op !== 'removed' && <Value text={valueText(c.new)} hidden={c.hidden && c.new === HIDDEN} tone="new" />}
              {c.truncated && <span className="text-xs text-muted-foreground">{t.history.truncated}</span>}
            </div>
          </li>
        ))}
      </ul>
      {more && <p className="mt-1 text-xs text-muted-foreground">{t.history.moreChanges}</p>}
    </div>
  )
}
