import { useState } from 'react'
import { Link } from 'react-router'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { t } from '@/i18n/zh-CN'
import { looksMono, recordHref, str } from '@/lib/ledger'
import type { RefLookup } from '@/lib/hooks'
import { cn } from '@/lib/utils'

export function BoolBadge({ value }: { value: boolean }) {
  return value ? (
    <Badge className="bg-success/15 text-success dark:bg-success/20">{t.common.yes}</Badge>
  ) : (
    <Badge variant="outline" className="text-muted-foreground">
      {t.common.no}
    </Badge>
  )
}

function Text({ value, expandable, className }: { value: string; expandable: boolean; className?: string }) {
  const [open, setOpen] = useState(false)
  const mono = looksMono(value)
  const long = expandable && (value.length > 36 || value.includes('\n'))
  const cls = cn(mono && 'font-mono text-[0.8125rem]', className)
  if (!long) return <span className={cls}>{value}</span>
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              setOpen((o) => !o)
            }}
            className={cn(
              'block max-w-[34ch] cursor-pointer text-left',
              open ? 'whitespace-pre-wrap break-words' : 'truncate',
              cls,
            )}
            aria-expanded={open}
          />
        }
      >
        {value}
      </TooltipTrigger>
      {!open && <TooltipContent className="max-w-sm whitespace-pre-wrap break-words">{value}</TooltipContent>}
    </Tooltip>
  )
}

/**
 * Renders one field value. `lookup` is given for reference fields; `variant` is
 * "cell" (table: long text truncates) or "detail" (full text).
 */
export function CellValue({
  value,
  lookup,
  variant = 'cell',
}: {
  value: unknown
  lookup?: RefLookup
  variant?: 'cell' | 'detail'
}) {
  if (value === undefined || value === null || value === '') return <span className="text-muted-foreground/60">—</span>
  if (typeof value === 'boolean') return <BoolBadge value={value} />
  if (Array.isArray(value)) {
    return (
      <span className="inline-flex flex-wrap gap-1">
        {value.map((v, i) => (
          <CellValue key={i} value={v} lookup={lookup} variant={variant} />
        ))}
      </span>
    )
  }
  const s = str(value)
  if (lookup) {
    if (lookup.allow.includes(s) && !lookup.map.has(s)) {
      return <Badge variant="secondary" className="font-mono">{s}</Badge>
    }
    const id = lookup.map.get(s)
    if (id !== undefined) {
      return (
        <Link
          to={recordHref(lookup.to, id)}
          className="font-mono text-[0.8125rem] text-sky-700 underline decoration-sky-700/30 underline-offset-4 hover:decoration-current dark:text-sky-300 dark:decoration-sky-300/30"
          onClick={(e) => e.stopPropagation()}
        >
          {s}
        </Link>
      )
    }
    // dangling reference: shown as plain text, flagged
    return <span className="font-mono text-[0.8125rem] text-destructive">{s}</span>
  }
  if (variant === 'detail') {
    return <span className={cn('whitespace-pre-wrap break-words', looksMono(s) && 'font-mono text-[0.8125rem]')}>{s}</span>
  }
  return <Text value={s} expandable />
}
