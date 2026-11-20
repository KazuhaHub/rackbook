import { useState } from 'react'
import { Link } from 'react-router'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import { countryName, flagEmoji, subdivisionCountry } from '@/lib/countryDisplay'
import { displayText, isTbd } from '@/lib/display'
import { enumColorClass } from '@/lib/enumColors'
import { enumValues, itemEnum } from '@/lib/fieldKind'
import { enumOption } from '@/lib/labels'
import { looksMono, recordHref, str } from '@/lib/ledger'
import { formatItem, formatPlain, objectItems, type Prop } from '@/lib/objectItems'
import type { RefLookup } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { EnumIcon } from './EnumIcon'

export function BoolBadge({ value }: { value: boolean }) {
  return value ? (
    <Badge className="bg-success/15 text-success dark:bg-success/20">{t.common.yes}</Badge>
  ) : (
    <Badge variant="outline" className="text-muted-foreground">
      {t.common.no}
    </Badge>
  )
}

/** The placeholder for an unknown value: a word in the viewer's language, muted; the stored value is `tbd`. */
export function TbdText() {
  return (
    <span className="text-muted-foreground italic" title="tbd">
      {t.placeholder.tbd}
    </span>
  )
}

/** An enum value: its label in the current language with its icon and colour; the icon is decoration, the text carries the meaning. */
export function EnumBadge({ schema, value }: { schema: Prop; value: string }) {
  const o = enumOption(schema, value)
  return (
    <Badge variant="secondary" className={cn('font-normal', o.color && enumColorClass[o.color])} title={o.label === o.value ? undefined : o.value}>
      <EnumIcon name={o.icon} />
      {o.label}
    </Badge>
  )
}

function CountryText({ code }: { code: string }) {
  return (
    <span title={code}>
      <span aria-hidden>{flagEmoji(code)}</span> {countryName(code)}
    </span>
  )
}

function SubdivisionText({ code }: { code: string }) {
  const country = subdivisionCountry(code)
  return (
    <span className="font-mono text-[0.8125rem]" title={country ? countryName(country) : undefined}>
      {country && <span aria-hidden>{flagEmoji(country)} </span>}
      {code}
    </span>
  )
}

/** A scalar string with a known meaning (country, subdivision, placeholder); null when it is plain text. */
function formatted(schema: Prop | undefined, s: string) {
  if (isTbd(s)) return <TbdText />
  const f = schema?.format ?? (schema?.items as Prop | undefined)?.format
  if (f === 'country' && /^[A-Z]{2}$/.test(s)) return <CountryText code={s} />
  if (f === 'subdivision' && /^[A-Z]{2}-/.test(s)) return <SubdivisionText code={s} />
  return null
}

function Text({ value, expandable, className }: { value: string; expandable: boolean; className?: string }) {
  const [open, setOpen] = useState(false)
  const mono = looksMono(value)
  const long = expandable && (value.length > 40 || value.includes('\n'))
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
              'block max-w-[40ch] cursor-pointer text-left break-words',
              open ? 'whitespace-pre-wrap' : 'line-clamp-2',
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
  schema,
}: {
  value: unknown
  lookup?: RefLookup
  /** the property's schema, to format arrays of objects */
  schema?: Prop
  variant?: 'cell' | 'detail'
}) {
  if (value === undefined || value === null || value === '') return <span className="text-muted-foreground/60">—</span>
  if (typeof value === 'boolean') return <BoolBadge value={value} />
  if (Array.isArray(value)) {
    // items that are flat objects ({protocol, port}): one badge each, "TCP 443", a note as tooltip
    if (!lookup && value.length && value.every((v) => v && typeof v === 'object' && !Array.isArray(v))) {
      const spec = schema ? objectItems(schema) : undefined
      return (
        <span className="inline-flex flex-wrap gap-1">
          {value.map((v, i) => {
            const f = spec ? formatItem(v, spec, (s, x) => displayText(s, x)) : { text: formatPlain(v), title: undefined }
            return (
              <Badge key={i} variant="secondary" className="font-mono font-normal" title={f.title}>
                {f.text}
              </Badge>
            )
          })}
        </span>
      )
    }
    // a list of plain values (tags) reads best as small badges
    if (!lookup && value.every((v) => typeof v === 'string' || typeof v === 'number')) {
      const listed = schema ? itemEnum(schema) : undefined
      return (
        <span className="inline-flex flex-wrap gap-1">
          {value.map((v, i) =>
            schema && listed?.includes(String(v)) ? (
              <EnumBadge key={i} schema={schema} value={String(v)} />
            ) : (
              <Badge key={i} variant="secondary" className="font-normal">
                {(typeof v === 'string' && formatted(schema, v)) || String(v)}
              </Badge>
            ),
          )}
        </span>
      )
    }
    return (
      <span className="inline-flex flex-wrap gap-1">
        {value.map((v, i) => (
          <CellValue key={i} value={v} lookup={lookup} variant={variant} />
        ))}
      </span>
    )
  }
  const s = str(value)
  if (!lookup && typeof value === 'string') {
    if (schema && enumValues(schema)?.includes(s)) return <EnumBadge schema={schema} value={s} />
    const f = formatted(schema, s)
    if (f) return f
  }
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
