import { useRef, useState } from 'react'
import { Plus, X } from 'lucide-react'
import type { WidgetProps } from '@rjsf/utils'
import { Autocomplete, AutocompleteContent, AutocompleteInput, AutocompleteItem, AutocompleteList } from '@/components/ui/autocomplete'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Combobox,
  ComboboxChip,
  ComboboxChips,
  ComboboxChipsInput,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
  ComboboxValue,
  useComboboxAnchor,
} from '@/components/ui/combobox'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { Switch } from '@/components/ui/switch'
import { t } from '@/i18n'
import { enumValues, itemEnum, listEntryError, listHint, type Prop } from '@/lib/fieldKind'
import { customFormats } from '@/lib/formats'
import { objectItems } from '@/lib/objectItems'
import { cn } from '@/lib/utils'

export type RefItem = { value: string; label: string; literal?: boolean }

const invalid = (rawErrors?: string[]) => (rawErrors && rawErrors.length > 0 ? true : undefined)

function RefItemRow({ item }: { item: RefItem }) {
  return (
    <>
      <span className="font-mono text-[0.8125rem]">{item.label}</span>
      {item.literal && (
        <Badge variant="secondary" className="ml-auto">
          {t.form.literalLabel}
        </Badge>
      )}
    </>
  )
}

/** Combobox over the records of the referenced collection plus allowed literals (e.g. "all"). */
export function RefWidget({ id, value, onChange, options, disabled, readonly, rawErrors }: WidgetProps) {
  const items = (options.items as RefItem[]) ?? []
  const current = value === undefined || value === null || value === '' ? null : String(value)
  const all = current !== null && !items.some((i) => i.value === current) ? [...items, { value: current, label: current }] : items
  const selected = all.find((i) => i.value === current) ?? null
  return (
    <div className="space-y-1">
      <Combobox
        autoHighlight
        items={all}
        value={selected}
        itemToStringLabel={(item: RefItem) => item.label}
        isItemEqualToValue={(a: RefItem, b: RefItem) => a.value === b.value}
        onValueChange={(item: RefItem | null) => onChange(item ? item.value : undefined)}
        disabled={disabled || readonly}
      >
        <ComboboxInput id={id} placeholder={t.form.pickReference} showClear={current !== null} aria-invalid={invalid(rawErrors)} className="w-full" />
        <ComboboxContent>
          <ComboboxEmpty>{t.form.noReferenceMatch}</ComboboxEmpty>
          <ComboboxList>
            {(item: RefItem) => (
              <ComboboxItem key={item.value} value={item}>
                <RefItemRow item={item} />
              </ComboboxItem>
            )}
          </ComboboxList>
        </ComboboxContent>
      </Combobox>
      {selected?.literal && <p className="text-xs text-muted-foreground">{t.form.literalPicked}</p>}
    </div>
  )
}

export function SwitchWidget({ id, value, onChange, disabled, readonly }: WidgetProps) {
  return (
    <div className="flex items-center gap-2 p-0.5">
      <Switch id={id} checked={!!value} onCheckedChange={(v) => onChange(v)} disabled={disabled || readonly} />
      <span className="text-sm text-muted-foreground">{value ? t.common.yes : t.common.no}</span>
    </div>
  )
}

/** A reference field that holds several values: chips for what is picked, a combobox to add more. */
export function RefManyWidget({ id, value, onChange, options, disabled, readonly, rawErrors }: WidgetProps) {
  const items = (options.items as RefItem[]) ?? []
  const current: string[] = Array.isArray(value) ? value.map(String) : []
  const remaining = items.filter((i) => !current.includes(i.value))
  const off = disabled || readonly
  return (
    <div className="space-y-2">
      {current.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {current.map((v) => (
            <Badge key={v} variant="secondary" className="font-mono">
              {v}
              {!off && (
                <button
                  type="button"
                  className="-mr-1 rounded-full p-0.5 hover:bg-foreground/10 [&_svg]:size-3"
                  aria-label={`${t.refs.removeValue} ${v}`}
                  onClick={() => {
                    const next = current.filter((x) => x !== v)
                    onChange(next.length ? next : undefined)
                  }}
                >
                  <X />
                </button>
              )}
            </Badge>
          ))}
        </div>
      )}
      {!off && (
        <Combobox
          autoHighlight
          items={remaining}
          value={null}
          itemToStringLabel={(item: RefItem) => item.label}
          onValueChange={(item: RefItem | null) => item && onChange([...current, item.value])}
        >
          <ComboboxInput id={id} placeholder={t.refs.addMany} aria-invalid={invalid(rawErrors)} className="w-full" />
          <ComboboxContent>
            <ComboboxEmpty>{t.form.noReferenceMatch}</ComboboxEmpty>
            <ComboboxList>
              {(item: RefItem) => (
                <ComboboxItem key={item.value} value={item}>
                  <RefItemRow item={item} />
                </ComboboxItem>
              )}
            </ComboboxList>
          </ComboboxContent>
        </Combobox>
      )}
    </div>
  )
}

/** A string enum as a searchable select. */
export function EnumWidget({ id, value, onChange, schema, disabled, readonly, required, rawErrors }: WidgetProps) {
  const base = enumValues(schema as Prop) ?? []
  const current = typeof value === 'string' && value !== '' ? value : null
  // a stored value the schema no longer lists stays visible, so it can be seen and changed
  const items = current !== null && !base.includes(current) ? [...base, current] : base
  return (
    <Combobox autoHighlight items={items} value={current} onValueChange={(v: string | null) => onChange(v ?? undefined)} disabled={disabled || readonly}>
      <ComboboxInput id={id} placeholder={t.form.pickOption} showClear={current !== null && !required} aria-invalid={invalid(rawErrors)} className="w-full" />
      <ComboboxContent>
        <ComboboxEmpty>{t.form.noOptionMatch}</ComboboxEmpty>
        <ComboboxList>
          {(item: string) => (
            <ComboboxItem key={item} value={item}>
              {item}
            </ComboboxItem>
          )}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
  )
}

/** An array of enum values as chips with a searchable dropdown. */
export function TagsWidget({ id, value, onChange, schema, disabled, readonly, rawErrors }: WidgetProps) {
  const anchor = useComboboxAnchor()
  const base = itemEnum(schema as Prop) ?? []
  const current: string[] = Array.isArray(value) ? value.map(String) : []
  const items = [...base, ...current.filter((v) => !base.includes(v))]
  return (
    <Combobox
      multiple
      autoHighlight
      items={items}
      value={current}
      onValueChange={(v: string[]) => {
        const next = items.filter((x) => v.includes(x)) // keep the schema's order
        onChange(next.length ? next : undefined)
      }}
      disabled={disabled || readonly}
    >
      <ComboboxChips ref={anchor} aria-invalid={invalid(rawErrors)}>
        <ComboboxValue>
          {(vals: string[]) => (
            <>
              {vals.map((v) => (
                <ComboboxChip key={v} showRemove={!(disabled || readonly)}>
                  {v}
                </ComboboxChip>
              ))}
              <ComboboxChipsInput id={id} placeholder={vals.length ? '' : t.form.pickTags} />
            </>
          )}
        </ComboboxValue>
      </ComboboxChips>
      <ComboboxContent anchor={anchor}>
        <ComboboxEmpty>{t.form.noOptionMatch}</ComboboxEmpty>
        <ComboboxList>
          {(item: string) => (
            <ComboboxItem key={item} value={item}>
              {item}
            </ComboboxItem>
          )}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
  )
}

/** Short free text with the values already used in this field as a dropdown. */
export function SuggestWidget({ id, value, onChange, options, disabled, readonly, rawErrors, placeholder }: WidgetProps) {
  const suggestions = (options.suggestions as string[] | undefined) ?? []
  const text = typeof value === 'string' ? value : value === undefined || value === null ? '' : String(value)
  const set = (v: string) => onChange(v === '' ? undefined : v)
  if (suggestions.length === 0) {
    return <Input id={id} value={text} onChange={(e) => set(e.target.value)} placeholder={placeholder} disabled={disabled} readOnly={readonly} aria-invalid={invalid(rawErrors)} />
  }
  return (
    <Autocomplete autoHighlight items={suggestions} value={text} onValueChange={(v: string) => set(v)} disabled={disabled || readonly}>
      <AutocompleteInput id={id} placeholder={placeholder || t.form.suggestPlaceholder} aria-invalid={invalid(rawErrors)} className="w-full" />
      <AutocompleteContent>
        <AutocompleteList>
          {(item: string) => (
            <AutocompleteItem key={item} value={item}>
              {item}
            </AutocompleteItem>
          )}
        </AutocompleteList>
      </AutocompleteContent>
    </Autocomplete>
  )
}

/** The browser's date input; the value stays a YYYY-MM-DD string. */
export function DateWidget({ id, value, onChange, disabled, readonly, rawErrors }: WidgetProps) {
  return (
    <Input
      id={id}
      type="date"
      value={typeof value === 'string' ? value : ''}
      onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)}
      disabled={disabled}
      readOnly={readonly}
      aria-invalid={invalid(rawErrors)}
      className="w-full sm:w-48"
    />
  )
}

/**
 * An array of strings as chips plus an input. Each entry is checked as it is typed
 * (items.pattern, items.format, port ranges) and only a valid one is added; the
 * format hint shows under the input.
 */
export function ListWidget({ id, name, value, onChange, schema, disabled, readonly, rawErrors, registry }: WidgetProps) {
  const items = (schema as Prop).items as Prop | undefined
  const description = (schema as Prop).description
  const current: string[] = Array.isArray(value) ? value.map(String) : []
  const [text, setText] = useState('')
  const input = useRef<HTMLInputElement>(null)
  const off = disabled || readonly
  const check = (s: string) => listEntryError(items, s, customFormats, description)
  const hint = typeof description === 'string' && description ? undefined : listHint(items)

  // "443 8443, 20000-20018" adds three entries; the first invalid one stays in the box
  const words = text.split(/[\s,，]+/).filter(Boolean)
  const bad = words.find((w) => check(w) !== undefined)
  const error = bad !== undefined ? check(bad) : undefined
  // the form refuses to save while text is left in the box (see customValidate in RecordForm)
  const setPending = (registry.formContext as { setPending?: (f: string, t: string) => void } | undefined)?.setPending
  const leave = (rest: string) => {
    setPending?.(name, rest)
    setText(rest)
  }
  const add = () => {
    if (!words.length) return
    const good = words.filter((w) => check(w) === undefined && !current.includes(w))
    if (good.length) onChange([...current, ...good.filter((w, i, a) => a.indexOf(w) === i)])
    leave(bad ?? '')
  }

  return (
    <div className="space-y-2">
      {current.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {current.map((v) => {
            const err = check(v)
            return (
              <Badge key={v} variant={err ? 'destructive' : 'secondary'} className="font-mono" title={err}>
                {v}
                {!off && (
                  <button
                    type="button"
                    className="-mr-1 rounded-full p-0.5 hover:bg-foreground/10 [&_svg]:size-3"
                    aria-label={`${t.form.removeEntry} ${v}`}
                    onClick={() => {
                      const next = current.filter((x) => x !== v)
                      onChange(next.length ? next : undefined)
                    }}
                  >
                    <X />
                  </button>
                )}
              </Badge>
            )
          })}
        </div>
      )}
      {!off && (
        <div className="flex gap-2">
          <Input
            ref={input}
            id={id}
            value={text}
            onChange={(e) => leave(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault() // Enter adds the entry, it does not submit the form
                add()
              }
            }}
            onBlur={() => {
              if (words.length && bad === undefined) add()
            }}
            placeholder={t.form.addEntry}
            aria-invalid={error || invalid(rawErrors) ? true : undefined}
            className={cn('font-mono text-[0.8125rem]')}
          />
          <Button type="button" variant="outline" disabled={!words.length || bad !== undefined} onClick={add}>
            {t.form.addEntryButton}
          </Button>
        </div>
      )}
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : hint && !off ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  )
}

/**
 * An array of flat objects as a compact table: one row per item, one column per
 * item property (an enum is a small select, a pattern or format is checked as it is
 * typed), with add and remove row. On a narrow screen the cells of a row stack.
 */
export function RowsWidget({ id, value, onChange, schema, disabled, readonly, rawErrors }: WidgetProps) {
  const spec = objectItems(schema as Prop)
  const rows: Record<string, unknown>[] = Array.isArray(value) ? (value as Record<string, unknown>[]) : []
  const off = disabled || readonly
  if (!spec) return null
  const cols = spec.props.map(([, s]) => (Array.isArray(s.enum) || s.pattern || s.format ? 'minmax(5.5rem,9rem)' : 'minmax(8rem,1fr)')).join(' ')
  const grid = { '--cols': `${cols} 2rem` } as React.CSSProperties
  const set = (i: number, name: string, v: unknown) => {
    const next = rows.map((r, j) => {
      if (j !== i) return r
      const copy = { ...r }
      if (v === undefined || v === '') delete copy[name]
      else copy[name] = v
      return copy
    })
    onChange(next)
  }
  const label = (name: string, s: Prop) => `${(s.title as string) || name}${spec.required.includes(name) ? '*' : ''}`

  return (
    <div className="space-y-2" aria-invalid={invalid(rawErrors)}>
      {rows.length > 0 && (
        <div className="hidden gap-2 text-xs text-muted-foreground sm:grid sm:[grid-template-columns:var(--cols)]" style={grid}>
          {spec.props.map(([name, s]) => (
            <span key={name}>{label(name, s)}</span>
          ))}
          <span />
        </div>
      )}
      {rows.map((row, i) => {
        const started = Object.values(row).some((x) => x !== undefined && x !== '')
        return (
          <div key={i} className="grid gap-2 rounded-md border p-2 sm:[grid-template-columns:var(--cols)] sm:border-0 sm:p-0" style={grid}>
            {spec.props.map(([name, s]) => {
              const raw = row[name]
              const text = raw === undefined || raw === null ? '' : String(raw)
              const isEnum = Array.isArray(s.enum)
              const type = Array.isArray(s.type) ? s.type.find((x) => x !== 'null') : s.type
              const missing = started && text === '' && spec.required.includes(name)
              const err = !isEnum && text !== '' && typeof s.type !== 'undefined' && type === 'string' ? listEntryError(s, text, customFormats, s.description) : undefined
              const cid = `${id}_${i}_${name}`
              return (
                <div key={name} className="min-w-0 space-y-1">
                  <label htmlFor={cid} className="text-xs text-muted-foreground sm:hidden">
                    {label(name, s)}
                  </label>
                  {isEnum ? (
                    <NativeSelect id={cid} value={text} disabled={off} aria-invalid={missing ? true : undefined} onChange={(e) => set(i, name, e.target.value)}>
                      <option value="">—</option>
                      {(s.enum as unknown[]).filter((x) => x !== null).map((x) => (
                        <option key={String(x)} value={String(x)}>
                          {String(x)}
                        </option>
                      ))}
                    </NativeSelect>
                  ) : type === 'boolean' ? (
                    <Switch id={cid} checked={raw === true} disabled={off} onCheckedChange={(v) => set(i, name, v)} />
                  ) : (
                    <Input
                      id={cid}
                      value={text}
                      disabled={disabled}
                      readOnly={readonly}
                      placeholder={(s.title as string) || name}
                      aria-invalid={err || missing ? true : undefined}
                      className={cn(!s.enum && s.pattern ? 'font-mono text-[0.8125rem]' : undefined)}
                      title={err}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') e.preventDefault() // never submits the form
                      }}
                      onChange={(e) => {
                        const v = e.target.value
                        const num = (type === 'integer' || type === 'number') && v.trim() !== '' && Number.isFinite(Number(v))
                        set(i, name, num ? Number(v) : v)
                      }}
                    />
                  )}
                  {err && <p className="text-xs font-medium text-destructive">{err}</p>}
                  {missing && !err && <p className="text-xs font-medium text-destructive">{t.form.required}</p>}
                </div>
              )
            })}
            {!off && (
              <Button type="button" variant="ghost" size="icon-sm" aria-label={t.form.removeRow} className="self-end sm:self-start" onClick={() => onChange(rows.filter((_, j) => j !== i).length ? rows.filter((_, j) => j !== i) : undefined)}>
                <X />
              </Button>
            )}
          </div>
        )
      })}
      {!off && (
        <Button type="button" variant="outline" size="sm" onClick={() => onChange([...rows, {}])}>
          <Plus /> {t.form.addRow}
        </Button>
      )}
    </div>
  )
}
