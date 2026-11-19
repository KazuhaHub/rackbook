import { useRef, useState } from 'react'
import { X } from 'lucide-react'
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
import { Switch } from '@/components/ui/switch'
import { t } from '@/i18n/zh-CN'
import { enumValues, itemEnum, listEntryError, listHint, type Prop } from '@/lib/fieldKind'
import { customFormats } from '@/lib/formats'
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
    <Combobox items={items} value={current} onValueChange={(v: string | null) => onChange(v ?? undefined)} disabled={disabled || readonly}>
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
    <Autocomplete items={suggestions} value={text} onValueChange={(v: string) => set(v)} disabled={disabled || readonly}>
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
export function ListWidget({ id, value, onChange, schema, disabled, readonly, rawErrors }: WidgetProps) {
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
  const add = () => {
    if (!words.length) return
    const good = words.filter((w) => check(w) === undefined && !current.includes(w))
    if (good.length) onChange([...current, ...good.filter((w, i, a) => a.indexOf(w) === i)])
    setText(bad ?? '')
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
            onChange={(e) => setText(e.target.value)}
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
