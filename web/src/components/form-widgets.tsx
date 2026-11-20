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
import { listEntryError, listHint, type Prop } from '@/lib/fieldKind'
import { COUNTRY_CODES } from '@/lib/countries'
import { countryName, flagEmoji } from '@/lib/countryDisplay'
import { codeForLabel, enumMatches, enumOptions, fieldDescription, fieldTitle, isEnumLike, type EnumOption } from '@/lib/labels'
import { enumColorClass } from '@/lib/enumColors'
import { collator } from '@/i18n/format'
import { customFormats } from '@/lib/formats'
import { objectItems } from '@/lib/objectItems'
import { cn } from '@/lib/utils'
import { EnumIcon } from './EnumIcon'

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

/** A choice in a picker: a stored code with the text, icon and colour it is shown with. */
type PickItem = EnumOption & { prefix?: string }

function ItemLabel({ item }: { item: PickItem }) {
  return (
    <>
      {item.prefix && <span aria-hidden>{item.prefix}</span>}
      <EnumIcon name={item.icon} />
      {item.label}
    </>
  )
}

/**
 * A searchable single select over codes. `matches` decides what a typed query finds (the code and
 * its names in every language); `resolve` maps text typed and left in the box to a code, so typing a
 * label exactly picks its code.
 */
function SinglePick({
  id,
  items,
  current,
  onChange,
  matches,
  resolve,
  disabled,
  required,
  rawErrors,
}: {
  id: string
  items: PickItem[]
  current: string | null
  onChange: (v: string | undefined) => void
  matches: (item: PickItem, query: string) => boolean
  resolve: (text: string) => string | undefined
  disabled?: boolean
  required?: boolean
  rawErrors?: string[]
}) {
  const selected = items.find((i) => i.value === current) ?? null
  return (
    <Combobox
      autoHighlight
      items={items}
      value={selected}
      itemToStringLabel={(item: PickItem) => item.label}
      isItemEqualToValue={(a: PickItem, b: PickItem) => a.value === b.value}
      filter={matches}
      onValueChange={(item: PickItem | null) => onChange(item ? item.value : undefined)}
      disabled={disabled}
    >
      <ComboboxInput
        id={id}
        placeholder={t.form.pickOption}
        showClear={current !== null && !required}
        aria-invalid={invalid(rawErrors)}
        className="w-full"
        onBlur={(e) => {
          const code = resolve(e.currentTarget.value)
          if (code !== undefined && code !== current) onChange(code)
        }}
      />
      <ComboboxContent>
        <ComboboxEmpty>{t.form.noOptionMatch}</ComboboxEmpty>
        <ComboboxList>
          {(item: PickItem) => (
            <ComboboxItem key={item.value} value={item}>
              <ItemLabel item={item} />
            </ComboboxItem>
          )}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
  )
}

/** A string enum as a searchable select: icon and label in the current language, the code is what is stored. */
export function EnumWidget({ id, value, onChange, schema, disabled, readonly, required, rawErrors }: WidgetProps) {
  const prop = schema as Prop
  const options = enumOptions(prop)
  const current = typeof value === 'string' && value !== '' ? value : null
  // a stored value the schema no longer lists stays visible, so it can be seen and changed
  const items = current !== null && !options.some((o) => o.value === current) ? [...options, { value: current, label: current }] : options
  return (
    <SinglePick
      id={id}
      items={items}
      current={current}
      onChange={onChange}
      matches={(item, q) => enumMatches(prop, item.value, q) || item.label.toLowerCase().includes(q.trim().toLowerCase())}
      resolve={(text) => codeForLabel(prop, text)}
      disabled={disabled || readonly}
      required={required}
      rawErrors={rawErrors}
    />
  )
}

/** The country picker: every assigned code (plus the placeholder tbd) by flag and name in the current language. */
export function CountryWidget({ id, value, onChange, disabled, readonly, required, rawErrors }: WidgetProps) {
  const current = typeof value === 'string' && value !== '' ? value : null
  const items: PickItem[] = COUNTRY_CODES.map((code) => ({ value: code, label: countryName(code), prefix: flagEmoji(code) })).sort((a, b) =>
    collator().compare(a.label, b.label),
  )
  items.push({ value: 'tbd', label: t.placeholder.tbd })
  if (current !== null && !items.some((i) => i.value === current)) items.push({ value: current, label: current })
  const names = (code: string) => [code, countryName(code), countryName(code, 'en-US')]
  return (
    <SinglePick
      id={id}
      items={items}
      current={current}
      onChange={onChange}
      matches={(item, q) => {
        const x = q.trim().toLowerCase()
        return x === '' || [...names(item.value), item.label].some((n) => n.toLowerCase().includes(x))
      }}
      resolve={(text) => {
        const x = text.trim()
        if (x === 'tbd' || x.toLowerCase() === t.placeholder.tbd.toLowerCase()) return 'tbd'
        const code = x.toUpperCase()
        if (COUNTRY_CODES.includes(code)) return code
        return COUNTRY_CODES.find((c) => names(c).some((n) => n.toLowerCase() === x.toLowerCase()))
      }}
      disabled={disabled || readonly}
      required={required}
      rawErrors={rawErrors}
    />
  )
}

/** An array of enum values as chips with a searchable dropdown. */
export function TagsWidget({ id, value, onChange, schema, disabled, readonly, rawErrors }: WidgetProps) {
  const anchor = useComboboxAnchor()
  const prop = schema as Prop
  const base = enumOptions(prop)
  const current: string[] = Array.isArray(value) ? value.map(String) : []
  const items: PickItem[] = [...base, ...current.filter((v) => !base.some((o) => o.value === v)).map((v) => ({ value: v, label: v }))]
  const chosen = items.filter((i) => current.includes(i.value))
  return (
    <Combobox
      multiple
      autoHighlight
      items={items}
      value={chosen}
      itemToStringLabel={(item: PickItem) => item.label}
      isItemEqualToValue={(a: PickItem, b: PickItem) => a.value === b.value}
      filter={(item: PickItem, q: string) => enumMatches(prop, item.value, q) || item.label.toLowerCase().includes(q.trim().toLowerCase())}
      onValueChange={(v: PickItem[]) => {
        const codes = v.map((x) => x.value)
        const next = items.filter((x) => codes.includes(x.value)).map((x) => x.value) // keep the schema's order
        onChange(next.length ? next : undefined)
      }}
      disabled={disabled || readonly}
    >
      <ComboboxChips ref={anchor} aria-invalid={invalid(rawErrors)}>
        <ComboboxValue>
          {(vals: PickItem[]) => (
            <>
              {vals.map((v) => (
                <ComboboxChip key={v.value} showRemove={!(disabled || readonly)} className={cn(v.color && enumColorClass[v.color])}>
                  <ItemLabel item={v} />
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
          {(item: PickItem) => (
            <ComboboxItem key={item.value} value={item}>
              <ItemLabel item={item} />
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
  const cols = spec.props.map(([, s]) => (isEnumLike(s) || s.pattern || s.format ? 'minmax(5.5rem,9rem)' : 'minmax(8rem,1fr)')).join(' ')
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
  const label = (name: string, s: Prop) => `${fieldTitle(s, name)}${spec.required.includes(name) ? '*' : ''}`

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
              const isEnum = isEnumLike(s)
              const type = Array.isArray(s.type) ? s.type.find((x) => x !== 'null') : s.type
              const missing = started && text === '' && spec.required.includes(name)
              const err = !isEnum && text !== '' && typeof s.type !== 'undefined' && type === 'string' ? listEntryError(s, text, customFormats, fieldDescription(s)) : undefined
              const cid = `${id}_${i}_${name}`
              return (
                <div key={name} className="min-w-0 space-y-1">
                  <label htmlFor={cid} className="text-xs text-muted-foreground sm:hidden">
                    {label(name, s)}
                  </label>
                  {isEnum ? (
                    <NativeSelect id={cid} value={text} disabled={off} aria-invalid={missing ? true : undefined} onChange={(e) => set(i, name, e.target.value)}>
                      <option value="">—</option>
                      {[...enumOptions(s), ...(text !== '' && !enumOptions(s).some((o) => o.value === text) ? [{ value: text, label: text }] : [])].map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
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
                      placeholder={fieldTitle(s, name)}
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
