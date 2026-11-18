import { Combobox, ComboboxContent, ComboboxEmpty, ComboboxInput, ComboboxItem, ComboboxList } from '@/components/ui/combobox'
import { X } from 'lucide-react'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { t } from '@/i18n/zh-CN'
import type { WidgetProps } from '@rjsf/utils'

export type RefItem = { value: string; label: string; literal?: boolean }

/** Combobox over the records of the referenced collection plus allowed literals (e.g. "all"). */
export function RefWidget({ id, value, onChange, options, disabled, readonly, rawErrors }: WidgetProps) {
  const items = (options.items as RefItem[]) ?? []
  const current = value === undefined || value === null || value === '' ? null : String(value)
  const all = current !== null && !items.some((i) => i.value === current) ? [...items, { value: current, label: current }] : items
  const selected = all.find((i) => i.value === current) ?? null
  return (
    <Combobox
      items={all}
      value={selected}
      onValueChange={(item: RefItem | null) => onChange(item ? item.value : undefined)}
      disabled={disabled || readonly}
    >
      <ComboboxInput
        id={id}
        placeholder={t.form.pickReference}
        showClear={current !== null}
        aria-invalid={rawErrors && rawErrors.length > 0 ? true : undefined}
        className="w-full"
      />
      <ComboboxContent>
        <ComboboxEmpty>{t.form.noReferenceMatch}</ComboboxEmpty>
        <ComboboxList>
          {(item: RefItem) => (
            <ComboboxItem key={item.value} value={item}>
              <span className="font-mono text-[0.8125rem]">{item.label}</span>
              {item.literal && (
                <Badge variant="secondary" className="ml-auto">
                  {t.form.literalLabel}
                </Badge>
              )}
            </ComboboxItem>
          )}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
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
                  className="-mr-1 rounded-full p-0.5 hover:bg-foreground/10"
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
          onValueChange={(item: RefItem | null) => item && onChange([...current, item.value])}
        >
          <ComboboxInput id={id} placeholder={t.refs.addMany} aria-invalid={rawErrors && rawErrors.length > 0 ? true : undefined} className="w-full" />
          <ComboboxContent>
            <ComboboxEmpty>{t.form.noReferenceMatch}</ComboboxEmpty>
            <ComboboxList>
              {(item: RefItem) => (
                <ComboboxItem key={item.value} value={item}>
                  <span className="font-mono text-[0.8125rem]">{item.label}</span>
                  {item.literal && (
                    <Badge variant="secondary" className="ml-auto">
                      {t.form.literalLabel}
                    </Badge>
                  )}
                </ComboboxItem>
              )}
            </ComboboxList>
          </ComboboxContent>
        </Combobox>
      )}
    </div>
  )
}
