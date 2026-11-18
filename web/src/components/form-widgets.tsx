import { Combobox, ComboboxContent, ComboboxEmpty, ComboboxInput, ComboboxItem, ComboboxList } from '@/components/ui/combobox'
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
