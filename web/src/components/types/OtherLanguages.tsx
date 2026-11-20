import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { LOCALE_NAMES, t } from '@/i18n'
import { useDefaultLocale, useOtherLocales } from '@/lib/defaultLocale'
import { withText, type I18n } from '@/lib/typedef'

/**
 * Inputs for the text of the languages other than the default one (the default language's text
 * is the standard field above). Empty inputs are not stored; an entry that has no text left
 * disappears.
 */
export function OtherLanguages<K extends string>({
  fields,
  value,
  onChange,
}: {
  fields: { key: K; label: string; multiline?: boolean }[]
  value: I18n<K> | undefined
  onChange: (next: I18n<K> | undefined) => void
}) {
  const others = useOtherLocales()
  const def = useDefaultLocale()
  if (others.length === 0) return null
  return (
    <div className="space-y-3 rounded-lg border border-dashed p-3">
      <div>
        <p className="text-sm font-medium">{t.types.i18n.heading}</p>
        <p className="text-xs text-muted-foreground">{t.types.i18n.hint(LOCALE_NAMES[def])}</p>
      </div>
      {others.map((loc) => (
        <div key={loc} className="grid gap-3 sm:grid-cols-2">
          {fields.map((f) => {
            const id = `i18n-${loc}-${f.key}`
            const text = value?.[loc]?.[f.key] ?? ''
            const set = (v: string) => onChange(withText(value, loc, f.key, v))
            return (
              <div key={f.key} className={f.multiline ? 'space-y-1.5 sm:col-span-2' : 'space-y-1.5'}>
                <Label htmlFor={id}>{t.types.i18n.inLanguage(f.label, LOCALE_NAMES[loc])}</Label>
                {f.multiline ? <Textarea id={id} rows={2} lang={loc} value={text} onChange={(e) => set(e.target.value)} /> : <Input id={id} lang={loc} value={text} onChange={(e) => set(e.target.value)} />}
              </div>
            )
          })}
        </div>
      ))}
    </div>
  )
}
