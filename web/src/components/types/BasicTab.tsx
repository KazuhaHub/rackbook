import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/ui/native-select'
import { Textarea } from '@/components/ui/textarea'
import { LOCALE_NAMES, t } from '@/i18n'
import { useDefaultLocale } from '@/lib/defaultLocale'
import { iconChoices } from '@/lib/icons'
import type { TypeDef } from '@/lib/typedef'
import { cn } from 'cn'
import { OtherLanguages } from './OtherLanguages'

function Field({ label, hint, children, className }: { label: string; hint?: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('space-y-1.5', className)}>
      <Label>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

export function BasicTab({
  draft,
  update,
  creating,
  dataDir,
  schemaDir,
}: {
  draft: TypeDef
  update: (fn: (d: TypeDef) => TypeDef) => void
  creating: boolean
  dataDir: string
  schemaDir: string
}) {
  const def = useDefaultLocale()
  const inDefault = (label: string) => t.types.i18n.inDefault(label, LOCALE_NAMES[def])
  const set = (patch: Partial<TypeDef>) => update((d) => ({ ...d, ...patch }))
  const names = draft.fields.map((f) => f.name).filter(Boolean)
  const defaultFile = `${dataDir}/${draft.name || t.types.basic.namePlaceholder}.yml`
  const defaultSchema = `${schemaDir}/${draft.name || t.types.basic.namePlaceholder}.json`

  return (
    <div className="grid gap-5 sm:grid-cols-2">
      <Field label={t.types.basic.name} hint={creating ? t.types.basic.nameHint : t.types.basic.nameFixed}>
        <Input
          value={draft.name}
          disabled={!creating}
          className="font-mono"
          autoComplete="off"
          onChange={(e) => set({ name: e.target.value.trim() })}
        />
      </Field>
      <Field label={inDefault(t.types.basic.title)}>
        <Input lang={def} value={draft.title} onChange={(e) => set({ title: e.target.value })} />
      </Field>
      <Field label={inDefault(t.types.basic.description)} className="sm:col-span-2">
        <Textarea lang={def} rows={2} value={draft.description ?? ''} onChange={(e) => set({ description: e.target.value })} />
      </Field>
      <Field label={inDefault(t.types.basic.group)} hint={t.types.basic.groupHint}>
        <Input lang={def} value={draft.group ?? ''} onChange={(e) => set({ group: e.target.value })} />
      </Field>
      <div className="sm:col-span-2">
        <OtherLanguages
          value={draft.i18n}
          onChange={(i18n) => set({ i18n })}
          fields={[
            { key: 'title', label: t.types.basic.title },
            { key: 'group', label: t.types.basic.group },
            { key: 'description', label: t.types.basic.description, multiline: true },
          ]}
        />
      </div>
      <Field label={t.types.basic.icon}>
        <div className="flex flex-wrap gap-1">
          <button
            type="button"
            onClick={() => set({ icon: '' })}
            className={cn('h-8 rounded-lg border px-2.5 text-xs transition-colors hover:bg-muted', !draft.icon && 'border-brand bg-brand/10 text-brand')}
          >
            {t.types.basic.iconNone}
          </button>
          {iconChoices.map(({ name, Icon }) => (
            <button
              key={name}
              type="button"
              title={name}
              aria-label={name}
              aria-pressed={draft.icon === name}
              onClick={() => set({ icon: name })}
              className={cn('flex size-8 items-center justify-center rounded-lg border transition-colors hover:bg-muted', draft.icon === name && 'border-brand bg-brand/10 text-brand')}
            >
              <Icon className="size-4" />
            </button>
          ))}
        </div>
      </Field>

      <Field label={t.types.basic.file} hint={creating ? t.types.basic.fileHintDefault(t.types.basic.fileHint, defaultFile) : t.types.basic.fileHint}>
        <Input
          value={creating ? draft.file : draft.file}
          disabled={!creating}
          placeholder={defaultFile}
          className="font-mono"
          onChange={(e) => set({ file: e.target.value.trim() })}
        />
      </Field>
      <Field label={t.types.basic.path} hint={creating ? t.types.basic.pathHint : undefined}>
        <Input value={draft.path ?? ''} disabled={!creating} className="font-mono" onChange={(e) => set({ path: e.target.value.trim() })} />
      </Field>
      <Field label={t.types.basic.schemaFile}>
        <Input value={draft.schemaFile} disabled={!creating} placeholder={defaultSchema} className="font-mono" onChange={(e) => set({ schemaFile: e.target.value.trim() })} />
      </Field>

      <Field label={t.types.basic.key} hint={t.types.basic.keyHint} className="sm:col-span-2">
        {names.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t.types.basic.pickFields}</p>
        ) : (
          <div className="flex flex-wrap gap-x-5 gap-y-2">
            {names.map((n) => (
              <label key={n} className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={draft.key.includes(n)}
                  onCheckedChange={(v) => set({ key: v ? [...draft.key, n] : draft.key.filter((k) => k !== n) })}
                />
                <span className="font-mono">{n}</span>
              </label>
            ))}
          </div>
        )}
        {draft.key.length === 0 && names.length > 0 && <p className="text-xs text-muted-foreground">{t.types.basic.keyNone}</p>}
      </Field>
      <Field label={t.types.basic.label} hint={t.types.basic.labelHint}>
        <NativeSelect value={draft.label ?? ''} onChange={(e) => set({ label: e.target.value })}>
          <option value="">{t.types.basic.labelNone}</option>
          {names.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </NativeSelect>
      </Field>
    </div>
  )
}
