import { useMemo, useState, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/ui/native-select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { TagInput } from '@/components/types/TagInput'
import { t } from '@/i18n/zh-CN'
import {
  cleanSettings,
  defaultsToText,
  firstBad,
  isAppId,
  isEmail,
  isTime,
  parseDefaults,
  parseThresholds,
  sameSettings,
  type ModuleSettings,
  type ModuleView,
} from '@/lib/modules'
import { useMeta } from '@/providers/meta'

const s = t.modules.settings

/** What the form edits, in the shapes the inputs use (text, not numbers). */
type Draft = {
  times: string[]
  timezone: string
  thresholds: string[]
  recipients: string[]
  language: string
  collections: string[]
  servicePrincipals: boolean
  exclude: string[]
  prefix: string
  purpose: string
  defaults: string
}

const strs = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : [])

function toDraft(type: string, st: ModuleSettings): Draft {
  return {
    times: strs(type === 'notify' ? st.send_at : st.sync_at),
    timezone: typeof st.timezone === 'string' ? st.timezone : '',
    thresholds: strs(st.thresholds),
    recipients: strs(st.recipients),
    language: typeof st.language === 'string' ? st.language : '',
    collections: strs(st.collections),
    servicePrincipals: st.service_principals !== false,
    exclude: strs(st.exclude_app_ids),
    prefix: typeof st.name_prefix === 'string' ? st.name_prefix : '',
    purpose: typeof st.purpose === 'string' ? st.purpose : '',
    defaults: defaultsToText(st.defaults),
  }
}

type Errors = Partial<Record<'times' | 'timezone' | 'thresholds' | 'recipients' | 'exclude' | 'defaults', string>>

function check(type: string, d: Draft): Errors {
  const e: Errors = {}
  const badTime = firstBad(d.times, isTime)
  if (badTime) e.times = s.errors.time(badTime)
  if (type === 'notify') {
    const th = parseThresholds(d.thresholds)
    if (th.error) e.thresholds = s.errors.threshold(th.error)
    const bad = firstBad(d.recipients, isEmail)
    if (bad) e.recipients = s.errors.email(bad)
  }
  if (type === 'entra') {
    const bad = firstBad(d.exclude, isAppId)
    if (bad) e.exclude = s.errors.appId(bad)
    const df = parseDefaults(d.defaults)
    if (df.error) e.defaults = s.errors[df.error]
  }
  return e
}

/** The settings the draft stands for: values that are not set are left out. `base` keeps what the form does not edit (paused). */
function toSettings(type: string, d: Draft, base: ModuleSettings): ModuleSettings {
  const out: ModuleSettings = { paused: base.paused, timezone: d.timezone.trim() }
  if (type === 'notify') {
    out.send_at = d.times
    out.thresholds = parseThresholds(d.thresholds).values
    out.recipients = d.recipients
    out.language = d.language
    out.collections = d.collections
  } else {
    out.sync_at = d.times
    out.service_principals = d.servicePrincipals ? (base.service_principals === true ? true : undefined) : false
    out.exclude_app_ids = d.exclude.map((x) => x.toLowerCase())
    out.name_prefix = d.prefix.trim() === '' ? undefined : d.prefix.trim()
    out.purpose = d.purpose.trim()
    out.defaults = parseDefaults(d.defaults).value
  }
  return cleanSettings(out)
}

function Field({ id, label, hint, error, children }: { id: string; label: string; hint?: ReactNode; error?: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {error ? <p className="text-xs text-destructive">{error}</p> : hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  )
}

const zones = (() => {
  try {
    return (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.('timeZone') ?? []
  } catch {
    return []
  }
})()

export function SettingsForm({
  module: m,
  saving,
  readOnly,
  onSave,
}: {
  module: ModuleView
  saving: boolean
  /** the server refuses writes */
  readOnly: boolean
  onSave: (settings: ModuleSettings) => void
}) {
  const { meta } = useMeta()
  const [draft, setDraft] = useState<Draft>(() => toDraft(m.type, m.settings))
  const set = (p: Partial<Draft>) => setDraft((d) => ({ ...d, ...p }))
  const errors = useMemo(() => check(m.type, draft), [m.type, draft])
  const next = useMemo(() => (Object.keys(errors).length ? undefined : toSettings(m.type, draft, m.settings)), [errors, draft, m.type, m.settings])
  const dirty = next ? !sameSettings(next, m.settings) : true
  const notify = m.type === 'notify'
  const defaultTimes = notify ? '08:00' : '03:00'
  const collections = meta.collections.filter((c) => c.expiryField)

  return (
    <form
      className="space-y-5"
      onSubmit={(e) => {
        e.preventDefault()
        if (next) onSave(next)
      }}
    >
      <div className="grid gap-5 md:grid-cols-2">
        <Field id="mod-times" label={notify ? s.timesNotify : s.timesEntra} hint={`${s.timesHint} ${s.defaultHint(defaultTimes)}`} error={errors.times}>
          <TagInput value={draft.times} onChange={(v) => set({ times: v })} placeholder={s.timesPlaceholder} mono />
        </Field>
        <Field id="mod-tz" label={s.timezone} hint={`${s.timezoneHint}`}>
          <Input id="mod-tz" list="mod-zones" value={draft.timezone} onChange={(e) => set({ timezone: e.target.value })} placeholder="Asia/Shanghai" autoComplete="off" />
          <datalist id="mod-zones">
            {zones.map((z) => (
              <option key={z} value={z} />
            ))}
          </datalist>
        </Field>
      </div>

      {notify ? (
        <>
          <div className="grid gap-5 md:grid-cols-2">
            <Field id="mod-th" label={s.thresholds} hint={`${s.thresholdsHint} ${s.defaultHint('30, 14, 7, 0')}`} error={errors.thresholds}>
              <TagInput value={draft.thresholds} onChange={(v) => set({ thresholds: v })} placeholder={s.thresholdsPlaceholder} mono />
            </Field>
            <Field id="mod-lang" label={s.language}>
              <NativeSelect id="mod-lang" value={draft.language} onChange={(e) => set({ language: e.target.value })}>
                {Object.entries(s.languages).map(([k, label]) => (
                  <option key={k} value={k}>
                    {label}
                  </option>
                ))}
              </NativeSelect>
            </Field>
          </div>
          <Field id="mod-rcpt" label={s.recipients} hint={s.recipientsHint} error={errors.recipients}>
            <TagInput value={draft.recipients} onChange={(v) => set({ recipients: v })} placeholder={s.recipientsPlaceholder} />
          </Field>
          <fieldset className="space-y-1.5">
            <legend className="mb-1.5 text-sm font-medium">{s.collections}</legend>
            <div className="flex flex-wrap gap-x-4 gap-y-1.5">
              {collections.map((c) => (
                <label key={c.name} className="flex items-center gap-1.5 text-sm">
                  <input
                    type="checkbox"
                    checked={draft.collections.includes(c.name)}
                    onChange={() => set({ collections: draft.collections.includes(c.name) ? draft.collections.filter((x) => x !== c.name) : [...draft.collections, c.name] })}
                  />
                  {c.title}
                </label>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">{s.collectionsHint}</p>
          </fieldset>
        </>
      ) : (
        <>
          <div className="flex items-start justify-between gap-4 rounded-lg border p-3">
            <div className="space-y-1">
              <Label htmlFor="mod-sp">{s.servicePrincipals}</Label>
              <p className="text-xs text-muted-foreground">{s.servicePrincipalsHint}</p>
            </div>
            <Switch id="mod-sp" checked={draft.servicePrincipals} onCheckedChange={(v) => set({ servicePrincipals: v })} />
          </div>
          <Field id="mod-excl" label={s.excludeIds} hint={s.excludeIdsHint} error={errors.exclude}>
            <TagInput value={draft.exclude} onChange={(v) => set({ exclude: v })} placeholder={s.excludeIdsPlaceholder} mono />
          </Field>
          <div className="grid gap-5 md:grid-cols-2">
            <Field id="mod-prefix" label={s.namePrefix} hint={`${s.namePrefixHint} ${s.defaultHint('entra-')}`}>
              <Input id="mod-prefix" value={draft.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="entra-" autoComplete="off" className="font-mono" />
            </Field>
            <Field id="mod-purpose" label={s.purpose} hint={s.purposeHint}>
              <Input id="mod-purpose" value={draft.purpose} onChange={(e) => set({ purpose: e.target.value })} placeholder={'Entra application "{app}": {type} "{name}"'} autoComplete="off" />
            </Field>
          </div>
          <Field id="mod-defaults" label={s.defaults} hint={s.defaultsHint} error={errors.defaults}>
            <Textarea id="mod-defaults" rows={5} value={draft.defaults} onChange={(e) => set({ defaults: e.target.value })} className="font-mono text-xs" spellCheck={false} />
          </Field>
        </>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t pt-4">
        <Button type="submit" disabled={saving || readOnly || !dirty || !next}>
          {saving ? s.saving : s.save}
        </Button>
        <Button type="button" variant="outline" disabled={saving || !dirty} onClick={() => setDraft(toDraft(m.type, m.settings))}>
          {s.reset}
        </Button>
        {readOnly ? <span className="text-xs text-muted-foreground">{s.readOnly}</span> : dirty && <span className="text-xs text-muted-foreground">{s.unsaved}</span>}
      </div>
    </form>
  )
}
