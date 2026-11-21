import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/ui/native-select'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { EmptyState } from '@/components/common'
import { InfraFrame, LoadError } from '@/components/infra/InfraFrame'
import { EditResult, ReauthNotice } from '@/components/infra/EditReview'
import { t } from '@/i18n'
import { ApiError } from '@/lib/api'
import { useInfraHost } from '@/lib/infra'
import { useEditFlow, useFeatureSpecs, useHostVars, useSecrets, useWriteState, type FeatureSpec, type SettingSpec } from '@/lib/infraEdit'
import { useMeta } from '@/providers/meta'

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="mb-8">
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="text-base font-semibold">{title}</h2>
        {hint && <span className="text-xs text-muted-foreground">{hint}</span>}
      </div>
      {children}
    </section>
  )
}

const asText = (v: unknown) => (v === undefined || v === null ? '' : String(v))

/** What the form knows of the host's SOPS file: whether the secrets editor is on and which keys it holds. */
type Secrets = { enabled: boolean; stored: Set<string> }

function FieldInput({ spec, value, onChange, id, stored }: { spec: SettingSpec; value: string; onChange: (v: string) => void; id: string; stored?: boolean | null }) {
  if (spec.secret) {
    if (stored === null || stored === undefined) return <p className="text-xs text-muted-foreground">{t.infra.edit.features.secret}</p>
    return (
      <Textarea
        id={id}
        autoComplete="off"
        spellCheck={false}
        rows={2}
        value={value}
        placeholder={stored ? t.infra.edit.features.secretStored : t.infra.edit.features.secretUnset}
        onChange={(e) => onChange(e.target.value)}
        className="font-mono text-xs"
      />
    )
  }
  if (spec.type === 'enum' || spec.type === 'bool') {
    const opts = spec.type === 'bool' ? ['true', 'false'] : (spec.enum ?? [])
    return (
      <NativeSelect id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">{t.infra.edit.features.empty}</option>
        {opts.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </NativeSelect>
    )
  }
  return (
    <Input
      id={id}
      value={value}
      type={spec.type === 'int' ? 'number' : 'text'}
      min={spec.min}
      max={spec.max}
      placeholder={t.infra.edit.features.empty}
      onChange={(e) => onChange(e.target.value)}
      className="font-mono"
    />
  )
}

function FeatureCard({
  spec,
  present,
  initial,
  busy,
  secrets,
  onReview,
}: {
  spec: FeatureSpec
  present: boolean
  initial: Record<string, unknown>
  busy: boolean
  secrets: Secrets
  onReview: (enabled: boolean, settings: Record<string, unknown>) => void
}) {
  const [enabled, setEnabled] = useState(present)
  const [vals, setVals] = useState<Record<string, string>>(() => Object.fromEntries(spec.settings.map((s) => [s.name, asText(initial[s.name])])))
  const submit = () => {
    const out: Record<string, unknown> = {}
    for (const s of spec.settings) {
      const v = vals[s.name]
      if (v === '') continue // an empty secret box keeps the stored value
      out[s.name] = s.type === 'int' ? Number(v) : s.type === 'bool' ? v === 'true' : v
    }
    onReview(enabled, out)
  }
  return (
    <div className="rounded-xl border bg-card p-4 shadow-xs">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-mono text-sm font-medium">{spec.name}</span>
        {spec.description && <span className="text-xs text-muted-foreground">{spec.description}</span>}
      </div>
      <div className="mt-3 flex items-center gap-2">
        <Checkbox id={`on-${spec.name}`} checked={enabled} onCheckedChange={(v) => setEnabled(!!v)} />
        <Label htmlFor={`on-${spec.name}`}>{t.infra.edit.features.on}</Label>
      </div>
      {enabled && (
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          {spec.settings.map((s) => (
            <div key={s.name} className="space-y-1">
              <Label htmlFor={`${spec.name}-${s.name}`} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs">{s.name}</span>
                {s.required && <span className="text-xs text-destructive">{t.infra.edit.features.required}</span>}
              </Label>
              <FieldInput
                spec={s}
                id={`${spec.name}-${s.name}`}
                stored={secrets.enabled ? secrets.stored.has(`feature_${spec.name}_${s.name}`) : null}
                value={vals[s.name] ?? ''}
                onChange={(v) => setVals((o) => ({ ...o, [s.name]: v }))} />
              {s.description && <p className="text-xs text-muted-foreground">{s.description}</p>}
              {s.default !== undefined && s.default !== null && !s.secret && <p className="text-xs text-muted-foreground">{t.infra.edit.features.defaultIs(String(s.default))}</p>}
            </div>
          ))}
        </div>
      )}
      <Button size="sm" className="mt-4" disabled={busy} onClick={submit}>
        {t.infra.edit.features.save}
      </Button>
    </div>
  )
}

export default function InfraHostEdit() {
  const { name = '' } = useParams()
  const { meta } = useMeta()
  const canWrite = !!meta.user?.canInfraWrite
  const write = useWriteState(canWrite)
  const vars = useHostVars(name, canWrite)
  const specs = useFeatureSpecs(canWrite)
  const host = useInfraHost(name, canWrite)
  const secretsQ = useSecrets(name, canWrite)
  const secrets: Secrets = { enabled: !!secretsQ.data?.enabled, stored: new Set(secretsQ.data?.file?.keys.map((k) => k.name)) }
  const flow = useEditFlow()
  const [text, setText] = useState<string | null>(null)
  const busy = flow.state.phase === 'checking' || flow.state.phase === 'committing'

  const content = text ?? vars.data?.content ?? ''
  const base = vars.data?.base ?? ''
  const reload = () => {
    flow.reset()
    setText(null)
    void vars.refetch()
    void host.refetch()
  }
  const path = `/infra/hosts/${encodeURIComponent(name)}`
  const stale = write.data && !write.data.fresh
  const notFound = vars.error instanceof ApiError && vars.error.statusCode === 404

  return (
    <InfraFrame header={false}>
      <Link to={`/infra/hosts/${encodeURIComponent(name)}`} className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> {t.infra.edit.back}
      </Link>
      <h1 className="mb-2 text-xl font-semibold break-all">{t.infra.edit.editTitle(name)}</h1>
      {!canWrite ? (
        <EmptyState title={t.infra.edit.writeOff} />
      ) : vars.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : notFound ? (
        <EmptyState title={t.infra.host.notFound} />
      ) : vars.isError ? (
        <LoadError error={vars.error} />
      ) : (
        <>
          <p className="mb-4 text-xs text-muted-foreground">{t.infra.edit.commitNote}</p>
          {stale && <ReauthNotice hours={Math.round(write.data.maxAgeSeconds / 3600)} />}

          <Section title={t.infra.edit.vars.title} hint={t.infra.edit.vars.hint}>
            {vars.data.hidden > 0 ? (
              <p className="text-sm text-muted-foreground">{t.infra.edit.vars.hidden}</p>
            ) : (
              <>
                {!vars.data.exists && <p className="mb-2 text-xs text-muted-foreground">{t.infra.edit.vars.newFile}</p>}
                <Textarea
                  aria-label={t.infra.edit.vars.label}
                  value={content}
                  onChange={(e) => setText(e.target.value)}
                  spellCheck={false}
                  className="min-h-64 font-mono text-xs leading-relaxed"
                />
                <Button className="mt-3" disabled={busy || content === (vars.data.content ?? '')} onClick={() => flow.review('vars', `${path}/vars`, { base, content })}>
                  {t.infra.edit.review}
                </Button>
                <EditResult flow={flow.state} mine={flow.state.key === 'vars'} onCommit={flow.commit} onReload={reload} onCancel={flow.reset} />
              </>
            )}
          </Section>

          <Section title={t.infra.edit.features.title} hint={t.infra.edit.features.hint}>
            {specs.isPending || host.isPending ? (
              <Skeleton className="h-24 w-full" />
            ) : specs.isError ? (
              <LoadError error={specs.error} />
            ) : specs.data.features.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t.infra.edit.features.none}</p>
            ) : (
              <div className="space-y-4">
                {specs.data.invalid.length > 0 && <p className="text-xs text-muted-foreground">{t.infra.edit.features.broken(specs.data.invalid.join(', '))}</p>}
                {specs.data.features.map((f) => {
                  const cur = host.data?.host.features.find((x) => x.name === f.name)
                  return (
                    <div key={f.name}>
                      <FeatureCard
                        key={JSON.stringify([f.name, !!cur, cur?.settings ?? null, flow.state.phase === 'done' && flow.state.key === `feature:${f.name}` ? flow.state.outcome?.commit : null])}
                        spec={f}
                        present={!!cur}
                        initial={cur?.settings ?? {}}
                        busy={busy}
                        secrets={secrets}
                        onReview={(enabled, settings) => flow.review(`feature:${f.name}`, `${path}/features/${encodeURIComponent(f.name)}`, { base, enabled, settings })}
                      />
                      <EditResult flow={flow.state} mine={flow.state.key === `feature:${f.name}`} onCommit={flow.commit} onReload={reload} onCancel={flow.reset} />
                    </div>
                  )
                })}
              </div>
            )}
          </Section>
        </>
      )}
    </InfraFrame>
  )
}
