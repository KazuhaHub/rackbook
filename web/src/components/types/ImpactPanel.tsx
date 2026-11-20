import { Link } from 'react-router'
import { AlertTriangle, ArrowDownLeft, ArrowUpRight, CheckCircle2, FileDiff, Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { t } from '@/i18n'
import { recordHref } from '@/lib/ledger'
import type { Migration, Offer, Plan, PlanIssue } from '@/lib/typedef'
import { cn } from 'cn'

function Section({ title, children, tone }: { title: string; children: React.ReactNode; tone?: 'bad' }) {
  return (
    <section className="space-y-2">
      <h3 className={cn('text-xs font-semibold tracking-wide text-muted-foreground', tone === 'bad' && 'text-destructive')}>{title}</h3>
      {children}
    </section>
  )
}

function Issues({ items }: { items: PlanIssue[] }) {
  return (
    <ul className="max-h-48 space-y-1 overflow-y-auto text-xs">
      {items.slice(0, 50).map((i, n) => (
        <li key={n} className="flex gap-2">
          {i.id ? (
            <Link to={recordHref(i.collection, i.id)} className="shrink-0 font-mono text-brand hover:underline">
              {i.collection}/{i.id}
            </Link>
          ) : (
            <span className="shrink-0 font-mono">{i.collection}</span>
          )}
          <span className="min-w-0 text-muted-foreground">
            {i.path && <span className="font-mono">{i.path} </span>}
            {i.message}
          </span>
        </li>
      ))}
      {items.length > 50 && <li className="text-muted-foreground">… {t.types.impact.more}</li>}
    </ul>
  )
}

export const migKey = (m: { kind: string; field: string }) => `${m.kind}:${m.field}`

/** The dry run of a type change: what breaks, what can be migrated, what is committed. */
export function ImpactPanel({
  plan,
  planning,
  error,
  unchanged,
  chosen,
  onChoose,
  onViewFiles,
}: {
  plan?: Plan
  planning: boolean
  error?: string
  unchanged?: boolean
  chosen: Migration[]
  onChoose: (m: Migration[]) => void
  onViewFiles?: () => void
}) {
  const has = (o: Offer) => chosen.find((m) => migKey(m) === migKey(o))
  const toggle = (o: Offer, on: boolean) =>
    onChoose(on ? [...chosen, { kind: o.kind, field: o.field }] : chosen.filter((m) => migKey(m) !== migKey(o)))
  const setValue = (o: Offer, value: string) => onChoose(chosen.map((m) => (migKey(m) === migKey(o) ? { ...m, value: value === '' ? undefined : value } : m)))

  let head: React.ReactNode
  if (unchanged) {
    head = (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <CheckCircle2 className="size-4" /> {t.types.impact.unchanged}
      </div>
    )
  } else if (error) {
    head = (
      <div className="flex items-start gap-2 text-sm text-destructive">
        <AlertTriangle className="mt-0.5 size-4 shrink-0" /> {error}
      </div>
    )
  } else if (!plan) {
    head = (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> {t.types.impact.planning}
      </div>
    )
  } else if (plan.clean) {
    head = (
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-sm font-medium text-green-700 dark:text-green-400">
          <CheckCircle2 className="size-4" /> {plan.changed ? t.types.impact.clean : t.types.impact.unchanged}
        </div>
        {plan.changed && <p className="text-xs text-muted-foreground">{t.types.impact.cleanBody}</p>}
      </div>
    )
  } else {
    head = (
      <div className="flex items-center gap-2 text-sm font-medium text-destructive">
        <AlertTriangle className="size-4" /> {t.types.impact.blocked}
      </div>
    )
  }

  return (
    <div className={cn('space-y-5 rounded-xl border p-4 transition-opacity', planning && plan && 'opacity-60')}>
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">{t.types.impact.title}</h2>
        {planning && plan && <Loader2 className="size-3.5 animate-spin text-muted-foreground" />}
      </div>
      {head}

      {plan && !unchanged && (
        <>
          {plan.refusals.length > 0 && (
            <Section title={t.types.impact.refusals} tone="bad">
              <ul className="space-y-2">
                {plan.refusals.map((r, i) => (
                  <li key={i} className="rounded-lg bg-destructive/10 p-2.5 text-xs">
                    <div className="flex items-center gap-2">
                      <Badge variant="destructive">{t.types.impact.codes[r.code] ?? r.code}</Badge>
                      {r.field && <span className="font-mono">{r.field}</span>}
                    </div>
                    <p className="mt-1.5 text-foreground/90">{r.message}</p>
                    {r.records && r.records.length > 0 && (
                      <p className="mt-1.5 text-muted-foreground">
                        {t.types.impact.recordsLabel(r.count ?? r.records.length)}
                        {r.records.join(t.common.listSep)}
                        {(r.count ?? 0) > r.records.length && ' …'}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {plan.migrations.length > 0 && (
            <Section title={t.types.impact.migrations}>
              <p className="text-xs text-muted-foreground">{t.types.impact.migrationsHint}</p>
              <ul className="space-y-2.5">
                {plan.migrations.map((o) => {
                  const c = has(o)
                  return (
                    <li key={migKey(o)} className="rounded-lg border p-2.5 text-xs">
                      <label className="flex cursor-pointer items-start gap-2">
                        <Checkbox className="mt-0.5" checked={!!c} onCheckedChange={(v) => toggle(o, !!v)} />
                        <span className="text-sm">{o.kind === 'remove-field' ? t.types.impact.removeField(o.field, o.count) : t.types.impact.fillDefault(o.field, o.count)}</span>
                      </label>
                      {o.kind === 'fill-default' && (
                        <div className="mt-2 pl-6">
                          <Input
                            className="h-7 text-xs"
                            placeholder={o.default !== undefined ? String(o.default) : t.types.impact.fillNoDefault}
                            value={c?.value === undefined ? '' : String(c.value)}
                            disabled={!c}
                            aria-label={t.types.impact.fillValue}
                            onChange={(e) => setValue(o, e.target.value)}
                          />
                        </div>
                      )}
                      <p className="mt-1.5 pl-6 text-muted-foreground">
                        {o.records.join(t.common.listSep)}
                        {o.count > o.records.length && ' …'}
                      </p>
                    </li>
                  )
                })}
              </ul>
            </Section>
          )}

          {plan.invalid.length > 0 && (
            <Section title={t.types.impact.invalid(plan.invalid.length) + (plan.truncated ? '+' : '')} tone="bad">
              <Issues items={plan.invalid} />
            </Section>
          )}
          {plan.dangling.length > 0 && (
            <Section title={t.types.impact.dangling(plan.dangling.length)} tone="bad">
              <Issues items={plan.dangling} />
            </Section>
          )}
          {plan.other.length > 0 && (
            <Section title={t.types.impact.other(plan.other.length)} tone="bad">
              <Issues items={plan.other} />
            </Section>
          )}

          {plan.backrefs.length > 0 && (
            <Section title={t.types.impact.backrefs}>
              <ul className="space-y-1 text-xs">
                {plan.backrefs.map((b, i) => (
                  <li key={i} className="flex items-start gap-1.5">
                    {b.change === 'gained' ? <ArrowDownLeft className="mt-0.5 size-3.5 shrink-0 text-green-600" /> : <ArrowUpRight className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />}
                    {b.change === 'gained' ? t.types.impact.gained(b.collection, b.from) : t.types.impact.lost(b.collection, b.from)}
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {plan.files.length > 0 && (
            <Section title={t.types.impact.files}>
              <ul className="space-y-1 text-xs">
                {plan.files.map((f) => (
                  <li key={f.path} className="flex items-center gap-2">
                    <Badge variant={f.status === 'removed' ? 'destructive' : 'secondary'}>{t.types.preview[f.status]}</Badge>
                    <code className="min-w-0 truncate font-mono">{f.path}</code>
                  </li>
                ))}
              </ul>
              {onViewFiles && (
                <button type="button" className="inline-flex items-center gap-1 text-xs text-brand hover:underline" onClick={onViewFiles}>
                  <FileDiff className="size-3.5" /> {t.types.impact.viewDiff}
                </button>
              )}
            </Section>
          )}
        </>
      )}
    </div>
  )
}
