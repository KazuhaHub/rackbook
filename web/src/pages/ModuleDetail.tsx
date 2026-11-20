import { useCallback, useState } from 'react'
import { Link, useParams } from 'react-router'
import { ArrowLeft, KeyRound, Pause, Play, PlayCircle, ShieldAlert } from 'lucide-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ImpactDialog } from '@/components/modules/ImpactDialog'
import { ModuleStatus, RunStatusBadge } from '@/components/modules/ModuleStatus'
import { SettingsForm } from '@/components/modules/SettingsForm'
import { doneText, took, when } from '@/components/modules/format'
import { EmptyState, PageHeader } from '@/components/common'
import { t } from '@/i18n'
import { ApiError, errorMessage } from '@/lib/api'
import { changedElsewhere, cleanSettings, editBase, isRiskyChange, pinAfterLoadLatest, pinAfterSave, type EditBase, type Impact, type ModuleSettings, type ModuleView } from '@/lib/modules'
import { modulesKey, previewSettings, saveSettings, useModules, useRequestRun } from '@/lib/modulesApi'
import { useMeta } from '@/providers/meta'
import { nextText, typeLabel } from './Modules'

function Item({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 text-sm break-words">{children}</dd>
    </div>
  )
}

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

type Dialog = { settings: ModuleSettings; impact?: Impact; error?: string }

// Keyed by module name, so moving to another module never carries over
// unsaved edits or the version they started from.
export default function ModuleDetail() {
  const { name = '' } = useParams()
  return <ModuleDetailPage key={name} name={name} />
}

function ModuleDetailPage({ name }: { name: string }) {
  const { meta } = useMeta()
  const admin = !!meta.user?.canAdmin
  const q = useModules(admin, 30_000)
  const qc = useQueryClient()
  const run = useRequestRun(name)
  const [dialog, setDialog] = useState<Dialog | null>(null)
  const [conflict, setConflict] = useState(false)
  // the version and settings the unsaved edits started from (null: no edits)
  const [pin, setPin] = useState<EditBase | null>(null)
  // whether the form has unsaved edits, as the form itself says
  const [dirty, setDirty] = useState(false)
  const m = q.data?.modules.find((x) => x.name === name)

  const save = useMutation({
    mutationFn: ({ settings, confirm, version }: { settings: ModuleSettings; confirm?: boolean; version: string }) => saveSettings(name, version, settings, confirm),
    onSuccess: async (r) => {
      setDialog(null)
      setConflict(false)
      toast.success(!r.changed ? t.modules.settings.nothingChanged : r.pullRequest ? t.modules.settings.savedPr : t.modules.settings.saved)
      qc.invalidateQueries({ queryKey: ['rb'] })
      // the form follows the server again once the new settings have arrived
      if (pinAfterSave(pin, r) === null) await qc.refetchQueries({ queryKey: modulesKey })
      setPin((p) => pinAfterSave(p, r))
    },
    onError: (e, vars) => {
      if (e instanceof ApiError && e.code === 'conflict') {
        setDialog(null)
        setConflict(true)
        qc.invalidateQueries({ queryKey: modulesKey })
      } else if (e instanceof ApiError && e.code === 'confirm_required') {
        setDialog({ settings: vars.settings, impact: e.body?.impact })
      } else if (dialog) {
        setDialog({ ...dialog, error: errorMessage(e) })
      } else {
        toast.error(errorMessage(e))
      }
    },
  })

  const onDirtyChange = useCallback(
    (d: boolean) => {
      setDirty(d)
      // pinned when the form first becomes dirty, dropped when it is clean again
      setPin(d ? (cur) => cur ?? (m ? { version: m.version, settings: m.settings } : null) : null)
    },
    [m],
  )

  if (!admin) return <EmptyState icon={<ShieldAlert />} title={t.modules.adminOnly} />
  if (q.isPending) return <Skeleton className="h-64 w-full" />
  if (q.isError) return <EmptyState title={t.errors.generic} body={errorMessage(q.error)} />
  if (!m) {
    return (
      <EmptyState
        title={t.modules.notFound}
        action={
          <Button variant="outline" render={<Link to="/modules" />}>
            <ArrowLeft /> {t.modules.back}
          </Button>
        }
      />
    )
  }

  const latest: EditBase = { version: m.version, settings: m.settings }
  const base = editBase(pin, latest)
  const stale = changedElsewhere(pin, latest)
  // pause and resume save the settings too; with unsaved edits they would drop them
  const editing = dirty
  const loadLatest = async () => {
    await q.refetch()
    setConflict(false)
    setPin((p) => pinAfterLoadLatest(p, true))
  }
  const onSave = (settings: ModuleSettings) => {
    if (m.type === 'entra' && isRiskyChange(base.settings, settings)) {
      setDialog({ settings })
      previewSettings(name, settings).then(
        (impact) => setDialog((d) => (d ? { ...d, impact } : d)),
        (e) => setDialog((d) => (d ? { ...d, error: errorMessage(e) } : d)),
      )
      return
    }
    save.mutate({ settings, version: base.version })
  }
  const togglePause = () => save.mutate({ settings: cleanSettings({ ...m.settings, paused: m.paused ? undefined : true }), version: m.version })
  const colTitle = meta.collections.find((c) => c.name === m.collection)?.title ?? m.collection

  return (
    <div>
      <PageHeader
        eyebrow={
          <Link to="/modules" className="inline-flex items-center gap-1 hover:underline">
            <ArrowLeft className="size-3" /> {t.modules.back}
          </Link>
        }
        title={
          <span className="flex flex-wrap items-center gap-3">
            {m.name}
            <ModuleStatus module={m} />
          </span>
        }
        description={typeLabel(m.type)}
        actions={
          m.type !== '' && (
            <>
              {editing && <span className="text-xs text-muted-foreground">{t.modules.settings.finishEditing}</span>}
              <Button variant="outline" size="sm" disabled={save.isPending || meta.readOnly || !!m.runRequest || m.paused || editing} onClick={() => run.mutate(undefined, { onSuccess: () => toast.success(t.modules.runRequested), onError: (e) => toast.error(errorMessage(e)) })} title={editing ? t.modules.settings.finishEditing : m.paused ? t.modules.runNowPaused : undefined}>
                <PlayCircle /> {t.modules.runNow}
              </Button>
              <Button variant="outline" size="sm" disabled={save.isPending || meta.readOnly || editing} onClick={togglePause} title={editing ? t.modules.settings.finishEditing : undefined}>
                {m.paused ? <Play /> : <Pause />}
                {save.isPending ? (m.paused ? t.modules.resuming : t.modules.pausing) : m.paused ? t.modules.resume : t.modules.pause}
              </Button>
            </>
          )
        }
      />

      {m.runRequest && (
        <p role="status" className="mb-4 rounded-lg border bg-muted/40 px-3 py-2 text-sm">
          {t.modules.runPending(when(m.runRequest.requested))}
        </p>
      )}
      {m.status === 'failed' && m.lastRun && (
        <p role="alert" className="mb-4 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t.modules.statusHint.failed}{t.common.colon}{m.lastRun.error || '—'}
        </p>
      )}

      <Section title={t.modules.overview}>
        <dl className="grid gap-x-6 gap-y-4 rounded-xl border bg-card p-4 shadow-xs sm:grid-cols-2 lg:grid-cols-4">
          <Item label={t.modules.lastRun}>{m.lastRun ? `${when(m.lastRun.finished)}` : t.modules.never}</Item>
          <Item label={t.modules.lastOk}>{m.lastOk ? when(m.lastOk) : '—'}</Item>
          <Item label={t.modules.columns.next}>{nextText(m)}</Item>
          <Item label={t.modules.schedule}>
            <span className="font-mono text-xs">{m.schedule.times.join(', ')}</span> <span className="text-xs text-muted-foreground">{m.schedule.timezone}</span>
            {m.schedule.default && <Badge variant="outline" className="ml-2">{t.modules.scheduleDefault}</Badge>}
          </Item>
          <Item label={t.modules.columns.token}>
            <Link to="/admin/tokens" className="inline-flex items-center gap-1 font-mono text-xs hover:underline">
              <KeyRound className="size-3 text-muted-foreground" /> {m.token}
            </Link>
            {m.tokenStatus !== 'active' && (
              <Badge variant="destructive" className="ml-2">
                {t.modules.tokenState[m.tokenStatus]}
              </Badge>
            )}
          </Item>
          <Item label={t.modules.columns.target}>{m.readOnly ? t.modules.noCollection : t.modules.writesTo(colTitle ?? '')}</Item>
        </dl>
      </Section>

      <Section title={t.modules.settings.title} hint={t.modules.settings.subtitle}>
        {conflict && (
          <div role="alert" className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
            <div className="font-medium">{t.modules.settings.conflictTitle}</div>
            <p className="text-muted-foreground">{t.modules.settings.conflictBody}</p>
            <Button size="sm" variant="outline" className="mt-2" onClick={loadLatest}>
              {t.modules.settings.conflictLoad}
            </Button>
          </div>
        )}
        {stale && !conflict && (
          <div role="status" className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
            <div className="font-medium">{t.modules.settings.changedElsewhereTitle}</div>
            <p className="text-muted-foreground">{t.modules.settings.changedElsewhereBody}</p>
            <Button size="sm" variant="outline" className="mt-2" onClick={loadLatest}>
              {t.modules.settings.conflictLoad}
            </Button>
          </div>
        )}
        {m.type === '' ? (
          <p className="rounded-xl border bg-card p-4 text-sm text-muted-foreground shadow-xs">{t.modules.settings.noSettings}</p>
        ) : (
          <div className="rounded-xl border bg-card p-4 shadow-xs sm:p-5">
            <SettingsForm key={base.version} module={{ ...m, version: base.version, settings: base.settings }} onDirtyChange={onDirtyChange} saving={save.isPending && !dialog} readOnly={meta.readOnly} onSave={onSave} />
            <p className="mt-4 text-xs text-muted-foreground">{t.modules.settings.localOnly}</p>
          </div>
        )}
      </Section>

      <Section title={t.modules.runs} hint={t.modules.runsHint(m.runs.length)}>
        {m.runs.length === 0 ? (
          <p className="rounded-xl border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">{t.modules.noRuns}</p>
        ) : (
          <RunsTable m={m} />
        )}
      </Section>

      <ImpactDialog
        open={dialog !== null}
        impact={dialog?.impact}
        error={dialog?.error}
        saving={save.isPending}
        onCancel={() => setDialog(null)}
        onConfirm={() => dialog && save.mutate({ settings: dialog.settings, confirm: true, version: base.version })}
      />
    </div>
  )
}

function RunsTable({ m }: { m: ModuleView }) {
  return (
    <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
      <table className="w-full border-collapse text-sm">
        <thead className="bg-muted/60">
          <tr className="border-b text-left text-xs text-muted-foreground">
            {[t.modules.runCols.finished, t.modules.runCols.status, t.modules.runCols.result, t.modules.runCols.took, t.modules.runCols.error].map((h) => (
              <th key={h} className="h-9 px-4 font-semibold tracking-wide whitespace-nowrap">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {m.runs.map((r, i) => (
            <tr key={r.finished + i} className="border-b align-top last:border-0 even:bg-muted/25">
              <td className="px-4 py-2 whitespace-nowrap">{when(r.finished)}</td>
              <td className="px-4 py-2 whitespace-nowrap">
                <RunStatusBadge status={r.status} />
                {r.run_request && <span className="ml-2 text-xs text-muted-foreground">{t.modules.requestedRun}</span>}
              </td>
              <td className="px-4 py-2 whitespace-nowrap">{r.status === 'skipped' ? '—' : doneText(r, m.type)}</td>
              <td className="px-4 py-2 whitespace-nowrap tabular-nums">{r.status === 'skipped' ? '—' : took(r)}</td>
              <td className="max-w-md px-4 py-2 text-xs text-destructive">{r.status === 'failed' ? r.error : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
