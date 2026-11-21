import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { toast } from 'sonner'
import { Check, ChevronRight, ShieldAlert, Trash2, Undo2 } from 'lucide-react'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsIndicator, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { EmptyState, NotFound, PageHeader } from '@/components/common'
import { BasicTab } from '@/components/types/BasicTab'
import { FieldDialog, type FieldFlags } from '@/components/types/FieldDialog'
import { FieldsTab } from '@/components/types/FieldsTab'
import { ImpactPanel, migKey } from '@/components/types/ImpactPanel'
import { PreviewTab } from '@/components/types/PreviewTab'
import { RelationsTab } from '@/components/types/RelationsTab'
import { RulesTab } from '@/components/types/RulesTab'
import { t } from '@/i18n'
import { collectionTitle } from '@/lib/labels'
import { ApiError, errorMessage } from '@/lib/api'
import { emptyType, stable, type FieldDef, type FieldType, type Migration, type Plan, type TypeDef } from '@/lib/typedef'
import { createType, deleteType, planType, updateType, useRefreshAll, useTypeDetail, useTypeList, type TypeDetail } from '@/lib/typesApi'
import { useAfterWrite, useMeta } from '@/providers/meta'
import { cn } from 'cn'

export default function TypeEditorPage({ mode }: { mode: 'create' | 'edit' }) {
  const { meta } = useMeta()
  const { name } = useParams()
  const admin = !!meta.user?.canAdmin
  const list = useTypeList(admin)
  const detail = useTypeDetail(mode === 'edit' && admin ? name : undefined)
  if (!admin) return <EmptyState icon={<ShieldAlert />} title={t.types.adminOnly} />
  if (!list.data || (mode === 'edit' && detail.isPending)) return <Skeleton className="h-96 w-full" />
  if (mode === 'edit') {
    if (detail.isError) {
      const missing = detail.error instanceof ApiError && detail.error.statusCode === 404
      return <NotFound title={missing ? t.notFound.recordTitle : t.errors.generic} body={errorMessage(detail.error)} backTo="/types" backLabel={t.types.backToList} />
    }
    return <Editor key={`${name}@${detail.dataUpdatedAt}`} detail={detail.data} dataDir={list.data.dataDir} schemaDir={list.data.schemaDir} />
  }
  return <Editor dataDir={list.data.dataDir} schemaDir={list.data.schemaDir} />
}

// A field name that is replaced (a new field being renamed) must follow into key, label, list, facets and rules.
function rename(d: TypeDef, from: string, to: string): TypeDef {
  if (from === to) return d
  const sw = (x: string) => (x === from ? to : x)
  return {
    ...d,
    key: d.key.map(sw),
    label: d.label ? sw(d.label) : d.label,
    list: d.list.map(sw),
    facets: d.facets.map((f) => ({ ...f, field: sw(f.field) })),
    unique: d.unique.map((u) => u.map(sw)),
  }
}

function dropField(d: TypeDef, name: string): TypeDef {
  return {
    ...d,
    fields: d.fields.filter((f) => f.name !== name),
    key: d.key.filter((k) => k !== name),
    label: d.label === name ? '' : d.label,
    list: d.list.filter((k) => k !== name),
    facets: d.facets.filter((f) => f.field !== name),
    unique: d.unique.map((u) => u.filter((k) => k !== name)).filter((u) => u.length >= 2),
  }
}

type DialogState = { key: number; initial: FieldDef | null; locked: boolean; preset?: FieldType }

function Editor({ detail, dataDir, schemaDir }: { detail?: TypeDetail; dataDir: string; schemaDir: string }) {
  const original = detail?.type
  const creating = !original
  const navigate = useNavigate()
  const afterWrite = useAfterWrite()
  const refresh = useRefreshAll()
  const [draft, setDraft] = useState<TypeDef>(() => original ?? emptyType())
  const [tab, setTab] = useState<string>('basic')
  const [step, setStep] = useState(0)
  const [chosen, setChosen] = useState<Migration[]>([])
  const [plan, setPlan] = useState<Plan>()
  const [planning, setPlanning] = useState(false)
  const [planError, setPlanError] = useState<string>()
  const [dialog, setDialog] = useState<DialogState>()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [removing, setRemoving] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string>()
  const [deleting, setDeleting] = useState(false)

  const update = (fn: (d: TypeDef) => TypeDef) => setDraft(fn)
  const dirty = creating || stable(draft) !== stable(original)
  const planName = original?.name ?? draft.name

  // The dry run follows every edit (debounced): the impact panel and the Save button read it.
  useEffect(() => {
    if (!dirty || !planName) return
    const ctl = new AbortController()
    const id = window.setTimeout(async () => {
      setPlanning(true)
      try {
        const p = await planType(planName, { type: draft, migrations: chosen }, ctl.signal)
        if (ctl.signal.aborted) return
        setPlan(p)
        setPlanError(undefined)
        // a migration that is no longer offered stops being chosen
        const still = chosen.filter((m) => p.migrations.some((o) => migKey(o) === migKey(m)))
        if (still.length !== chosen.length) setChosen(still)
      } catch (e) {
        if (!ctl.signal.aborted) setPlanError(errorMessage(e))
      } finally {
        if (!ctl.signal.aborted) setPlanning(false)
      }
    }, 350)
    return () => {
      window.clearTimeout(id)
      ctl.abort()
    }
  }, [draft, chosen, dirty, planName])

  const fresh = !planning && !planError
  const canSave = dirty && !!plan && plan.clean && plan.changed && fresh && !saving

  const flagsFor = (name: string): FieldFlags => ({ list: draft.list.includes(name), facet: draft.facets.some((f) => f.field === name) })

  const openField = (name: string | null, preset?: FieldType) => {
    const initial = name ? (draft.fields.find((f) => f.name === name) ?? null) : null
    setDialog({ key: Date.now(), initial, locked: !!name && !!original?.fields.some((f) => f.name === name), preset })
    setDialogOpen(true)
  }

  const saveField = (f: FieldDef, fl: FieldFlags) => {
    const was = dialog?.initial?.name
    update((d0) => {
      let d = was && was !== f.name ? rename(d0, was, f.name) : d0
      const idx = was ? d.fields.findIndex((x) => x.name === was) : -1
      const fields = idx >= 0 ? d.fields.map((x, i) => (i === idx ? f : x)) : [...d.fields, f]
      const list = fl.list ? (d.list.includes(f.name) ? d.list : [...d.list, f.name]) : d.list.filter((x) => x !== f.name)
      const hasFacet = d.facets.some((x) => x.field === f.name)
      const facets = fl.facet ? (hasFacet ? d.facets : [...d.facets, { field: f.name, match: 'exact' as const, values: [] }]) : d.facets.filter((x) => x.field !== f.name)
      d = { ...d, fields, list, facets }
      return d
    })
  }

  const save = async () => {
    setSaving(true)
    setSaveError(undefined)
    try {
      const res = creating ? await createType(draft) : await updateType(original.name, draft, chosen)
      toast.success(creating ? t.types.wizard.created(res.commit) : t.types.saved(res.commit))
      await afterWrite()
      navigate(`/types/${encodeURIComponent(draft.name)}`, { replace: true })
    } catch (e) {
      if (e instanceof ApiError && e.code === 'refused' && e.body?.plan) setPlan(e.body.plan as Plan)
      if (e instanceof ApiError && e.code === 'conflict') {
        // Somebody changed the type first: refresh what we compare against, and make the user look at it.
        refresh()
        setSaveError(t.types.stale)
      } else {
        setSaveError(errorMessage(e))
      }
    } finally {
      setSaving(false)
    }
  }

  const stepOk = [!!draft.name && !!draft.title, draft.fields.length > 0, true]
  const stepHint = [t.types.wizard.needName, t.types.wizard.needFields, '']

  const header = (
    <PageHeader
      eyebrow={
        <span className="flex items-center gap-1">
          <Link to="/types" className="hover:text-foreground hover:underline">
            {t.types.backToList}
          </Link>
          <ChevronRight className="size-3" />
        </span>
      }
      title={creating ? t.types.wizard.title : collectionTitle(draft)}
      description={creating ? undefined : <span className="font-mono text-xs">{draft.name} · {draft.file}{draft.path ? `:${draft.path}` : ''}</span>}
      actions={
        !creating && (
          <>
            {dirty && (
              <Button variant="outline" onClick={() => { setDraft(original); setChosen([]); setPlan(undefined); setSaveError(undefined) }}>
                <Undo2 /> {t.types.discard}
              </Button>
            )}
            <Button disabled={!canSave} onClick={save}>
              <Check /> {saving ? t.types.saving : t.types.save}
            </Button>
          </>
        )
      }
    />
  )

  const tabsBody = {
    basic: <BasicTab draft={draft} update={update} creating={creating} dataDir={dataDir} schemaDir={schemaDir} />,
    fields: (
      <FieldsTab draft={draft} update={update} onEdit={(n) => openField(n)} onAdd={() => openField(null)} onRemove={(n) => setRemoving(n)} />
    ),
    relations: <RelationsTab draft={draft} incoming={detail?.incoming ?? []} onEdit={(n) => openField(n)} onAddRef={() => openField(null, 'ref')} />,
    rules: <RulesTab draft={draft} update={update} />,
    preview: <PreviewTab plan={dirty ? plan : undefined} planning={planning} />,
  }

  const impact = (
    <ImpactPanel
      plan={dirty ? plan : undefined}
      planning={planning}
      error={planError}
      unchanged={!dirty}
      chosen={chosen}
      onChoose={setChosen}
      onViewFiles={creating ? undefined : () => setTab('preview')}
    />
  )

  return (
    <div>
      {header}
      <div className="grid grid-cols-[minmax(0,1fr)] items-start gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0">
          {creating ? (
            <Wizard step={step} setStep={setStep} stepOk={stepOk} stepHint={stepHint} canCreate={canSave} saving={saving} onCreate={save} saveError={saveError}>
              {step === 0 && tabsBody.basic}
              {step === 1 && tabsBody.fields}
              {step === 2 && (
                <div className="space-y-4">
                  <p className="text-sm text-muted-foreground">{t.types.wizard.willCreate}</p>
                  {tabsBody.preview}
                  <p className="text-xs text-muted-foreground">{t.types.wizard.firstRecordHint}</p>
                </div>
              )}
            </Wizard>
          ) : (
            <Tabs value={tab} onValueChange={(v) => setTab(String(v))}>
              <TabsList>
                <TabsIndicator />
                {(['basic', 'fields', 'relations', 'rules', 'preview'] as const).map((k) => (
                  <TabsTrigger key={k} value={k}>
                    {t.types.tabs[k]}
                  </TabsTrigger>
                ))}
              </TabsList>
              {(['basic', 'fields', 'relations', 'rules', 'preview'] as const).map((k) => (
                <TabsContent key={k} value={k} className="rb-page">
                  {tabsBody[k]}
                </TabsContent>
              ))}
              {saveError && <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{saveError}</p>}
              <div className="border-t pt-5">
                <Button variant="outline" className="text-destructive hover:text-destructive" onClick={() => setDeleting(true)}>
                  <Trash2 /> {t.types.delete.button}
                </Button>
              </div>
            </Tabs>
          )}
        </div>
        <div className="xl:sticky xl:top-20">{impact}</div>
      </div>

      {dialog && (
        <FieldDialog
          key={dialog.key}
          open={dialogOpen}
          onOpenChange={setDialogOpen}
          initial={dialog.initial}
          locked={dialog.locked}
          presetType={dialog.preset}
          draft={draft}
          flags={dialog.initial ? flagsFor(dialog.initial.name) : { list: false, facet: false }}
          onSave={saveField}
        />
      )}

      <AlertDialog open={removing !== null} onOpenChange={(o) => !o && setRemoving(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.types.fields.removeConfirmTitle(removing ?? '')}</AlertDialogTitle>
            <AlertDialogDescription>{t.types.fields.removeConfirmBody}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.types.dialog.cancel}</AlertDialogCancel>
            <Button
              variant="destructive"
              onClick={() => {
                if (removing) update((d) => dropField(d, removing))
                setRemoving(null)
              }}
            >
              {t.types.fields.confirm}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {original && <DeleteDialog name={original.name} version={original.version} open={deleting} onOpenChange={setDeleting} />}
    </div>
  )
}

function Wizard({
  step,
  setStep,
  stepOk,
  stepHint,
  canCreate,
  saving,
  onCreate,
  saveError,
  children,
}: {
  step: number
  setStep: (n: number) => void
  stepOk: boolean[]
  stepHint: string[]
  canCreate: boolean
  saving: boolean
  onCreate: () => void
  saveError?: string
  children: React.ReactNode
}) {
  const steps = t.types.wizard.steps
  return (
    <div className="space-y-6">
      <ol className="flex flex-wrap items-center gap-2 text-sm">
        {steps.map((s, i) => (
          <li key={s} className="flex items-center gap-2">
            <span
              className={cn(
                'flex size-6 items-center justify-center rounded-full border text-xs font-medium',
                i < step && 'border-brand bg-brand text-white',
                i === step && 'border-brand text-brand',
                i > step && 'text-muted-foreground',
              )}
            >
              {i < step ? <Check className="size-3.5" /> : i + 1}
            </span>
            <span className={cn(i === step ? 'font-medium' : 'text-muted-foreground')}>{s}</span>
            {i < steps.length - 1 && <ChevronRight className="size-3.5 text-muted-foreground" />}
          </li>
        ))}
      </ol>
      <div key={step} className="rb-page">
        {children}
      </div>
      {saveError && <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{saveError}</p>}
      <div className="flex items-center gap-2 border-t pt-4">
        {step > 0 && (
          <Button variant="outline" onClick={() => setStep(step - 1)}>
            {t.types.wizard.back}
          </Button>
        )}
        {step < steps.length - 1 ? (
          <Button disabled={!stepOk[step]} title={stepOk[step] ? undefined : stepHint[step]} onClick={() => setStep(step + 1)}>
            {t.types.wizard.next}
          </Button>
        ) : (
          <Button disabled={!canCreate} onClick={onCreate}>
            {saving ? t.types.wizard.creating : t.types.wizard.create}
          </Button>
        )}
        {!stepOk[step] && <span className="text-xs text-muted-foreground">{stepHint[step]}</span>}
      </div>
    </div>
  )
}

function DeleteDialog({ name, version, open, onOpenChange }: { name: string; version?: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate()
  const afterWrite = useAfterWrite()
  const [plan, setPlan] = useState<Plan>()
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    const ctl = new AbortController()
    planType(name, { delete: true, version }, ctl.signal)
      .then((p) => !ctl.signal.aborted && setPlan(p))
      .catch((e) => !ctl.signal.aborted && setError(errorMessage(e)))
    return () => {
      ctl.abort()
      setPlan(undefined)
      setError(undefined)
    }
  }, [open, name, version])

  const go = async () => {
    setBusy(true)
    try {
      const res = await deleteType(name, version)
      toast.success(t.types.delete.done(res.commit))
      await afterWrite()
      navigate('/types', { replace: true })
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }
  const refusals = useMemo(() => plan?.refusals ?? [], [plan])
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{t.types.delete.title(name)}</AlertDialogTitle>
          <AlertDialogDescription>{t.types.delete.body}</AlertDialogDescription>
        </AlertDialogHeader>
        {!plan && !error && <p className="text-sm text-muted-foreground">{t.types.delete.planning}</p>}
        {refusals.length > 0 && (
          <div className="space-y-1.5 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
            <p className="font-medium">{t.types.delete.refused}</p>
            <ul className="list-disc pl-4">
              {refusals.map((r, i) => (
                <li key={i}>{r.message}</li>
              ))}
            </ul>
          </div>
        )}
        {error && <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}
        <AlertDialogFooter>
          <AlertDialogCancel>{t.types.dialog.cancel}</AlertDialogCancel>
          <Button variant="destructive" disabled={!plan?.clean || busy} onClick={go}>
            {t.types.delete.confirm}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
