import { useRef, useState } from 'react'
import { Link, useLocation, useNavigate, useParams, useSearchParams } from 'react-router'
import { useCreate, useOne, useUpdate } from '@refinedev/core'
import { toast } from 'sonner'
import { AlertTriangle, ChevronRight, Lock, Save } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { NotFound, PageHeader } from '@/components/common'
import { RecordForm } from '@/components/RecordForm'
import type { RestoreDraft } from '@/components/RestoreDialog'
import { t } from '@/i18n'
import { ApiError, errorMessage } from '@/lib/api'
import { canEdit, fieldTitle, idFromPath, moduleFor, pointerToPath, recordHref, recordLabel, schemaProps, str } from '@/lib/ledger'
import type { CheckError, Collection, LedgerRecord } from '@/lib/types'
import { useAfterWrite, useCollection, useMeta } from '@/providers/meta'
import { issueText } from '@/lib/issues'
import { displayId } from '@/lib/recordId'
import { shortHash } from '@/lib/versionValue'
import { collectionDescription, collectionTitle, collectionTitleOf } from '@/lib/labels'

export default function RecordFormPage({ mode }: { mode: 'create' | 'edit' }) {
  const { collection } = useParams()
  const id = idFromPath(useLocation().pathname)
  const col = useCollection(collection)
  const { meta } = useMeta()
  if (!col) return <NotFound />
  const base = `/c/${encodeURIComponent(col.name)}`
  if (!canEdit(meta)) {
    return (
      <div>
        <PageHeader title={collectionTitle(col)} />
        <Alert>
          <Lock />
          <AlertTitle>{t.user.readOnly}</AlertTitle>
          <AlertDescription>{t.form.readOnlyBlocked}</AlertDescription>
        </Alert>
        <Button variant="outline" className="mt-4" render={<Link to={base} />}>
          {t.notFound.backToList}
        </Button>
      </div>
    )
  }
  if (mode === 'create') return <Editor key="new" col={col} mode="create" />
  return <EditLoader key={col.name + '/' + id} col={col} id={id ?? ''} />
}

function EditLoader({ col, id }: { col: Collection; id: string }) {
  const { query, result } = useOne<LedgerRecord>({ resource: col.name, id, queryOptions: { retry: false } })
  const base = `/c/${encodeURIComponent(col.name)}`
  if (query.isLoading) return <Skeleton className="h-64 w-full" />
  if (!result) {
    return (
      <NotFound title={t.notFound.recordTitle} body={t.notFound.recordBody} backTo={base} backLabel={t.notFound.backToList} />
    )
  }
  return <Editor col={col} mode="edit" id={id} initial={result} />
}

function ConflictPanel({
  err,
  col,
  mode,
  onReload,
  onKeepMine,
}: {
  err: ApiError
  col: Collection
  mode: 'create' | 'edit'
  onReload: () => void
  onKeepMine: () => void
}) {
  const cur = err.current
  const text = cur === null ? t.errors.conflictDeleted : mode === 'create' ? t.errors.conflictExists : t.errors.conflictChanged
  return (
    <Alert variant="destructive" className="mb-4">
      <AlertTriangle />
      <AlertTitle>{t.errors.conflictTitle}</AlertTitle>
      <AlertDescription>
        <p>{text}</p>
        {cur && (
          <div className="mt-3 rounded-md border bg-background/60 p-3 text-foreground">
            <div className="mb-1 text-xs font-medium text-muted-foreground">{t.errors.currentVersion}</div>
            <dl className="grid grid-cols-[minmax(5rem,9rem)_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
              {schemaProps(col)
                .filter(([k]) => cur.data[k] !== undefined)
                .map(([k]) => (
                  <div key={k} className="contents">
                    <dt className="text-muted-foreground">{fieldTitle(col, k)}</dt>
                    <dd className="break-words">{str(cur.data[k])}</dd>
                  </div>
                ))}
            </dl>
          </div>
        )}
        <div className="mt-3 flex flex-wrap gap-2">
          {cur && mode === 'edit' && (
            <>
              <Button size="sm" variant="outline" onClick={onReload}>
                {t.errors.reload}
              </Button>
              <Button size="sm" variant="outline" onClick={onKeepMine}>
                {t.errors.overwrite}
              </Button>
            </>
          )}
          {cur && mode === 'create' && (
            <Button size="sm" variant="outline" render={<Link to={recordHref(col.name, cur.id)} />}>
              {recordLabel(col, cur)}
            </Button>
          )}
        </div>
      </AlertDescription>
    </Alert>
  )
}

function Editor({
  col,
  mode,
  id,
  initial,
}: {
  col: Collection
  mode: 'create' | 'edit'
  id?: string
  initial?: LedgerRecord
}) {
  const navigate = useNavigate()
  const afterWrite = useAfterWrite()
  const { meta, byName } = useMeta()
  const managedBy = mode === 'edit' ? moduleFor(meta, col.name, initial?.data.source) : undefined
  const [sp] = useSearchParams()
  // a version that could not be restored as it is arrives here to be fixed and saved as an ordinary edit
  const restore = (useLocation().state as { restore?: RestoreDraft } | null)?.restore
  const [data, setData] = useState<Record<string, unknown>>(() => {
    if (restore) return structuredClone(restore.data)
    if (initial) return structuredClone(initial.data)
    // ?field=value pre-fills a new record (used by "add related" on a detail page)
    const pre: Record<string, unknown> = {}
    for (const [k, v] of sp) if (col.schema.properties?.[k]) pre[k] = v
    return pre
  })
  const [hash, setHash] = useState(initial?.hash ?? '')
  const [serverErrors, setServerErrors] = useState<CheckError[]>(() => restore?.issues ?? [])
  // the problems of an old version, shown before anything was sent
  const [fromRestore, setFromRestore] = useState(() => !!restore?.issues?.length)
  const [conflict, setConflict] = useState<ApiError | null>(null)
  const [banner, setBanner] = useState<string | null>(null)
  // the server held the write: it looks like a secret (heuristic); the editor may confirm it is not
  const [suspected, setSuspected] = useState(false)
  const [notSecret, setNotSecret] = useState(false)
  const [clientInvalid, setClientInvalid] = useState<string[] | null>(null)
  const alertsRef = useRef<HTMLDivElement>(null)
  const showAlerts = () => requestAnimationFrame(() => alertsRef.current?.scrollIntoView({ block: 'center', behavior: 'smooth' }))
  const create = useCreate()
  const update = useUpdate()
  const pending = create.mutation.isPending || update.mutation.isPending
  const base = `/c/${encodeURIComponent(col.name)}`
  const cancelTo = mode === 'edit' && id !== undefined ? `${base}/${encodeURIComponent(id)}` : base

  const onDone = (res: any) => {
    const r = res.data as { id: string; commit?: string }
    toast.success(mode === 'create' ? t.form.created(r.commit ?? '') : t.form.saved(r.commit ?? ''))
    void afterWrite()
    navigate(recordHref(col.name, r.id))
  }
  const onError = (e: unknown) => {
    setServerErrors([])
    setConflict(null)
    setBanner(null)
    setSuspected(false)
    showAlerts()
    if (e instanceof ApiError) {
      if (e.code === 'secret_suspected') setSuspected(true)
      if (e.statusCode === 422) return setServerErrors(e.errors.length ? e.errors : [{ message: e.message }])
      if (e.statusCode === 409) return setConflict(e)
    }
    setBanner(errorMessage(e))
  }

  const submit = (d: Record<string, unknown>) => {
    setFromRestore(false)
    setClientInvalid(null)
    setServerErrors([])
    setConflict(null)
    setBanner(null)
    const opts = { successNotification: false as const, errorNotification: false as const }
    if (mode === 'create') {
      create.mutate({ resource: col.name, values: { data: d, ...(notSecret ? { confirm_not_secret: true } : {}) }, ...opts }, { onSuccess: onDone, onError })
    } else {
      update.mutate({ resource: col.name, id: id!, values: { data: d, hash, ...(notSecret ? { confirm_not_secret: true } : {}) }, ...opts }, { onSuccess: onDone, onError })
    }
  }

  const title = mode === 'create' ? t.form.createTitle(collectionTitle(col)) : t.form.editTitle(initial ? recordLabel(col, initial) : collectionTitle(col))

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader
        eyebrow={
          <span className="flex items-center gap-1">
            <Link to={base} className="hover:text-foreground hover:underline">
              {collectionTitle(col)}
            </Link>
            <ChevronRight className="size-3" />
          </span>
        }
        title={title}
        description={collectionDescription(col)}
      />

      {managedBy && (
        <Alert className="mb-4">
          <AlertTriangle />
          <AlertTitle>{t.expiryForm.moduleTitle}</AlertTitle>
          <AlertDescription>
            {t.expiryForm.moduleBody(managedBy.name, managedBy.fields.map((f) => fieldTitle(col, f)).join(t.common.listSep))}
          </AlertDescription>
        </Alert>
      )}
      {restore && (
        <Alert className="mb-4">
          <AlertTriangle />
          <AlertTitle>{t.history.needsEditTitle}</AlertTitle>
          <AlertDescription>
            <p>{t.history.needsEdit(shortHash(restore.commit))}</p>
            {restore.hidden > 0 && <p className="mt-1">{t.history.needsEditHidden(restore.hidden)}</p>}
          </AlertDescription>
        </Alert>
      )}
      <div ref={alertsRef} className="scroll-mt-20" />
      {conflict && (
        <ConflictPanel
          err={conflict}
          col={col}
          mode={mode}
          onReload={() => {
            if (conflict.current) {
              setData(structuredClone(conflict.current.data))
              setHash(conflict.current.hash)
            }
            setConflict(null)
          }}
          onKeepMine={() => {
            if (conflict.current) setHash(conflict.current.hash)
            setConflict(null)
          }}
        />
      )}
      {banner && (
        <Alert variant="destructive" className="mb-4">
          <AlertTriangle />
          <AlertTitle>{t.errors.generic}</AlertTitle>
          <AlertDescription>{banner}</AlertDescription>
        </Alert>
      )}
      {serverErrors.length > 0 && (
        <Alert variant="destructive" className="mb-4">
          <AlertTriangle />
          <AlertTitle>{suspected ? t.errors.suspectedTitle : fromRestore ? t.history.issuesTitle : t.errors.summaryTitle}</AlertTitle>
          <AlertDescription>
            <p>{suspected ? t.errors.suspectedBody : fromRestore ? t.history.issuesBody : t.errors.summaryBody}</p>
            {suspected && (
              <div className="mt-2 flex items-center gap-2">
                <Checkbox id="not-a-secret" checked={notSecret} onCheckedChange={(v) => setNotSecret(v === true)} />
                <Label htmlFor="not-a-secret">{t.errors.notASecret}</Label>
              </div>
            )}
            <ul className="mt-2 list-disc space-y-0.5 pl-5">
              {serverErrors.map((e, i) => {
                const own = !e.collection || e.collection === col.name
                const other = e.collection ? byName.get(e.collection) : undefined
                const f = own ? pointerToPath(e.path)[0] : undefined
                return (
                  <li key={i}>
                    {!own && (
                      <span className="font-medium">
                        {collectionTitleOf(other, e.collection ?? '')}
                        {e.id ? ` ${displayId(e.id)}` : ''}{t.common.colon}
                      </span>
                    )}
                    {f && <span className="font-medium">{fieldTitle(col, f)}{t.common.colon}</span>}
                    {issueText(e, meta.collections)}
                  </li>
                )
              })}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {clientInvalid && (
        <Alert variant="destructive" className="mb-4">
          <AlertTriangle />
          <AlertDescription>
            <p>{t.form.clientInvalid}</p>
            {clientInvalid.length > 0 && (
              <ul className="mt-2 list-disc space-y-0.5 pl-5">
                {clientInvalid.map((m, i) => (
                  <li key={i}>{m}</li>
                ))}
              </ul>
            )}
          </AlertDescription>
        </Alert>
      )}

      <Card className="rb-form">
        <CardContent>
          <RecordForm
            col={col}
            formId="rb-record-form"
            formData={data}
            onChange={setData}
            onSubmit={submit}
            onInvalid={(messages) => {
              setClientInvalid(messages)
              showAlerts()
            }}
            serverErrors={serverErrors}
            disabled={pending}
          />
        </CardContent>
      </Card>

      <div className="sticky bottom-0 z-20 -mx-4 mt-4 flex items-center justify-end gap-2 border-t bg-background/90 px-4 py-3 backdrop-blur sm:-mx-6 sm:px-6">
        <Button variant="ghost" render={<Link to={cancelTo} />}>
          {t.form.cancel}
        </Button>
        <Button type="submit" form="rb-record-form" disabled={pending}>
          <Save /> {pending ? t.form.saving : t.form.save}
        </Button>
      </div>
    </div>
  )
}
