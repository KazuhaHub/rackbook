import { useEffect, useRef, useState } from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router'
import { useDelete, useOne } from '@refinedev/core'
import { toast } from 'sonner'
import { ChevronRight, Pencil, Trash2 } from 'lucide-react'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsIndicator, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { BackrefTable } from '@/components/BackrefTable'
import { CollectionIcon } from '@/components/CollectionIcon'
import { CellValue } from '@/components/CellValue'
import { NotFound, PageHeader } from '@/components/common'
import { HistoryList } from '@/components/HistoryList'
import { t } from '@/i18n/zh-CN'
import { ApiError, errorMessage } from '@/lib/api'
import { pickTab, splitGeneric, tabHash, type GenericRule } from '@/lib/backrefs'
import { useRefLookups } from '@/lib/hooks'
import { canEdit, fieldTitle, idFromPath, recordHref, recordLabel, schemaProps, sourceLabel, str } from '@/lib/ledger'
import { displayId } from '@/lib/recordId'
import type { Backref, Collection, LedgerRecord, RecordWithBackrefs } from '@/lib/types'
import { useAfterWrite, useCollection, useMeta } from '@/providers/meta'

type BackTab = { key: string; col: Collection; backrefs: Backref[]; records: LedgerRecord[]; label: string; generic: boolean }

export default function RecordShow() {
  const { collection } = useParams()
  const id = idFromPath(useLocation().pathname)
  const col = useCollection(collection)
  if (!col || id === undefined) return <NotFound />
  return <Show key={col.name + '/' + id} col={col} id={id} />
}

function Show({ col, id }: { col: Collection; id: string }) {
  const { meta, byName } = useMeta()
  const navigate = useNavigate()
  const afterWrite = useAfterWrite()
  const lookups = useRefLookups(col)
  const editable = canEdit(meta)
  const [confirm, setConfirm] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [blockedBy, setBlockedBy] = useState<{ collection: string; id: string; field: string }[]>([])
  const { query, result } = useOne<RecordWithBackrefs>({
    resource: col.name,
    id,
    queryOptions: { retry: false },
  })
  const del = useDelete()
  const { hash } = useLocation()
  const tabScroller = useRef<HTMLDivElement>(null)

  // keep the selected tab in view when the tab bar scrolls sideways (a shared link may name a tab off screen)
  useEffect(() => {
    const box = tabScroller.current
    const el = box?.querySelector<HTMLElement>('[role="tab"][data-active]')
    if (box && el) box.scrollLeft = Math.max(0, el.offsetLeft - (box.clientWidth - el.offsetWidth) / 2)
  }, [hash, query.isLoading])

  const base = `/c/${encodeURIComponent(col.name)}`
  if (query.isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-9 w-72" />
        <Skeleton className="h-40 w-full" />
      </div>
    )
  }
  if (query.isError || !result) {
    const notFound = query.error instanceof ApiError && query.error.statusCode === 404
    return notFound || !query.error ? (
      <NotFound title={t.notFound.recordTitle} body={t.notFound.recordBody} backTo={base} backLabel={t.notFound.backToList} />
    ) : (
      <NotFound title={t.errors.generic} body={errorMessage(query.error)} backTo={base} backLabel={t.notFound.backToList} />
    )
  }

  const rec = result
  const label = recordLabel(col, rec)
  const props = schemaProps(col)
  const showSource = 'source' in (col.schema.properties ?? {}) || rec.data.source !== undefined
  const extra = Object.keys(rec.data).filter((k) => !col.schema.properties?.[k])
  const backGroups = new Map<string, Backref[]>()
  for (const b of col.backrefs ?? []) backGroups.set(b.collection, [...(backGroups.get(b.collection) ?? []), b])

  // One tab per collection that references this record; the records that apply to every record
  // (a reference field holding an allowed literal such as "all") get their own tab after them.
  const own: BackTab[] = []
  const general: BackTab[] = []
  for (const [name, brs] of backGroups) {
    const other = byName.get(name)
    if (!other) continue
    const rules: GenericRule[] = []
    for (const b of brs) {
      const ref = (other.refs ?? []).find((x) => x.field === b.field)
      if (ref) rules.push({ field: b.field, allow: ref.allow ?? [], parentValue: str(rec.data[ref.toField]) })
    }
    const split = splitGeneric(rec.backrefs?.[name] ?? [], rules)
    const title = brs.find((b) => b.title)?.title || other.title
    if (split.own.length > 0 || split.generic.length === 0 || editable) {
      own.push({ key: tabHash({ collection: name, generic: false }).slice(1), col: other, backrefs: brs, records: split.own, label: title, generic: false })
    }
    if (split.generic.length > 0) {
      general.push({ key: tabHash({ collection: name, generic: true }).slice(1), col: other, backrefs: brs, records: split.generic, label: t.show.genericTab(title), generic: true })
    }
  }
  const tabs = [...own, ...general]
  const active = tabs[pickTab(hash, tabs.map((x) => ({ collection: x.col.name, generic: x.generic })))]

  const doDelete = (clearReferences = false) => {
    setDeleteError(null)
    del.mutate(
      { resource: col.name, id, values: { hash: rec.hash, clearReferences }, successNotification: false, errorNotification: false },
      {
        onSuccess: (res) => {
          setConfirm(false)
          toast.success(t.show.deleted((res.data as any)?.commit ?? ''))
          void afterWrite()
          navigate(base)
        },
        onError: (e) => {
          const err = e as unknown
          // still referenced: list who points at it and offer to clear those references in the same commit
          if (err instanceof ApiError && err.code === 'referenced') setBlockedBy(err.body?.references ?? [])
          setDeleteError(errorMessage(e))
        },
      },
    )
  }

  return (
    <div>
      <PageHeader
        eyebrow={
          <span className="flex items-center gap-1">
            <Link to={base} className="hover:text-foreground hover:underline">
              {col.title}
            </Link>
            <ChevronRight className="size-3" />
          </span>
        }
        title={label}
        actions={
          editable && (
            <>
              <Button variant="outline" render={<Link to={`${base}/${encodeURIComponent(id)}/edit`} />}>
                <Pencil /> {t.show.edit}
              </Button>
              <Button variant="destructive" onClick={() => setConfirm(true)}>
                <Trash2 /> {t.show.delete}
              </Button>
            </>
          )
        }
      />

      <div className="grid grid-cols-[minmax(0,1fr)] gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-5">
          <Card>
            <CardHeader>
              <CardTitle>{t.show.fields}</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-x-8 gap-y-5 sm:grid-cols-[minmax(7rem,12rem)_minmax(0,1fr)]">
                {props.map(([field, schema]) => (
                  <div key={field} className="contents">
                    <dt className="text-sm text-muted-foreground" title={schema.description || field}>
                      {fieldTitle(col, field)}
                    </dt>
                    <dd className="min-w-0 text-sm">
                      <CellValue value={rec.data[field]} lookup={lookups[field]} variant="detail" schema={schema} />
                    </dd>
                  </div>
                ))}
                {extra.map((field) => (
                  <div key={field} className="contents">
                    <dt className="font-mono text-xs text-muted-foreground" title={t.show.extraFields}>
                      {field}
                    </dt>
                    <dd className="min-w-0 text-sm">
                      <CellValue value={rec.data[field]} variant="detail" />
                    </dd>
                  </div>
                ))}
              </dl>
            </CardContent>
          </Card>

        </div>

        <div className="space-y-5">
          <Card>
            <CardHeader>
              <CardTitle>{t.show.historyRecord}</CardTitle>
            </CardHeader>
            <CardContent>
              <HistoryList collection={col.name} recordId={id} />
            </CardContent>
          </Card>
          <div className="rounded-xl border p-4 text-xs text-muted-foreground">
            {showSource && (
              <div className="flex items-center justify-between gap-3 py-0.5">
                <span>{t.expiring.source}</span>
                <Badge variant="outline">{sourceLabel(rec.data.source)}</Badge>
              </div>
            )}
            <div className="flex justify-between gap-3 py-0.5">
              <span>{t.show.id}</span>
              <span className="min-w-0 truncate font-mono" title={displayId(rec.id)}>{displayId(rec.id)}</span>
            </div>
            <div className="flex justify-between gap-3 py-0.5">
              <span>{t.show.hash}</span>
              <span className="font-mono">{rec.hash}</span>
            </div>
          </div>
        </div>
      </div>

      {active && (
        <Card className="mt-5">
          <CardContent>
            <Tabs value={active.key} onValueChange={(v) => navigate({ hash: '#' + String(v) }, { replace: true })}>
              <div ref={tabScroller} className="-mx-1 overflow-x-auto px-1 pb-1">
                <TabsList className="w-max">
                  <TabsIndicator />
                  {tabs.map((x) => (
                    <TabsTrigger key={x.key} value={x.key}>
                      {!x.generic && <CollectionIcon col={x.col} className="size-4 text-muted-foreground" />}
                      {x.label}
                      <Badge variant="secondary" className="px-1.5 tabular-nums">
                        {x.records.length}
                      </Badge>
                    </TabsTrigger>
                  ))}
                </TabsList>
              </div>
              <TabsContent value={active.key}>
                <BackrefTable
                  key={active.key}
                  col={active.col}
                  backrefs={active.backrefs}
                  records={active.records}
                  parent={rec}
                  editable={editable}
                  generic={active.generic}
                  onChanged={() => void query.refetch()}
                />
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      )}

      <AlertDialog
        open={confirm}
        onOpenChange={(o) => {
          setConfirm(o)
          if (!o) {
            setBlockedBy([])
            setDeleteError(null)
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.show.deleteTitle}</AlertDialogTitle>
            <AlertDialogDescription>{t.show.deleteBody(label)}</AlertDialogDescription>
          </AlertDialogHeader>
          {deleteError && (
            <div className="space-y-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
              <p>{blockedBy.length ? t.refs.deleteBlockedTitle : deleteError}</p>
              {blockedBy.length > 0 && (
                <>
                  <p className="text-xs text-foreground/80">{t.refs.deleteBlockedBody}</p>
                  <ul className="max-h-40 space-y-1 overflow-y-auto text-xs">
                    {blockedBy.map((r) => (
                      <li key={`${r.collection}/${r.id}/${r.field}`}>
                        <Link to={recordHref(r.collection, r.id)} className="font-mono text-brand hover:underline" onClick={() => setConfirm(false)}>
                          {byName.get(r.collection)?.title ?? r.collection} · {displayId(r.id)}
                        </Link>
                        <span className="text-muted-foreground"> （{fieldTitle(byName.get(r.collection) ?? col, r.field)}）</span>
                      </li>
                    ))}
                  </ul>
                  <p className="text-xs text-muted-foreground">{t.refs.clearHint}</p>
                </>
              )}
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>{t.show.cancel}</AlertDialogCancel>
            {blockedBy.length > 0 ? (
              <Button variant="destructive" disabled={del.mutation.isPending} onClick={() => doDelete(true)}>
                {del.mutation.isPending ? t.show.deleting : t.refs.clearAndDelete}
              </Button>
            ) : (
              <Button variant="destructive" disabled={del.mutation.isPending} onClick={() => doDelete()}>
                {del.mutation.isPending ? t.show.deleting : t.show.deleteConfirm}
              </Button>
            )}
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
