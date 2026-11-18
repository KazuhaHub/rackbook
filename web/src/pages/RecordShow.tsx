import { useState } from 'react'
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
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { BackrefTable } from '@/components/BackrefTable'
import { CellValue } from '@/components/CellValue'
import { NotFound, PageHeader } from '@/components/common'
import { HistoryList } from '@/components/HistoryList'
import { t } from '@/i18n/zh-CN'
import { ApiError, errorMessage } from '@/lib/api'
import { useRefLookups } from '@/lib/hooks'
import { canEdit, fieldTitle, idFromPath, recordLabel, schemaProps } from '@/lib/ledger'
import type { Collection, RecordWithBackrefs } from '@/lib/types'
import { useAfterWrite, useCollection, useMeta } from '@/providers/meta'

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
  const { query, result } = useOne<RecordWithBackrefs>({
    resource: col.name,
    id,
    queryOptions: { retry: false },
  })
  const del = useDelete()

  const base = `/c/${encodeURIComponent(col.name)}`
  if (query.isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 w-full" />
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
  const extra = Object.keys(rec.data).filter((k) => !col.schema.properties?.[k])
  const backGroups = new Map<string, typeof col.backrefs>()
  for (const b of col.backrefs ?? []) backGroups.set(b.collection, [...(backGroups.get(b.collection) ?? []), b])

  const doDelete = () => {
    setDeleteError(null)
    del.mutate(
      { resource: col.name, id, values: { hash: rec.hash }, successNotification: false, errorNotification: false },
      {
        onSuccess: (res) => {
          setConfirm(false)
          toast.success(t.show.deleted((res.data as any)?.commit ?? ''))
          void afterWrite()
          navigate(base)
        },
        onError: (e) => setDeleteError(errorMessage(e)),
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
                      <CellValue value={rec.data[field]} lookup={lookups[field]} variant="detail" />
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

          {[...backGroups].map(([name, brs]) => {
            const other = byName.get(name)
            if (!other) return null
            return (
              <BackrefTable
                key={name}
                col={other}
                backrefs={brs ?? []}
                records={rec.backrefs?.[name] ?? []}
                parent={rec}
                editable={editable}
              />
            )
          })}
        </div>

        <div className="space-y-5">
          <Card>
            <CardHeader>
              <CardTitle>{t.show.history}</CardTitle>
            </CardHeader>
            <CardContent>
              <HistoryList collection={col.name} />
            </CardContent>
          </Card>
          <div className="rounded-xl border p-4 text-xs text-muted-foreground">
            <div className="flex justify-between gap-3 py-0.5">
              <span>{t.show.id}</span>
              <span className="min-w-0 truncate font-mono" title={rec.id}>{rec.id}</span>
            </div>
            <div className="flex justify-between gap-3 py-0.5">
              <span>{t.show.hash}</span>
              <span className="font-mono">{rec.hash}</span>
            </div>
          </div>
        </div>
      </div>

      <AlertDialog open={confirm} onOpenChange={setConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.show.deleteTitle}</AlertDialogTitle>
            <AlertDialogDescription>{t.show.deleteBody(label)}</AlertDialogDescription>
          </AlertDialogHeader>
          {deleteError && (
            <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{deleteError}</p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>{t.show.cancel}</AlertDialogCancel>
            <Button variant="destructive" disabled={del.mutation.isPending} onClick={doDelete}>
              {del.mutation.isPending ? t.show.deleting : t.show.deleteConfirm}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
