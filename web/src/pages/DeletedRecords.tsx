import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { ArchiveRestore, ChevronDown, ChevronRight, RotateCcw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { CellValue } from '@/components/CellValue'
import { VerifiedBadge, Who } from '@/components/CommitWho'
import { EmptyState, NotFound, PageHeader } from '@/components/common'
import { RestoreDialog } from '@/components/RestoreDialog'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { errorMessage } from '@/lib/api'
import { useDeleted, useVersionDetail, type DeletedItem } from '@/lib/history'
import { canEdit, fieldTitle, relativeTime, schemaProps } from '@/lib/ledger'
import { collectionTitle } from '@/lib/labels'
import { displayId } from '@/lib/recordId'
import { shortHash } from '@/lib/versionValue'
import type { Collection } from '@/lib/types'
import { useCollection, useMeta } from '@/providers/meta'

/** The last version of a deleted record, opened. */
function LastVersion({ col, item }: { col: Collection; item: DeletedItem }) {
  const q = useVersionDetail(col.name, item.id, item.last)
  if (q.isPending) return <Skeleton className="h-16 w-full" />
  if (q.isError) return <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{errorMessage(q.error)}</p>
  const data = q.data.data
  const known = new Set(schemaProps(col).map(([f]) => f))
  return (
    <div className="min-w-0">
    {q.data.approximate && <p className="mb-1 text-xs text-muted-foreground">{t.history.approximate}</p>}
    <dl className="grid min-w-0 gap-x-4 gap-y-2 rounded-lg border bg-muted/20 p-3 text-sm sm:grid-cols-[minmax(6rem,10rem)_minmax(0,1fr)]">
      {schemaProps(col)
        .filter(([f]) => data[f] !== undefined)
        .map(([f, schema]) => (
          <div key={f} className="contents">
            <dt className="text-muted-foreground">{fieldTitle(col, f)}</dt>
            <dd className="min-w-0 break-words">
              <CellValue value={data[f]} variant="detail" schema={schema} />
            </dd>
          </div>
        ))}
      {Object.keys(data)
        .filter((f) => !known.has(f))
        .map((f) => (
          <div key={f} className="contents">
            <dt className="font-mono text-xs text-muted-foreground">{f}</dt>
            <dd className="min-w-0 break-words">
              <CellValue value={data[f]} variant="detail" />
            </dd>
          </div>
        ))}
    </dl>
    </div>
  )
}

function Row({ col, item, audit, editable, onRestore }: { col: Collection; item: DeletedItem; audit: boolean; editable: boolean; onRestore: () => void }) {
  const [open, setOpen] = useState(false)
  return (
    <li className="min-w-0 px-4 py-3 text-sm">
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
        <button type="button" className="flex min-w-0 flex-1 basis-56 items-center gap-1.5 text-left hover:underline" aria-expanded={open} title={open ? t.history.deleted.hideLast : t.history.deleted.showLast} onClick={() => setOpen(!open)}>
          {open ? <ChevronDown className="size-3.5 shrink-0" /> : <ChevronRight className="size-3.5 shrink-0" />}
          <span className="min-w-0 font-medium break-words">{displayId(item.id)}</span>
        </button>
        {editable && (
          <Button variant="outline" size="sm" onClick={onRestore}>
            <RotateCcw /> {t.history.deleted.restore}
          </Button>
        )}
      </div>
      <div className="mt-1 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 pl-5 text-xs text-muted-foreground">
        {item.summary.length ? (
          item.summary.map((s) => (
            <span key={s.field} className="min-w-0 break-words">
              {fieldTitle(col, s.field)}: {s.value}
            </span>
          ))
        ) : (
          <span>{t.history.deleted.unnamed}</span>
        )}
      </div>
      <div className="mt-1 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 pl-5 text-xs text-muted-foreground">
        <span title={formatDateTime(item.deletedAt)}>
          {t.history.deleted.deletedAt} {relativeTime(item.deletedAt)}
        </span>
        <Who item={item} />
        <VerifiedBadge verified={!!item.verified} audit={audit} />
        <code className="font-mono" title={item.hash}>
          {item.short ?? shortHash(item.hash ?? '')}
        </code>
      </div>
      {open && (
        <div className="mt-3 pl-5">
          <h3 className="mb-1 text-xs font-medium text-muted-foreground">{t.history.deleted.lastVersion}</h3>
          <LastVersion col={col} item={item} />
        </div>
      )}
    </li>
  )
}

export default function DeletedRecords() {
  const { collection } = useParams()
  const col = useCollection(collection)
  if (!col) return <NotFound />
  return <Deleted col={col} />
}

function Deleted({ col }: { col: Collection }) {
  const { meta } = useMeta()
  const editable = canEdit(meta)
  const q = useDeleted(col.name)
  const [restoring, setRestoring] = useState<DeletedItem | null>(null)
  const base = `/c/${encodeURIComponent(col.name)}`
  const records = q.data?.records ?? []
  return (
    <div>
      <PageHeader
        icon={<ArchiveRestore />}
        eyebrow={
          <span className="flex items-center gap-1">
            <Link to={base} className="hover:text-foreground hover:underline">
              {collectionTitle(col)}
            </Link>
            <ChevronRight className="size-3" />
          </span>
        }
        title={t.history.deleted.title}
        description={t.history.deleted.description}
        actions={
          <Button variant="outline" render={<Link to={base} />}>
            {t.history.deleted.back}
          </Button>
        }
      />
      {q.data && !q.data.complete && <p className="mb-4 rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">{t.history.deleted.incomplete}</p>}
      {q.isPending ? (
        <Skeleton className="h-32 w-full" />
      ) : q.isError ? (
        <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{errorMessage(q.error)}</p>
      ) : records.length === 0 ? (
        q.data.complete ? <EmptyState title={t.history.deleted.empty} /> : null
      ) : (
        <ul className="divide-y rounded-xl border bg-card shadow-xs">
          {records.map((r) => (
            <Row key={r.id + r.hash} col={col} item={r} audit={q.data.audit} editable={editable} onRestore={() => setRestoring(r)} />
          ))}
        </ul>
      )}
      {q.data?.more && <p className="mt-3 text-xs text-muted-foreground">{t.history.deleted.more}</p>}
      {restoring && (
        <RestoreDialog
          col={col}
          id={restoring.id}
          commit={restoring.last}
          time={restoring.deletedAt}
          hash=""
          onClose={() => setRestoring(null)}
          onRestored={() => void q.refetch()}
        />
      )}
    </div>
  )
}
