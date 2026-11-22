import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { GitCommitHorizontal, History, RotateCcw } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { VerifiedBadge, Who } from '@/components/CommitWho'
import { FieldChanges } from '@/components/FieldChanges'
import { RestoreDialog } from '@/components/RestoreDialog'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { ApiError, errorMessage } from '@/lib/api'
import { useVersions, type RecordVersion } from '@/lib/history'
import { relativeTime } from '@/lib/ledger'
import { displayId } from '@/lib/recordId'
import { shortHash } from '@/lib/versionValue'
import type { Collection } from '@/lib/types'

/**
 * The version timeline of a record: who changed it, when, and what each commit changed field by field,
 * newest first. An editor may restore an older version.
 */
export function RecordHistory({
  col,
  id,
  hash,
  editable,
  onRestored,
}: {
  col: Collection
  id: string
  /** the hash of the current record: the version with that hash is the current one */
  hash: string
  editable: boolean
  onRestored: () => void
}) {
  const q = useVersions(col.name, id)
  const qc = useQueryClient()
  const [restoring, setRestoring] = useState<RecordVersion | null>(null)
  const pages = q.data?.pages ?? []
  const versions = pages.flatMap((p) => p.versions)
  const audit = pages[0]?.audit ?? true
  // A page can come back empty with a cursor (the walk budget ran out before a version was found): go on by itself a few times.
  let emptyRun = 0
  for (let i = pages.length - 1; i >= 0 && pages[i].versions.length === 0; i--) emptyRun++
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = q
  useEffect(() => {
    if (emptyRun > 0 && emptyRun < 3 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [emptyRun, hasNextPage, isFetchingNextPage, fetchNextPage])
  // a cursor the server no longer accepts (it restarted): start again from the newest
  const cursorGone = q.isFetchNextPageError && q.error instanceof ApiError && q.error.code === 'cursor_invalid'
  useEffect(() => {
    if (cursorGone) void qc.resetQueries({ queryKey: ['rb', 'versions', col.name, id] })
  }, [cursorGone, qc, col.name, id])

  const all = new URLSearchParams({ collection: col.name, id })
  return (
    <div className="min-w-0">
      {q.isPending ? (
        <Skeleton className="h-24 w-full" />
      ) : q.isError ? (
        <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{errorMessage(q.error)}</p>
      ) : versions.length === 0 && !hasNextPage ? (
        <p className="text-sm text-muted-foreground">{t.history.empty}</p>
      ) : (
        <ol className="space-y-5">
          {versions.map((v) => {
            const current = !!hash && v.recordHash === hash
            return (
              <li key={v.hash} className="min-w-0 border-l-2 border-border pl-4">
                <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-sm">
                  <GitCommitHorizontal className="size-3.5 shrink-0 text-muted-foreground" />
                  <time dateTime={v.time} title={formatDateTime(v.time)} className="text-xs text-muted-foreground">
                    {relativeTime(v.time)}
                  </time>
                  <Badge variant={v.change === 'deleted' ? 'destructive' : 'secondary'}>{t.history.change[v.change] ?? v.change}</Badge>
                  <VerifiedBadge verified={!!v.verified} audit={audit} />
                  {current && <Badge variant="outline">{t.history.current}</Badge>}
                  <code className="font-mono text-xs text-muted-foreground" title={v.hash}>
                    {v.short ?? shortHash(v.hash ?? '')}
                  </code>
                </div>
                <div className="mt-1 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                  <Who item={v} />
                  {v.token && <span>{t.activity.viaToken(v.token)}</span>}
                  {v.restoredFrom && <span className="rounded bg-muted px-1.5 py-0.5">{t.history.restoredFrom(shortHash(v.restoredFrom))}</span>}
                  {v.renamedFrom && <span>{t.history.renamedFrom(displayId(v.renamedFrom))}</span>}
                  {v.renamedTo && <span>{t.history.renamedTo(displayId(v.renamedTo))}</span>}
                </div>
                <p className="mt-1 min-w-0 text-sm break-words">{v.subject}</p>
                <div className="mt-2">
                  <FieldChanges changes={v.changes} more={v.moreChanges} />
                </div>
                {editable && !current && v.change !== 'deleted' && v.hash && (
                  <Button variant="outline" size="sm" className="mt-2" onClick={() => setRestoring(v)}>
                    <RotateCcw /> {t.history.restore}
                  </Button>
                )}
              </li>
            )
          })}
        </ol>
      )}
      {hasNextPage && (
        <div className="mt-4">
          <Button variant="outline" size="sm" disabled={isFetchingNextPage} onClick={() => void fetchNextPage()}>
            <History /> {isFetchingNextPage ? t.history.loading : t.history.loadMore}
          </Button>
        </div>
      )}
      <Link to={`/activity?${all}`} className="mt-3 inline-block text-xs text-sky-700 underline decoration-sky-700/30 underline-offset-4 dark:text-sky-300">
        {t.activity.seeAll}
      </Link>
      {restoring && (
        <RestoreDialog
          col={col}
          id={id}
          commit={restoring.hash ?? ''}
          time={restoring.time}
          hash={hash}
          onClose={() => setRestoring(null)}
          onRestored={() => {
            void qc.invalidateQueries({ queryKey: ['rb', 'versions', col.name, id] })
            onRestored()
          }}
        />
      )}
    </div>
  )
}
