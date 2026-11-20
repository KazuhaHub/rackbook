import { Link } from 'react-router'
import { CheckCircle2, CircleAlert, RefreshCw } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, PageHeader } from '@/components/common'
import { t } from '@/i18n'
import { errorMessage } from '@/lib/api'
import { fieldTitle, pointerToPath, recordHref } from '@/lib/ledger'
import { collectionTitle } from '@/lib/labels'
import { useCheck, useMeta } from '@/providers/meta'
import { issueText } from '@/lib/issues'
import { displayId } from '@/lib/recordId'

export default function Problems() {
  const { meta, byName } = useMeta()
  const { data, isPending, isError, error, isFetching } = useCheck()
  const qc = useQueryClient()

  return (
    <div>
      <PageHeader
        title={t.problems.title}
        description={data && !data.ok ? t.problems.count(data.errors.length) : undefined}
        actions={
          <Button variant="outline" size="sm" disabled={isFetching} onClick={() => qc.invalidateQueries({ queryKey: ['rb', 'check'] })}>
            <RefreshCw className={isFetching ? 'animate-spin' : ''} /> {t.problems.recheck}
          </Button>
        }
      />
      {isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : isError ? (
        <EmptyState icon={<CircleAlert className="size-8" />} title={t.errors.generic} body={errorMessage(error)} />
      ) : data.ok ? (
        <EmptyState icon={<CheckCircle2 className="size-8 text-success" />} title={t.problems.okTitle} body={t.problems.okBody} />
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                {[t.problems.collection, t.problems.record, t.problems.field, t.problems.rule, t.problems.message].map((h) => (
                  <th key={h} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.errors.map((e, i) => {
                const col = e.collection ? byName.get(e.collection) : undefined
                const field = pointerToPath(e.path)[0]
                return (
                  <tr key={i} className="border-b align-top transition-colors duration-150 last:border-0 even:bg-muted/25 hover:bg-destructive/5">
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      {col ? (
                        <Link to={`/c/${encodeURIComponent(col.name)}`} className="hover:underline">
                          {collectionTitle(col)}
                        </Link>
                      ) : (
                        e.collection || '—'
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      {col && e.id ? (
                        <Link to={recordHref(col.name, e.id)} className="font-mono text-[0.8125rem] text-sky-700 underline decoration-sky-700/30 underline-offset-4 dark:text-sky-300">
                          {displayId(e.id)}
                        </Link>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      {field ? (
                        <>
                          {col ? fieldTitle(col, field) : field}
                          <span className="ml-1 font-mono text-xs text-muted-foreground">{e.path}</span>
                        </>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge variant="outline">{t.problems.rules[e.rule ?? ''] ?? e.rule}</Badge>
                    </td>
                    <td className="px-4 py-2.5">{issueText(e, meta.collections)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
