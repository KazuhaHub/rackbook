import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/common'
import { InfraFrame, LoadError, RepoLine } from '@/components/infra/InfraFrame'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { shortHash, useInfraCommits } from '@/lib/infra'
import { useMeta } from '@/providers/meta'

export default function InfraCommits() {
  const { meta } = useMeta()
  const q = useInfraCommits(!!meta.user?.canInfra)
  return (
    <InfraFrame>
      <RepoLine repo={q.data?.repo} />
      <p className="mb-4 text-xs text-muted-foreground">{t.infra.commits.hint}</p>
      {q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : q.isError ? (
        <LoadError error={q.error} />
      ) : q.data.commits.length === 0 ? (
        <EmptyState title={t.infra.commits.empty} />
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                {[t.infra.commits.columns.commit, t.infra.commits.columns.subject, t.infra.commits.columns.author, t.infra.commits.columns.time].map((h) => (
                  <th key={h} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {q.data.commits.map((c) => (
                <tr key={c.hash} className="border-b align-top last:border-0">
                  <td className="px-4 py-2.5 font-mono text-xs" title={c.hash}>
                    {shortHash(c.hash)}
                  </td>
                  <td className="px-4 py-2.5 break-words">{c.subject}</td>
                  <td className="px-4 py-2.5 whitespace-nowrap">{c.author}</td>
                  <td className="px-4 py-2.5 text-xs whitespace-nowrap">{formatDateTime(c.time)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </InfraFrame>
  )
}
