import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/common'
import { InfraFrame, LoadError, RepoLine } from '@/components/infra/InfraFrame'
import { EditResult } from '@/components/infra/EditReview'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { shortHash, useInfraCommits } from '@/lib/infra'
import { useEditFlow } from '@/lib/infraEdit'
import { useMeta } from '@/providers/meta'

export default function InfraCommits() {
  const { meta } = useMeta()
  const q = useInfraCommits(!!meta.user?.canInfra)
  const flow = useEditFlow()
  const [target, setTarget] = useState<string | null>(null)
  const canRevert = !!q.data?.canRevert && !!meta.user?.canInfraWrite
  const busy = flow.state.phase === 'checking' || flow.state.phase === 'committing'
  const headers = [t.infra.commits.columns.commit, t.infra.commits.columns.subject, t.infra.commits.columns.author, t.infra.commits.columns.time, ...(canRevert ? [t.infra.commits.columns.actions] : [])]
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
                {headers.map((h, i) => (
                  <th key={i} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap">
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
                  <td className="px-4 py-2.5 break-words">
                    {c.subject}
                    {c.files && c.files.length > 0 && <div className="mt-0.5 font-mono text-xs text-muted-foreground">{c.files.join(', ')}</div>}
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">{c.author}</td>
                  <td className="px-4 py-2.5 text-xs whitespace-nowrap">{formatDateTime(c.time)}</td>
                  {canRevert && (
                    <td className="px-4 py-2.5 text-xs">
                      {c.revertible ? (
                        <Button
                          size="xs"
                          variant="outline"
                          disabled={busy}
                          title={t.infra.commits.revertHint}
                          onClick={() => {
                            setTarget(c.hash)
                            void flow.review(`revert:${c.hash}`, `/infra/commits/${c.hash}/revert`, {})
                          }}
                        >
                          {t.infra.commits.revert}
                        </Button>
                      ) : (
                        c.reason && <span className="text-muted-foreground">{t.infra.commits.reasons[c.reason] ?? c.reason}</span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {target && (
        <div className="mt-4">
          <h2 className="text-sm font-semibold">{t.infra.edit.revert.title(shortHash(target))}</h2>
          <p className="text-xs text-muted-foreground">{t.infra.edit.revert.body}</p>
          <EditResult
            flow={flow.state}
            mine={flow.state.key === `revert:${target}`}
            onCommit={flow.commit}
            onCancel={() => {
              flow.reset()
              setTarget(null)
            }}
            commitLabel={t.infra.commits.revert}
          />
        </div>
      )}
    </InfraFrame>
  )
}
