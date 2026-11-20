import { Link } from 'react-router'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/common'
import { HubBanner, InfraFrame, LoadError, RepoLine } from '@/components/infra/InfraFrame'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { shortHash, useInfraHosts } from '@/lib/infra'
import { useMeta } from '@/providers/meta'

export function ResultBadge({ result }: { result: string }) {
  const bad = result === 'failed' || result === 'rejected' || result === 'unreachable'
  return <Badge variant={bad ? 'destructive' : 'secondary'}>{t.infra.result[result] ?? result}</Badge>
}

export default function InfraHosts() {
  const { meta } = useMeta()
  const q = useInfraHosts(!!meta.user?.canInfra)
  return (
    <InfraFrame>
      <HubBanner hub={q.data?.hub} />
      <RepoLine repo={q.data?.repo} />
      {q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : q.isError ? (
        <LoadError error={q.error} />
      ) : q.data.hosts.length === 0 ? (
        <EmptyState title={t.infra.hosts.empty} />
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                {[t.infra.hosts.columns.host, t.infra.hosts.columns.groups, t.infra.hosts.columns.features, t.infra.hosts.columns.result, t.infra.hosts.columns.applied, t.infra.hosts.columns.reported].map((h) => (
                  <th key={h} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {q.data.hosts.map((h) => (
                <tr key={h.name} className="border-b align-top last:border-0 hover:bg-brand/[0.07]">
                  <td className="px-4 py-2.5">
                    <Link to={`/infra/hosts/${encodeURIComponent(h.name)}`} className="font-medium hover:underline">
                      {h.name}
                    </Link>
                    {!h.hasVars && <div className="text-xs text-muted-foreground">{t.infra.hosts.noVars}</div>}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {h.groups.map((g) => (
                        <Badge key={g} variant="outline">
                          {g}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-xs">{h.features.length ? h.features.join(', ') : <span className="text-muted-foreground">—</span>}</td>
                  <td className="px-4 py-2.5">
                    {h.report ? (
                      <>
                        <ResultBadge result={h.report.result} />
                        {h.report.message && <div className="mt-1 max-w-64 text-xs break-words text-muted-foreground">{h.report.message}</div>}
                      </>
                    ) : (
                      <span className="text-muted-foreground">{t.infra.hosts.noReport}</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    {h.report ? (
                      <>
                        <span className="font-mono text-xs">{shortHash(h.report.appliedCommit) || '—'}</span>
                        <div>
                          <Badge variant={h.behind ? 'destructive' : 'secondary'}>{h.behind ? t.infra.hosts.behind : t.infra.hosts.onMain}</Badge>
                        </div>
                      </>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-xs whitespace-nowrap">{h.report ? formatDateTime(h.report.receivedAt || h.report.time) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </InfraFrame>
  )
}
