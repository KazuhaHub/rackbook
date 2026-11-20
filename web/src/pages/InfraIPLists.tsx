import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/common'
import { HubBanner, InfraFrame, LoadError } from '@/components/infra/InfraFrame'
import { t } from '@/i18n'
import { formatNumber } from '@/i18n/format'
import { useInfraIPLists } from '@/lib/infra'
import { useMeta } from '@/providers/meta'

export default function InfraIPLists() {
  const { meta } = useMeta()
  const q = useInfraIPLists(!!meta.user?.canInfra)
  return (
    <InfraFrame>
      <HubBanner hub={q.data?.hub} />
      {q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : q.isError ? (
        <LoadError error={q.error} />
      ) : q.data.lists.length === 0 ? (
        <EmptyState title={t.infra.iplists.empty} />
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                {[t.infra.iplists.columns.name, t.infra.iplists.columns.version, t.infra.iplists.columns.entries, t.infra.iplists.columns.warnings].map((h) => (
                  <th key={h} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {q.data.lists.map((l) => (
                <tr key={l.name} className="border-b align-top last:border-0">
                  <td className="px-4 py-2.5 font-medium">{l.name}</td>
                  <td className="px-4 py-2.5 font-mono text-xs break-all">{l.version ?? '—'}</td>
                  <td className="px-4 py-2.5 tabular-nums">{formatNumber(l.entries)}</td>
                  <td className="px-4 py-2.5 text-xs">
                    {l.warnings.length ? (
                      <ul className="list-disc space-y-0.5 pl-4 text-destructive">
                        {l.warnings.map((w, i) => (
                          <li key={i} className="break-words">
                            {w}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <span className="text-muted-foreground">{t.infra.iplists.none}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </InfraFrame>
  )
}
