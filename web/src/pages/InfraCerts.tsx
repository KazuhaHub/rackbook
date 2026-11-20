import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/common'
import { HubBanner, InfraFrame, LoadError } from '@/components/infra/InfraFrame'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { useInfraCerts } from '@/lib/infra'
import { useMeta } from '@/providers/meta'

export default function InfraCerts() {
  const { meta } = useMeta()
  const q = useInfraCerts(!!meta.user?.canInfra)
  return (
    <InfraFrame>
      <HubBanner hub={q.data?.hub} />
      {q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : q.isError ? (
        <LoadError error={q.error} />
      ) : q.data.certs.length === 0 ? (
        <EmptyState title={t.infra.certs.empty} />
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                {[t.infra.certs.columns.name, t.infra.certs.columns.owner, t.infra.certs.columns.notAfter, t.infra.certs.columns.state, t.infra.certs.columns.lastError].map((h) => (
                  <th key={h} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {q.data.certs.map((c) => (
                <tr key={c.name} className="border-b align-top last:border-0">
                  <td className="px-4 py-2.5 font-mono text-xs break-all">{c.name}</td>
                  <td className="px-4 py-2.5">{c.owner}</td>
                  <td className="px-4 py-2.5 whitespace-nowrap">{c.notAfter ? formatDateTime(c.notAfter) : '—'}</td>
                  <td className="px-4 py-2.5">
                    <Badge variant={c.failing ? 'destructive' : 'secondary'}>{c.failing ? t.infra.certs.failing : t.infra.certs.ok}</Badge>
                  </td>
                  <td className="max-w-80 px-4 py-2.5 text-xs break-words text-destructive">{c.lastError ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </InfraFrame>
  )
}
