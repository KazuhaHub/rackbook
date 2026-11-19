import { Link, useNavigate } from 'react-router'
import { KeyRound, Puzzle, ShieldAlert } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { ModuleStatus } from '@/components/modules/ModuleStatus'
import { doneText, when } from '@/components/modules/format'
import { EmptyState, PageHeader } from '@/components/common'
import { t } from '@/i18n/zh-CN'
import { errorMessage } from '@/lib/api'
import { failedCount, type ModuleView } from '@/lib/modules'
import { useModules } from '@/lib/modulesApi'
import { useMeta } from '@/providers/meta'

/** When the module runs next, in words. */
export function nextText(m: ModuleView) {
  if (m.type === '') return t.modules.nextNone
  if (m.paused) return t.modules.nextPaused
  if (m.runRequest) return t.modules.nextRequested
  if (m.due) return t.modules.nextDue
  return m.nextRun ? `${when(m.nextRun, m.schedule.timezone)} (${m.schedule.timezone})` : t.modules.nextNone
}

export function typeLabel(type: string) {
  return t.modules.types[type] ?? t.modules.types['']
}

export default function Modules() {
  const { meta } = useMeta()
  const admin = !!meta.user?.canAdmin
  const q = useModules(admin, 30_000)
  const navigate = useNavigate()
  if (!admin) return <EmptyState icon={<ShieldAlert />} title={t.modules.adminOnly} />
  const mods = q.data?.modules ?? []
  const failed = failedCount(mods)
  return (
    <div>
      <PageHeader icon={<Puzzle />} title={t.modules.title} description={t.modules.subtitle} />
      {failed > 0 && (
        <p role="status" className="mb-4 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t.modules.failedBanner(failed)}
        </p>
      )}
      {q.data && !q.data.historyKept && <p className="mb-4 rounded-lg border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">{t.modules.historyNotKept}</p>}
      {q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : q.isError ? (
        <EmptyState title={t.errors.generic} body={errorMessage(q.error)} />
      ) : mods.length === 0 ? (
        <EmptyState icon={<Puzzle />} title={t.modules.empty} body={t.modules.emptyBody} />
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                {[t.modules.columns.module, t.modules.columns.status, t.modules.columns.lastRun, t.modules.columns.next, t.modules.columns.token, t.modules.columns.target].map((h) => (
                  <th key={h} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {mods.map((m) => (
                <tr
                  key={m.name}
                  className="cursor-pointer border-b align-top transition-colors duration-150 last:border-0 hover:bg-brand/[0.07]"
                  onClick={(e) => {
                    if (!(e.target as HTMLElement).closest('a,button')) navigate(`/modules/${encodeURIComponent(m.name)}`)
                  }}
                >
                  <td className="px-4 py-2.5">
                    <Link to={`/modules/${encodeURIComponent(m.name)}`} className="font-medium hover:underline">
                      {m.name}
                    </Link>
                    <div className="text-xs text-muted-foreground">{typeLabel(m.type)}</div>
                  </td>
                  <td className="px-4 py-2.5">
                    <ModuleStatus module={m} />
                  </td>
                  <td className="px-4 py-2.5">
                    {m.lastRun ? (
                      <>
                        <div className="whitespace-nowrap">{when(m.lastRun.finished)}</div>
                        {m.lastRun.status === 'failed' ? (
                          <div className="max-w-64 text-xs text-destructive">{m.lastRun.error || t.modules.status.failed}</div>
                        ) : (
                          <div className="text-xs text-muted-foreground">{m.lastRun.status === 'skipped' ? t.modules.status.skipped : doneText(m.lastRun, m.type)}</div>
                        )}
                      </>
                    ) : (
                      <span className="text-muted-foreground">{t.modules.never}</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-xs">{nextText(m)}</td>
                  <td className="px-4 py-2.5">
                    <Link to="/admin/tokens" className="inline-flex items-center gap-1 font-mono text-xs hover:underline" title={t.modules.tokenLink}>
                      <KeyRound className="size-3 text-muted-foreground" /> {m.token}
                    </Link>
                    {m.tokenStatus !== 'active' && (
                      <div>
                        <Badge variant="destructive" className="mt-1">
                          {t.modules.tokenState[m.tokenStatus]}
                        </Badge>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-xs">{m.readOnly ? <span className="text-muted-foreground">{t.modules.noCollection}</span> : t.modules.writesTo(meta.collections.find((c) => c.name === m.collection)?.title ?? m.collection ?? '')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
