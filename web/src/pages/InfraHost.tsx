import { Link, useParams } from 'react-router'
import { ArrowLeft } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/common'
import { HubBanner, InfraFrame, LoadError, RepoLine } from '@/components/infra/InfraFrame'
import { ResultBadge } from './InfraHosts'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { ApiError } from '@/lib/api'
import { shortHash, useInfraHost } from '@/lib/infra'
import { useMeta } from '@/providers/meta'

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="mb-8">
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="text-base font-semibold">{title}</h2>
        {hint && <span className="text-xs text-muted-foreground">{hint}</span>}
      </div>
      {children}
    </section>
  )
}

export default function InfraHost() {
  const { name = '' } = useParams()
  const { meta } = useMeta()
  const q = useInfraHost(name, !!meta.user?.canInfra)
  const notFound = q.error instanceof ApiError && q.error.statusCode === 404
  return (
    <InfraFrame header={false}>
      <Link to="/infra" className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> {t.infra.host.back}
      </Link>
      <h1 className="mb-4 text-xl font-semibold break-all">{name}</h1>
      {q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : notFound ? (
        <EmptyState title={t.infra.host.notFound} />
      ) : q.isError ? (
        <LoadError error={q.error} />
      ) : (
        <>
          <HubBanner hub={q.data.hub} />
          <RepoLine repo={q.data.repo} />
          <Section title={t.infra.host.groups}>
            {q.data.host.groups.length ? (
              <div className="flex flex-wrap gap-1">
                {q.data.host.groups.map((g) => (
                  <Badge key={g} variant="outline">
                    {g}
                  </Badge>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">{t.infra.host.noGroups}</p>
            )}
          </Section>
          <Section title={t.infra.host.report}>
            {q.data.report ? (
              <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <div>
                  <dt className="text-xs text-muted-foreground">{t.infra.hosts.columns.result}</dt>
                  <dd className="mt-0.5">
                    <ResultBadge result={q.data.report.result} />
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">{t.infra.host.applied}</dt>
                  <dd className="mt-0.5 text-sm">
                    <span className="font-mono">{shortHash(q.data.report.appliedCommit) || '—'}</span>{' '}
                    <Badge variant={q.data.behind ? 'destructive' : 'secondary'}>{q.data.behind ? t.infra.hosts.behind : t.infra.hosts.onMain}</Badge>
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">{t.infra.host.reported}</dt>
                  <dd className="mt-0.5 text-sm">{formatDateTime(q.data.report.time)}</dd>
                </div>
                {q.data.report.receivedAt && (
                  <div>
                    <dt className="text-xs text-muted-foreground">{t.infra.host.received}</dt>
                    <dd className="mt-0.5 text-sm">{formatDateTime(q.data.report.receivedAt)}</dd>
                  </div>
                )}
                {q.data.report.message && (
                  <div className="sm:col-span-2">
                    <dt className="text-xs text-muted-foreground">{t.infra.host.message}</dt>
                    <dd className="mt-0.5 text-sm break-words">{q.data.report.message}</dd>
                  </div>
                )}
                {q.data.report.features && q.data.report.features.length > 0 && (
                  <div className="sm:col-span-2 lg:col-span-3">
                    <dt className="text-xs text-muted-foreground">{t.infra.host.featureResults}</dt>
                    <dd className="mt-1 flex flex-wrap gap-2 text-sm">
                      {q.data.report.features.map((f) => (
                        <span key={f.name} className="inline-flex items-center gap-1" title={f.message}>
                          <span className="font-mono text-xs">{f.name}</span>
                          <Badge variant={f.result === 'failed' ? 'destructive' : 'secondary'}>{t.infra.featureResult[f.result] ?? f.result}</Badge>
                        </span>
                      ))}
                    </dd>
                  </div>
                )}
              </dl>
            ) : (
              <p className="text-sm text-muted-foreground">{t.infra.host.noReport}</p>
            )}
          </Section>
          <Section title={t.infra.host.features} hint={t.infra.host.featuresHint}>
            {q.data.host.features.length ? (
              <ul className="space-y-1 text-sm">
                {q.data.host.features.map((f) => (
                  <li key={f.name} className="flex items-center gap-2">
                    <span className="font-mono text-xs">{f.name}</span>
                    <Badge variant={f.enabled ? 'secondary' : 'outline'}>{f.enabled ? t.infra.host.enabled : t.infra.host.disabled}</Badge>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">{t.infra.host.noFeatures}</p>
            )}
          </Section>
          <Section title={t.infra.host.vars} hint={q.data.host.hasVars ? t.infra.host.varsHint : undefined}>
            {q.data.host.vars ? (
              <>
                {q.data.host.hidden > 0 && <p className="mb-2 text-xs text-muted-foreground">{t.infra.host.hidden(q.data.host.hidden)}</p>}
                <pre className="overflow-x-auto rounded-xl border bg-muted/40 p-4 font-mono text-xs leading-relaxed">{q.data.host.vars}</pre>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">{t.infra.host.noVars}</p>
            )}
          </Section>
        </>
      )}
    </InfraFrame>
  )
}
