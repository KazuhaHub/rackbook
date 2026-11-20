import { NavLink } from 'react-router'
import { Server, ShieldAlert } from 'lucide-react'
import { EmptyState, PageHeader } from '@/components/common'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { agoText, shortHash, type Hub, type RepoState } from '@/lib/infra'
import { errorMessage } from '@/lib/api'
import { useMeta } from '@/providers/meta'

const tabs = [
  { to: '/infra', end: true, label: () => t.infra.tabs.hosts },
  { to: '/infra/certs', end: false, label: () => t.infra.tabs.certs },
  { to: '/infra/iplists', end: false, label: () => t.infra.tabs.iplists },
  { to: '/infra/commits', end: false, label: () => t.infra.tabs.commits },
]

/** The status of the hub's file: its age, or why nothing below is current. */
export function HubBanner({ hub }: { hub?: Hub }) {
  if (!hub) return null
  if (hub.state === 'ok') {
    return <p className="mb-4 text-xs text-muted-foreground">{t.infra.hub.updated(agoText(hub.ageSeconds))}</p>
  }
  const why = hub.state === 'stale' ? t.infra.hub.stale(agoText(hub.ageSeconds)) : hub.state === 'missing' ? t.infra.hub.missing : t.infra.hub.invalid
  return (
    <p role="status" className="mb-4 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      <strong className="font-semibold">{t.infra.hub.unavailable}</strong> {why} {t.infra.hub.detail}
    </p>
  )
}

/** The commit the clone follows, and whether syncing it works. */
export function RepoLine({ repo }: { repo?: RepoState }) {
  if (!repo) return null
  return (
    <div className="mb-4 text-xs text-muted-foreground">
      <span>
        {t.infra.repo.head}: <span className="font-mono">{shortHash(repo.head) || '—'}</span>
      </span>
      <span className="mx-2">·</span>
      <span>
        {t.infra.repo.syncedAt}: {repo.syncedAt && !repo.syncedAt.startsWith('0001') ? formatDateTime(repo.syncedAt) : t.infra.repo.never}
      </span>
      {repo.error && (
        <p role="status" className="mt-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm break-words text-destructive">
          {t.infra.repo.failed}: {repo.error}
        </p>
      )}
    </div>
  )
}

export function LoadError({ error }: { error: unknown }) {
  return <EmptyState title={t.infra.loadFailed} body={errorMessage(error)} />
}

/** Header and tabs of every /infra page; the page itself only renders for infra administrators. */
export function InfraFrame({ children, header = true }: { children: React.ReactNode; header?: boolean }) {
  const { meta } = useMeta()
  if (!meta.user?.canInfra) return <EmptyState icon={<ShieldAlert />} title={t.infra.adminOnly} body={t.infra.adminOnlyBody} />
  return (
    <div>
      {header && <PageHeader icon={<Server />} title={t.infra.title} description={t.infra.subtitle} />}
      <nav className="mb-6 flex flex-wrap gap-1 border-b" aria-label={t.infra.title}>
        {tabs.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            end={tab.end}
            className={({ isActive }) => `-mb-px border-b-2 px-3 py-2 text-sm ${isActive ? 'border-brand font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'}`}
          >
            {tab.label()}
          </NavLink>
        ))}
      </nav>
      {children}
    </div>
  )
}
