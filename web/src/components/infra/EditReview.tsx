import { useState } from 'react'
import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { t } from '@/i18n'
import { issueText, type FileDiff, type FlowState, type Issue } from '@/lib/infraEdit'
import { shortHash } from '@/lib/infra'

export function DiffView({ diffs }: { diffs: FileDiff[] }) {
  return (
    <div className="space-y-3">
      {diffs.map((d) => (
        <div key={d.path} className="overflow-x-auto rounded-xl border bg-muted/30">
          <div className="border-b px-3 py-1.5 font-mono text-xs text-muted-foreground">{d.path}</div>
          <pre className="p-3 font-mono text-xs leading-relaxed">
            {d.diff.split('\n').map((l, i) => (
              <div
                key={i}
                className={
                  l.startsWith('@@')
                    ? 'text-muted-foreground'
                    : l.startsWith('+') && !l.startsWith('+++')
                      ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
                      : l.startsWith('-') && !l.startsWith('---')
                        ? 'bg-destructive/10 text-destructive'
                        : ''
                }
              >
                {l || ' '}
              </div>
            ))}
          </pre>
        </div>
      ))}
    </div>
  )
}

const sevLabel = (s: Issue['severity']) => (s === 'error' ? t.infra.edit.issue.error : s === 'confirm' ? t.infra.edit.issue.confirm : t.infra.edit.issue.warning)

export function IssueList({ issues }: { issues: Issue[] }) {
  if (issues.length === 0) return null
  return (
    <ul className="space-y-1 text-sm">
      {issues.map((i, n) => (
        <li key={n} className="flex flex-wrap items-baseline gap-x-2">
          <span className={`rounded px-1.5 py-0.5 text-xs ${i.severity === 'warning' ? 'bg-muted text-muted-foreground' : i.severity === 'confirm' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-400' : 'bg-destructive/10 text-destructive'}`}>
            {sevLabel(i.severity)}
          </span>
          <span className="break-words">{issueText(i)}</span>
          {i.file && <span className="font-mono text-xs text-muted-foreground">{t.infra.edit.issue.at(i.file)}</span>}
        </li>
      ))}
    </ul>
  )
}

/** A short sign-in to edit: a link back through the IdP, returning to this page. */
export function ReauthNotice({ hours }: { hours: number }) {
  const ret = window.location.pathname + window.location.search
  return (
    <div role="alert" className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
      <p className="font-medium">{t.infra.edit.reauth.title}</p>
      <p className="mt-1 text-muted-foreground">{t.infra.edit.reauth.body(hours)}</p>
      <a className="mt-2 inline-block" href={`/auth/oidc/start?return=${encodeURIComponent(ret)}`}>
        <Button size="sm" variant="outline">
          {t.infra.edit.reauth.action}
        </Button>
      </a>
    </div>
  )
}

/** The result area under an editor: problems, then the diff and the checks with the commit button. */
export function EditResult({
  flow,
  mine,
  onCommit,
  onReload,
  onCancel,
  commitLabel,
}: {
  flow: FlowState
  /** show only when the flow belongs to this section */
  mine: boolean
  onCommit: (confirmSecretScan: boolean) => void
  onReload?: () => void
  onCancel: () => void
  commitLabel?: string
}) {
  const [confirm, setConfirm] = useState(false)
  if (!mine) return null
  const p = flow.problem
  const o = flow.outcome
  if (flow.phase === 'checking') return <p className="mt-3 text-sm text-muted-foreground">{t.infra.edit.checking}</p>
  if (flow.phase === 'done' && o) {
    return (
      <div role="status" className="mt-3 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm">
        {t.infra.edit.committed(shortHash(o.commit))}
        {o.issues.some((i) => i.severity === 'warning') && (
          <div className="mt-2">
            <IssueList issues={o.issues.filter((i) => i.severity === 'warning')} />
          </div>
        )}
      </div>
    )
  }
  return (
    <div className="mt-3 space-y-3">
      {p?.kind === 'reauth' && <ReauthNotice hours={Math.round(p.maxAgeSeconds / 3600)} />}
      {p?.kind === 'message' && (
        <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {t.infra.edit.failed}
          {t.common.colon}
          {p.message}
        </p>
      )}
      {p?.kind === 'invalid' && (
        <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2">
          <p className="mb-2 text-sm font-medium text-destructive">{t.infra.edit.blocked}</p>
          <IssueList issues={p.issues} />
        </div>
      )}
      {p?.kind === 'conflict' && (
        <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2">
          <p className="text-sm font-medium text-destructive">{p.reason === 'later_commits' ? t.infra.edit.conflict.later(p.later.length) : t.infra.edit.conflict.title}</p>
          {p.reason !== 'later_commits' && <p className="mt-1 text-sm text-muted-foreground">{t.infra.edit.conflict.body}</p>}
          {p.diffs.length > 0 && (
            <div className="mt-2">
              <DiffView diffs={p.diffs} />
            </div>
          )}
          {onReload && p.reason !== 'later_commits' && (
            <Button size="sm" variant="outline" className="mt-2" onClick={onReload}>
              {t.infra.edit.conflict.reload}
            </Button>
          )}
        </div>
      )}
      {flow.phase !== 'idle' && o && (
        <div className="space-y-3">
          <h3 className="text-sm font-semibold">{t.infra.edit.reviewTitle}</h3>
          <DiffView diffs={o.diffs} />
          <p className={`text-sm font-medium ${o.blocked ? 'text-destructive' : 'text-emerald-700 dark:text-emerald-400'}`}>{o.blocked ? t.infra.edit.blocked : t.infra.edit.allowed}</p>
          <IssueList issues={o.issues.filter((i) => i.severity !== 'warning')} />
          {o.issues.some((i) => i.severity === 'warning') && (
            <details className="text-sm">
              <summary className="cursor-pointer text-muted-foreground">{t.infra.edit.warnings}</summary>
              <div className="mt-2">
                <IssueList issues={o.issues.filter((i) => i.severity === 'warning')} />
              </div>
            </details>
          )}
          {o.issues.some((i) => i.severity === 'confirm') && (
            <div className="flex items-center gap-2">
              <Checkbox id="confirm-secrets" checked={confirm} onCheckedChange={(v) => setConfirm(!!v)} />
              <Label htmlFor="confirm-secrets">{t.infra.edit.confirmSecrets}</Label>
            </div>
          )}
          <div className="flex gap-2">
            <Button
              disabled={flow.phase === 'committing' || (o.blocked && !(confirm && o.issues.every((i) => i.severity !== 'error')))}
              onClick={() => onCommit(confirm)}
            >
              {flow.phase === 'committing' ? t.infra.edit.committing : (commitLabel ?? t.infra.edit.commit)}
            </Button>
            <Button variant="outline" onClick={onCancel}>
              {t.infra.edit.back2}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

export function EditLink({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <Link to={to} className="text-sm text-primary underline-offset-4 hover:underline">
      {children}
    </Link>
  )
}
