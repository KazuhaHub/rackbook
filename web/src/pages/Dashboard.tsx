import { useState, type CSSProperties } from 'react'
import { Link } from 'react-router'
import {
  ArrowRight,
  Bot,
  CalendarClock,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  Clock,
  FileJson,
  FileText,
  GitCommitHorizontal,
  Layers,
  ListChecks,
  StickyNote,
  Share2,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { PageHeader } from '@/components/common'
import { t } from '@/i18n/zh-CN'
import { useExpiring, useHistory } from '@/lib/hooks'
import { CollectionIcon } from '@/components/CollectionIcon'
import { hasExpiry, recordHref, relativeTime } from '@/lib/ledger'
import type { CheckError, Commit } from '@/lib/types'
import { cn } from '@/lib/utils'
import { useCheck, useMeta } from '@/providers/meta'

const stagger = (i: number) => ({ '--i': i }) as CSSProperties

function NoteItem({ title, text, source }: { title: string; text: string; source: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border transition-colors duration-150 hover:bg-muted/30">
      <button
        type="button"
        className="flex w-full items-center gap-2 rounded-lg px-3 py-2.5 text-left text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <ChevronDown className={cn('size-4 shrink-0 text-muted-foreground transition-transform duration-200', !open && '-rotate-90')} />
        <span className="flex-1">{title}</span>
        <span className="text-xs font-normal text-muted-foreground">{source}</span>
      </button>
      {open && <p className="border-t px-3 py-2.5 text-sm whitespace-pre-wrap text-muted-foreground">{text}</p>}
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
  tone,
  index,
}: {
  icon: React.ReactNode
  label: string
  value: React.ReactNode
  tone?: 'bad' | 'good'
  index: number
}) {
  return (
    <div style={stagger(index)} className="rb-row-in flex items-center gap-4 rounded-xl bg-card p-5 shadow-xs ring-1 ring-foreground/10">
      <span
        className={cn(
          'flex size-11 shrink-0 items-center justify-center rounded-xl [&_svg]:size-5',
          tone === 'bad' ? 'bg-destructive/10 text-destructive' : tone === 'good' ? 'bg-success/15 text-success' : 'bg-brand/10 text-brand',
        )}
      >
        {icon}
      </span>
      <div className="min-w-0">
        <div className="truncate text-xs text-muted-foreground">{label}</div>
        <div className="truncate text-2xl leading-tight font-semibold tabular-nums">{value}</div>
      </div>
    </div>
  )
}

/** Commit subjects look like `ledger(services): edit x/SSH`; the scope is the collection. */
function commitCollection(c: Commit, names: Map<string, unknown>): string | undefined {
  const m = /^ledger\(([^)]+)\):/.exec(c.subject)
  return m && names.has(m[1]) ? m[1] : undefined
}

function problemHref(e: CheckError, names: Map<string, unknown>) {
  if (e.collection && names.has(e.collection)) {
    return e.id ? recordHref(e.collection, e.id) : `/c/${encodeURIComponent(e.collection)}`
  }
  return '/check'
}

export default function Dashboard() {
  const { meta, byName } = useMeta()
  const check = useCheck()
  const history = useHistory(undefined, 8)
  const showExpiry = hasExpiry(meta)
  const expiry = useExpiring(30, false, showExpiry)
  const expiredCount = expiry.data?.items.filter((i) => i.status === 'expired').length ?? 0
  const soonCount = expiry.data?.items.filter((i) => i.status === 'expiring').length ?? 0
  const total = meta.collections.reduce((n, c) => n + c.count, 0)
  const notes = meta.collections.flatMap((c) => (c.notes ?? []).map((n) => ({ ...n, source: c.title })))
  const problems = check.data && !check.data.ok ? check.data.errors : []
  const last = history.data?.[0]

  return (
    <div>
      <PageHeader
        title={meta.title || t.dashboard.title}
        description={meta.description}
        actions={
          meta.writeMode && (
            <Badge variant="outline">
              {t.dashboard.writeMode}：{t.dashboard.writeModes[meta.writeMode] ?? meta.writeMode}
            </Badge>
          )
        }
      />

      <div className="mb-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard index={0} icon={<ListChecks />} label={t.dashboard.stats.records} value={total} />
        <StatCard index={1} icon={<Layers />} label={t.dashboard.stats.collections} value={meta.collections.length} />
        <StatCard
          index={2}
          icon={problems.length ? <CircleAlert /> : <CheckCircle2 />}
          label={t.dashboard.stats.problems}
          tone={check.data ? (problems.length ? 'bad' : 'good') : undefined}
          value={check.data ? problems.length : '—'}
        />
        <StatCard
          index={3}
          icon={<Clock />}
          label={t.dashboard.stats.lastEdit}
          value={<span className="text-xl">{last ? relativeTime(last.date) : t.dashboard.noEdits}</span>}
        />
      </div>

      {showExpiry && expiry.data && (
        <Link
          to="/expiring"
          className={cn(
            'mb-8 flex items-center gap-3 rounded-xl border bg-card px-4 py-3 text-sm shadow-xs transition-colors duration-150 outline-none hover:bg-muted/40 focus-visible:ring-2 focus-visible:ring-ring/60',
            expiredCount > 0 && 'border-destructive/40',
          )}
        >
          <CalendarClock className={cn('size-4 shrink-0', expiredCount > 0 ? 'text-destructive' : 'text-muted-foreground')} />
          <span className="font-medium">{t.expiring.dashboardTitle}</span>
          <span className="min-w-0 flex-1 truncate text-muted-foreground">
            {expiredCount + soonCount ? t.expiring.dashboardCounts(expiredCount, soonCount) : t.expiring.dashboardNone}
          </span>
          <span className="flex shrink-0 items-center gap-1 text-xs text-muted-foreground">
            {t.expiring.dashboardView}
            <ArrowRight className="size-3.5" />
          </span>
        </Link>
      )}

      <div className="mb-8 grid gap-5 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <GitCommitHorizontal className="size-4 text-muted-foreground" />
              {t.dashboard.recentTitle}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {history.isPending ? (
              <Skeleton className="h-28 w-full" />
            ) : history.data?.length ? (
              <ul className="-mx-2 divide-y">
                {history.data.map((c, i) => {
                  const scope = commitCollection(c, byName)
                  const col = scope ? byName.get(scope) : undefined
                  const inner = (
                    <>
                      <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground [&_svg]:size-4">
                        {col ? <CollectionIcon col={col} /> : <GitCommitHorizontal />}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-medium">{c.subject}</span>
                        <span className="block truncate text-xs text-muted-foreground">
                          {c.author} · <span title={c.date}>{relativeTime(c.date)}</span>
                          {col && <> · {col.title}</>}
                        </span>
                      </span>
                      <code className="hidden shrink-0 font-mono text-xs text-muted-foreground sm:inline">{c.hash.slice(0, 7)}</code>
                    </>
                  )
                  const cls = 'flex items-start gap-3 rounded-lg px-2 py-2.5'
                  return (
                    <li key={c.hash} style={stagger(i)} className="rb-row-in">
                      {col ? (
                        <Link
                          to={`/c/${encodeURIComponent(col.name)}`}
                          className={cn(cls, 'transition-colors duration-150 outline-none hover:bg-muted/60 focus-visible:ring-2 focus-visible:ring-ring/60')}
                        >
                          {inner}
                        </Link>
                      ) : (
                        <div className={cls}>{inner}</div>
                      )}
                    </li>
                  )
                })}
              </ul>
            ) : (
              <div className="flex flex-col items-center gap-2 py-8 text-center text-sm text-muted-foreground">
                <span className="flex size-12 items-center justify-center rounded-full bg-muted">
                  <GitCommitHorizontal className="size-6" />
                </span>
                {t.dashboard.recentEmpty}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className={cn('lg:col-span-2', problems.length > 0 && 'ring-destructive/40')}>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {problems.length ? (
                <CircleAlert className="size-4 text-destructive" />
              ) : (
                <CheckCircle2 className="size-4 text-success" />
              )}
              {t.dashboard.checkTitle}
            </CardTitle>
            <CardDescription>
              {check.data ? (check.data.ok ? t.check.ok : t.check.problems(problems.length)) : t.dashboard.totalRecords(total)}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {check.isPending ? (
              <Skeleton className="h-20 w-full" />
            ) : !check.data ? (
              <span className="text-sm text-muted-foreground">{t.check.unknown}</span>
            ) : check.data.ok ? (
              <div className="flex flex-col items-center gap-2 py-6 text-center text-sm text-muted-foreground">
                <span className="flex size-12 items-center justify-center rounded-full bg-success/15 text-success">
                  <CheckCircle2 className="size-6" />
                </span>
                <span className="font-medium text-foreground">{t.dashboard.allGood}</span>
                {t.dashboard.allGoodBody}
              </div>
            ) : (
              <div className="space-y-3">
                <ul className="-mx-2 space-y-0.5">
                  {problems.slice(0, 4).map((e, i) => (
                    <li key={i}>
                      <Link
                        to={problemHref(e, byName)}
                        className="block rounded-lg px-2 py-2 transition-colors duration-150 outline-none hover:bg-destructive/5 focus-visible:ring-2 focus-visible:ring-ring/60"
                      >
                        <span className="block text-sm leading-snug break-words">{e.message}</span>
                        <span className="mt-0.5 block truncate text-xs text-muted-foreground">
                          {[byName.get(e.collection ?? '')?.title ?? e.collection, e.id].filter(Boolean).join(' · ') || '—'}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
                <Button size="sm" variant="outline" render={<Link to="/check" />}>
                  {problems.length > 4 ? t.dashboard.moreProblems(problems.length - 4) : t.dashboard.viewProblems}
                  <ArrowRight />
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="mb-3 flex items-baseline justify-between gap-3">
        <h2 className="text-base font-semibold">{t.dashboard.collections}</h2>
        <span className="text-xs text-muted-foreground">{t.dashboard.collectionsHint}</span>
      </div>
      <div className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {meta.collections.map((c, i) => {
          return (
            <Link
              key={c.name}
              to={`/c/${encodeURIComponent(c.name)}`}
              style={stagger(i)}
              className="rb-row-in group flex items-center gap-4 rounded-xl border bg-card p-4 shadow-xs transition-[border-color,background-color,box-shadow,translate,transform] duration-150 outline-none hover:-translate-y-px hover:border-brand/40 hover:bg-brand/[0.04] hover:shadow-sm focus-visible:ring-2 focus-visible:ring-ring/60 active:translate-y-0"
            >
              <span className="flex size-11 shrink-0 items-center justify-center rounded-xl bg-brand/10 text-brand transition-colors duration-150 group-hover:bg-brand/15 [&_svg]:size-5">
                <CollectionIcon col={c} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="line-clamp-2 font-medium break-words">{c.title}</span>
                <span className="block truncate text-xs text-muted-foreground">{c.group || c.name}</span>
              </span>
              <span className="text-2xl leading-tight font-semibold tabular-nums" title={t.dashboard.records(c.count)}>
                {c.count}
              </span>
            </Link>
          )
        })}
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <StickyNote className="size-4 text-muted-foreground" />
              {t.dashboard.notes}
            </CardTitle>
            <CardDescription>{t.dashboard.notesHint}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {notes.length ? (
              notes.map((n, i) => <NoteItem key={i} title={n.title} text={n.text} source={n.source} />)
            ) : (
              <div className="flex flex-col items-center gap-2 py-6 text-center text-sm text-muted-foreground">
                <span className="flex size-12 items-center justify-center rounded-full bg-muted">
                  <StickyNote className="size-6" />
                </span>
                {t.dashboard.notesEmpty}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Share2 className="size-4 text-muted-foreground" />
              {t.dashboard.exportsTitle}
            </CardTitle>
            <CardDescription>{t.dashboard.exportsHint}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" render={<a href="/export.md" target="_blank" rel="noreferrer" />}>
              <FileText /> Markdown
            </Button>
            <Button variant="outline" size="sm" render={<a href="/export.json" target="_blank" rel="noreferrer" />}>
              <FileJson /> JSON
            </Button>
            <Button variant="outline" size="sm" render={<a href="/llms.txt" target="_blank" rel="noreferrer" />}>
              <Bot /> llms.txt
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
