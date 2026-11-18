import { useState } from 'react'
import { Link } from 'react-router'
import { CheckCircle2, ChevronDown, CircleAlert, FileJson, FileText, GitCommitHorizontal, Bot } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { PageHeader } from '@/components/common'
import { t } from '@/i18n/zh-CN'
import { useHistory } from '@/lib/hooks'
import { relativeTime } from '@/lib/ledger'
import { cn } from '@/lib/utils'
import { useCheck, useMeta } from '@/providers/meta'

function NoteItem({ title, text, source }: { title: string; text: string; source: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border">
      <button
        type="button"
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm font-medium"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <ChevronDown className={cn('size-4 shrink-0 text-muted-foreground transition-transform', !open && '-rotate-90')} />
        <span className="flex-1">{title}</span>
        <span className="text-xs font-normal text-muted-foreground">{source}</span>
      </button>
      {open && <p className="border-t px-3 py-2 text-sm whitespace-pre-wrap text-muted-foreground">{text}</p>}
    </div>
  )
}

export default function Dashboard() {
  const { meta } = useMeta()
  const check = useCheck()
  const history = useHistory(undefined, 8)
  const total = meta.collections.reduce((n, c) => n + c.count, 0)
  const notes = meta.collections.flatMap((c) => (c.notes ?? []).map((n) => ({ ...n, source: c.title })))

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

      <div className="mb-6 grid gap-4 lg:grid-cols-3">
        <Card className={cn(check.data && !check.data.ok && 'ring-destructive/40')}>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {check.data?.ok === false ? (
                <CircleAlert className="size-4 text-destructive" />
              ) : (
                <CheckCircle2 className="size-4 text-success" />
              )}
              {t.dashboard.checkTitle}
            </CardTitle>
            <CardDescription>{t.dashboard.totalRecords(total)}</CardDescription>
          </CardHeader>
          <CardContent>
            {check.isPending ? (
              <Skeleton className="h-5 w-40" />
            ) : check.data ? (
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className={cn('text-sm', check.data.ok ? 'text-success' : 'text-destructive')}>
                  {check.data.ok ? `✓ ${t.check.ok}` : t.check.problems(check.data.errors.length)}
                </span>
                {!check.data.ok && (
                  <Button size="sm" variant="outline" render={<Link to="/check" />}>
                    {t.dashboard.viewProblems}
                  </Button>
                )}
              </div>
            ) : (
              <span className="text-sm text-muted-foreground">{t.check.unknown}</span>
            )}
            {check.data && !check.data.ok && (
              <p className="mt-2 text-xs text-muted-foreground">{t.dashboard.checkProblemText(check.data.errors.length)}</p>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <GitCommitHorizontal className="size-4 text-muted-foreground" />
              {t.dashboard.recent}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {history.isPending ? (
              <Skeleton className="h-16 w-full" />
            ) : history.data?.length ? (
              <ul className="divide-y">
                {history.data.map((c) => (
                  <li key={c.hash} className="flex items-baseline gap-3 py-1.5 text-sm">
                    <code className="shrink-0 font-mono text-xs text-muted-foreground">{c.hash.slice(0, 7)}</code>
                    <span className="min-w-0 flex-1 truncate">{c.subject}</span>
                    <span className="hidden shrink-0 text-xs text-muted-foreground sm:inline">{c.author}</span>
                    <span className="shrink-0 text-xs text-muted-foreground" title={c.date}>
                      {relativeTime(c.date)}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">{t.dashboard.recentEmpty}</p>
            )}
          </CardContent>
        </Card>
      </div>

      <h2 className="mb-3 text-sm font-medium text-muted-foreground">{t.dashboard.collections}</h2>
      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {meta.collections.map((c) => (
          <Link
            key={c.name}
            to={`/c/${encodeURIComponent(c.name)}`}
            className="group rounded-xl border bg-card p-4 transition-colors hover:border-foreground/30 hover:bg-muted/40"
          >
            <div className="flex items-baseline justify-between gap-2">
              <span className="font-medium">{c.title}</span>
              <span className="text-2xl font-semibold tabular-nums">{c.count}</span>
            </div>
            <div className="mt-1 flex items-center justify-between gap-2 text-xs text-muted-foreground">
              <span className="truncate">{c.group || c.name}</span>
              <span>{t.dashboard.records(c.count)}</span>
            </div>
          </Link>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{t.dashboard.notes}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {notes.length ? (
              notes.map((n, i) => <NoteItem key={i} title={n.title} text={n.text} source={n.source} />)
            ) : (
              <p className="text-sm text-muted-foreground">{t.dashboard.notesEmpty}</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>{t.dashboard.exportsTitle}</CardTitle>
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
