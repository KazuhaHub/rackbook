import { Fragment, useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { Activity as ActivityIcon, ChevronDown, ChevronRight, Download, GitCommitHorizontal, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { DiffView } from '@/components/types/DiffView'
import { EmptyState, PageHeader } from '@/components/common'
import { t } from '@/i18n'
import { formatDateTime, formatDay, formatTime } from '@/i18n/format'
import { errorMessage } from '@/lib/api'
import {
  AREAS,
  eventSentence,
  exportHref,
  filterQuery,
  filtersFromParams,
  useActivity,
  useCommitDiff,
  type ActivityArea,
  type ActivityFilters,
  type ActivityItem,
} from '@/lib/activity'
import { collectionTitle } from '@/lib/labels'
import { recordHref } from '@/lib/recordUrl'
import { displayId } from '@/lib/recordId'
import { cn } from '@/lib/utils'
import { useMeta } from '@/providers/meta'

/** The areas this person may name; the server refuses the others. */
function useVisibleAreas(): ActivityArea[] {
  const { meta } = useMeta()
  return AREAS.filter((a) => a === 'ledger' || (a === 'infra' && !!meta.user?.canInfra) || (a === 'audit' && !!meta.user?.canAdmin))
}

function Filters({ value, onChange }: { value: ActivityFilters; onChange: (f: ActivityFilters) => void }) {
  const { meta } = useMeta()
  const visible = useVisibleAreas()
  // the text fields are applied on Enter or when they lose focus, the rest at once
  const [identity, setIdentity] = useState(value.identity)
  const [id, setId] = useState(value.id)
  const [seen, setSeen] = useState(value)
  if (seen !== value) {
    setSeen(value)
    setIdentity(value.identity)
    setId(value.id)
  }
  const commit = (patch: Partial<ActivityFilters>) => onChange({ ...value, identity, id, ...patch })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    commit({})
  }
  const toggle = (a: ActivityArea) => commit({ areas: value.areas.includes(a) ? value.areas.filter((x) => x !== a) : [...value.areas, a] })
  const active = !!(value.identity || value.areas.length || value.collection || value.since || value.until)
  const label = 'mb-1 block text-xs font-medium text-muted-foreground'
  return (
    <form onSubmit={submit} className="mb-6 grid gap-3 rounded-xl border bg-card p-4 shadow-xs sm:grid-cols-2 lg:grid-cols-4">
      <div className="min-w-0">
        <label className={label} htmlFor="act-person">
          {t.activity.filters.person}
        </label>
        <Input
          id="act-person"
          value={identity}
          placeholder={t.activity.filters.personPlaceholder}
          title={t.activity.filters.personHint}
          onChange={(e) => setIdentity(e.target.value)}
          onBlur={() => identity !== value.identity && commit({})}
        />
      </div>
      <div className="min-w-0">
        <span className={label}>{t.activity.filters.areas}</span>
        <div className="flex flex-wrap gap-1.5" role="group" aria-label={t.activity.filters.areas}>
          {visible.map((a) => (
            <Button key={a} type="button" size="sm" variant={value.areas.includes(a) ? 'default' : 'outline'} aria-pressed={value.areas.includes(a)} onClick={() => toggle(a)}>
              {t.activity.filters.area[a]}
            </Button>
          ))}
        </div>
      </div>
      <div className="min-w-0">
        <label className={label} htmlFor="act-collection">
          {t.activity.filters.collection}
        </label>
        <NativeSelect id="act-collection" value={value.collection} onChange={(e) => commit({ collection: e.target.value, id: e.target.value ? id : '' })}>
          <option value="">{t.activity.filters.anyCollection}</option>
          {meta.collections.map((c) => (
            <option key={c.name} value={c.name}>
              {collectionTitle(c)}
            </option>
          ))}
        </NativeSelect>
      </div>
      <div className="min-w-0">
        <label className={label} htmlFor="act-record">
          {t.activity.filters.record}
        </label>
        <Input
          id="act-record"
          value={id}
          disabled={!value.collection}
          placeholder={value.collection ? t.activity.filters.recordPlaceholder : t.activity.filters.recordNeedsCollection}
          onChange={(e) => setId(e.target.value)}
          onBlur={() => id !== value.id && commit({})}
        />
      </div>
      <div className="min-w-0">
        <label className={label} htmlFor="act-since">
          {t.activity.filters.from}
        </label>
        <Input id="act-since" type="date" value={value.since} max={value.until || undefined} onChange={(e) => commit({ since: e.target.value })} />
      </div>
      <div className="min-w-0">
        <label className={label} htmlFor="act-until">
          {t.activity.filters.to}
        </label>
        <Input id="act-until" type="date" value={value.until} min={value.since || undefined} onChange={(e) => commit({ until: e.target.value })} />
      </div>
      <div className="flex items-end gap-2 sm:col-span-2">
        <Button type="submit" size="sm">
          {t.activity.filters.apply}
        </Button>
        {active && (
          <Button type="button" size="sm" variant="ghost" onClick={() => onChange({ identity: '', areas: [], collection: '', id: '', since: '', until: '' })}>
            {t.activity.filters.clear}
          </Button>
        )}
      </div>
    </form>
  )
}

function VerifiedBadge({ verified, audit }: { verified: boolean; audit: boolean }) {
  const hint = verified ? t.activity.verifiedHint : audit ? t.activity.unverifiedHint : t.activity.noAudit
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <span
            tabIndex={0}
            className={cn(
              'inline-flex h-5 items-center gap-1 rounded-4xl border px-2 text-xs font-medium whitespace-nowrap [&>svg]:size-3',
              verified ? 'border-transparent bg-success/10 text-success' : 'border-border text-muted-foreground',
            )}
          />
        }
      >
        {verified ? <ShieldCheck /> : <ShieldQuestion />}
        {verified ? t.activity.verified : t.activity.unverified}
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">{hint}</TooltipContent>
    </Tooltip>
  )
}

function DiffPanel({ item }: { item: ActivityItem }) {
  const q = useCommitDiff(item.area, item.hash ?? '', true)
  if (q.isPending) return <Skeleton className="h-20 w-full" />
  if (q.isError) return <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{errorMessage(q.error)}</p>
  const files = q.data.files
  if (!files.length) return <p className="text-sm text-muted-foreground">{t.activity.diff.empty}</p>
  return (
    <div className="space-y-3">
      {files.map((f) => (
        <div key={f.path} className="min-w-0">
          <div className="mb-1 flex min-w-0 items-center gap-2 text-xs">
            <Badge variant="outline">{t.activity.diff.status[f.status] ?? f.status}</Badge>
            <code className="min-w-0 break-all font-mono">{f.path}</code>
          </div>
          {f.hidden ? (
            <p className="text-xs text-muted-foreground">{t.activity.diff.hidden}</p>
          ) : (
            <>
              {f.patch ? <DiffView diff={f.patch} className="max-h-96 overflow-y-auto" /> : null}
              {f.truncated && <p className="mt-1 text-xs text-muted-foreground">{t.activity.diff.truncated}</p>}
            </>
          )}
        </div>
      ))}
      {q.data.moreFiles && <p className="text-xs text-muted-foreground">{t.activity.diff.moreFiles}</p>}
    </div>
  )
}

function Who({ item }: { item: ActivityItem }) {
  const shown = item.name || item.identity || t.activity.system
  return (
    <span className="min-w-0 break-words">
      <span className="font-medium">{shown}</span>
      {item.identity && item.identity !== shown && <span className="ml-1 font-mono text-xs text-muted-foreground">{item.identity}</span>}
    </span>
  )
}

function Row({ item, audit }: { item: ActivityItem; audit: boolean }) {
  const { byName } = useMeta()
  const [open, setOpen] = useState(false)
  const isCommit = item.kind === 'commit'
  return (
    <li className="px-4 py-3 text-sm">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        <time dateTime={item.time} title={formatDateTime(item.time)} className="w-16 shrink-0 font-mono text-xs text-muted-foreground tabular-nums">
          {formatTime(item.time)}
        </time>
        <Badge variant="outline">{t.activity.filters.area[item.area]}</Badge>
        {isCommit ? (
          <button
            type="button"
            className="flex min-w-0 flex-1 basis-60 items-center gap-1.5 text-left hover:underline"
            aria-expanded={open}
            title={open ? t.activity.hideChanges : t.activity.showChanges}
            onClick={() => setOpen(!open)}
          >
            {open ? <ChevronDown className="size-3.5 shrink-0" /> : <ChevronRight className="size-3.5 shrink-0" />}
            <span className="min-w-0 break-words">{item.subject}</span>
          </button>
        ) : (
          <span className="min-w-0 flex-1 basis-60 break-words">
            <Who item={item} /> {eventSentence(item)}
          </span>
        )}
        {isCommit && item.state && (
          <Badge variant="secondary" title={t.activity.stateHint}>
            {t.activity.state}
          </Badge>
        )}
      </div>
      {isCommit && (
        <div className="mt-1 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 pl-[4.5rem] text-xs text-muted-foreground">
          <Who item={item} />
          <VerifiedBadge verified={!!item.verified} audit={audit} />
          {item.token && <span>{t.activity.viaToken(item.token)}</span>}
          {item.records?.map((r) => {
            const [coll, ...rest] = r.split('/')
            const rid = rest.join('/')
            const col = byName.get(coll)
            return col ? (
              <Link key={r} to={recordHref(coll, rid)} className="font-mono text-sky-700 underline decoration-sky-700/30 underline-offset-4 dark:text-sky-300">
                {collectionTitle(col)} · {displayId(rid)}
              </Link>
            ) : (
              <span key={r} className="font-mono">
                {r}
              </span>
            )
          })}
          <code className="font-mono" title={item.hash}>
            <GitCommitHorizontal className="mr-0.5 inline size-3" />
            {item.short}
          </code>
        </div>
      )}
      {isCommit && open && (
        <div className="mt-3 pl-0 sm:pl-[4.5rem]">
          <DiffPanel item={item} />
        </div>
      )}
    </li>
  )
}

/** Day by day, in the viewer's time zone. */
function Timeline({ items, audit }: { items: ActivityItem[]; audit: boolean }) {
  const groups: { day: string; items: ActivityItem[] }[] = []
  for (const it of items) {
    const day = formatDay(it.time)
    const last = groups[groups.length - 1]
    if (last && last.day === day) last.items.push(it)
    else groups.push({ day, items: [it] })
  }
  return (
    <div className="space-y-6">
      {groups.map((g) => (
        <Fragment key={g.day + g.items[0].time + (g.items[0].seq ?? g.items[0].hash)}>
          <section>
            <h2 className="mb-2 text-sm font-semibold">{g.day}</h2>
            <ul className="divide-y rounded-xl border bg-card shadow-xs">
              {g.items.map((it) => (
                <Row key={it.kind === 'commit' ? `${it.area}:${it.hash}` : `audit:${it.seq}`} item={it} audit={audit} />
              ))}
            </ul>
          </section>
        </Fragment>
      ))}
    </div>
  )
}

export default function Activity() {
  const { meta } = useMeta()
  const [sp, setSp] = useSearchParams()
  const filters = filtersFromParams(sp)
  const q = useActivity(filters)
  const items = q.data?.pages.flatMap((p) => p.items) ?? []
  const audit = q.data?.pages[0]?.audit ?? true
  // a page can come back empty with a cursor (the server's work budget ran out before it found a row): go on
  const lastEmpty = !!q.data && q.data.pages[q.data.pages.length - 1].items.length === 0
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = q
  useEffect(() => {
    if (lastEmpty && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastEmpty, hasNextPage, isFetchingNextPage, fetchNextPage])
  const setFilters = (f: ActivityFilters) => setSp(filterQuery(f), { replace: false })
  return (
    <div>
      <PageHeader
        icon={<ActivityIcon />}
        title={t.activity.title}
        description={t.activity.description}
        actions={
          meta.user?.canAdmin && (
            <Button variant="outline" size="sm" title={t.activity.exportHint} render={<a href={exportHref(filters)} download />}>
              <Download />
              {t.activity.export}
            </Button>
          )
        }
      />
      <Filters value={filters} onChange={setFilters} />
      {q.data && !audit && <p className="mb-4 rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">{t.activity.noAudit}</p>}
      {q.isPending ? (
        <Skeleton className="h-48 w-full" />
      ) : q.isError ? (
        <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{errorMessage(q.error)}</p>
      ) : items.length === 0 && !q.hasNextPage ? (
        <EmptyState title={t.activity.empty} />
      ) : (
        <>
          <Timeline items={items} audit={audit} />
          {q.hasNextPage && (
            <div className="mt-6 flex justify-center">
              <Button variant="outline" disabled={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
                {q.isFetchingNextPage ? t.activity.loading : t.activity.loadMore}
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
