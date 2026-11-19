import { Link, useSearchParams } from 'react-router'
import { CalendarClock, CheckCircle2, CircleAlert } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { NativeSelect } from '@/components/ui/native-select'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, NotFound, PageHeader } from '@/components/common'
import { t } from '@/i18n/zh-CN'
import { errorMessage } from '@/lib/api'
import { useExpiring } from '@/lib/hooks'
import { hasExpiry, recordHref, sourceLabel } from '@/lib/ledger'
import type { ExpiringItem } from '@/lib/types'
import { cn } from '@/lib/utils'
import { useMeta } from '@/providers/meta'
import { displayId } from '@/lib/recordId'

const WINDOWS = [30, 60, 90, 365]

export function daysLeftText(item: ExpiringItem): string {
  if (item.daysLeft === null) return t.expiring.unknownDate
  if (item.daysLeft < 0) return t.expiring.expiredDays(-item.daysLeft)
  if (item.daysLeft === 0) return t.expiring.today
  return t.expiring.leftDays(item.daysLeft)
}

function Section({
  title,
  hint,
  empty,
  items,
  tone,
}: {
  title: string
  hint?: string
  empty: string
  items: ExpiringItem[]
  tone: 'bad' | 'warn' | 'muted'
}) {
  const { byName } = useMeta()
  return (
    <section className="mb-8">
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="text-base font-semibold">{title}</h2>
        <span className="text-xs text-muted-foreground tabular-nums">{items.length}</span>
        {hint && <span className="text-xs text-muted-foreground">{hint}</span>}
      </div>
      {items.length === 0 ? (
        <div className="flex items-center gap-2 rounded-xl border bg-card px-4 py-5 text-sm text-muted-foreground shadow-xs">
          <CheckCircle2 className="size-4 text-success" />
          {empty}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                {[t.expiring.collection, t.expiring.record, t.expiring.expires, t.expiring.daysLeft, t.expiring.source].map((h) => (
                  <th key={h} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((it) => {
                const col = byName.get(it.collection)
                return (
                  <tr
                    key={`${it.collection}/${it.id}`}
                    className={cn(
                      'border-b align-top transition-colors duration-150 last:border-0 even:bg-muted/25',
                      tone === 'bad' ? 'hover:bg-destructive/5' : 'hover:bg-muted/50',
                    )}
                  >
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      {col ? (
                        <Link to={`/c/${encodeURIComponent(col.name)}`} className="hover:underline">
                          {col.title}
                        </Link>
                      ) : (
                        it.collection
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <Link
                        to={recordHref(it.collection, it.id)}
                        className="font-mono text-[0.8125rem] text-sky-700 underline decoration-sky-700/30 underline-offset-4 dark:text-sky-300"
                      >
                        {it.label || displayId(it.id)}
                      </Link>
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap tabular-nums">{it.expires || '—'}</td>
                    <td
                      className={cn(
                        'px-4 py-2.5 whitespace-nowrap tabular-nums',
                        tone === 'bad' && 'font-medium text-destructive',
                        tone === 'warn' && 'font-medium',
                        tone === 'muted' && 'text-muted-foreground',
                      )}
                    >
                      {daysLeftText(it)}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <Badge variant="outline">{sourceLabel(it.source)}</Badge>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

export default function Expiring() {
  const { meta } = useMeta()
  const [sp, setSp] = useSearchParams()
  const asked = Number(sp.get('days'))
  const days = WINDOWS.includes(asked) ? asked : 30
  const enabled = hasExpiry(meta)
  const { data, isPending, isError, error } = useExpiring(days, true, enabled)
  if (!enabled) return <NotFound />

  const items = data?.items ?? []
  const expired = items.filter((i) => i.status === 'expired')
  const expiring = items.filter((i) => i.status === 'expiring')
  const unknown = items.filter((i) => i.status === 'unknown')

  return (
    <div>
      <PageHeader
        icon={<CalendarClock />}
        title={t.expiring.title}
        description={data ? `${t.expiring.description} ${t.expiring.asOf(data.today)}` : t.expiring.description}
        actions={
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <span className="whitespace-nowrap">{t.expiring.window}</span>
            <NativeSelect
              className="w-28"
              value={days}
              onChange={(e) => {
                const next = new URLSearchParams(sp)
                if (Number(e.target.value) === 30) next.delete('days')
                else next.set('days', e.target.value)
                setSp(next, { replace: true })
              }}
            >
              {WINDOWS.map((w) => (
                <option key={w} value={w}>
                  {t.expiring.windowOption(w)}
                </option>
              ))}
            </NativeSelect>
          </label>
        }
      />
      {isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : isError ? (
        <EmptyState icon={<CircleAlert className="size-8" />} title={t.errors.generic} body={errorMessage(error)} />
      ) : (
        <>
          <Section title={t.expiring.expiredTitle} empty={t.expiring.expiredEmpty} items={expired} tone="bad" />
          <Section title={t.expiring.expiringTitle(days)} empty={t.expiring.expiringEmpty(days)} items={expiring} tone="warn" />
          <Section
            title={t.expiring.unknownTitle}
            hint={t.expiring.unknownHint}
            empty={t.expiring.unknownEmpty}
            items={unknown}
            tone="muted"
          />
        </>
      )}
    </div>
  )
}
