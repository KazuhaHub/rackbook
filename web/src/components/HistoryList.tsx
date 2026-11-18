import { GitCommitHorizontal } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { t } from '@/i18n/zh-CN'
import { useHistory } from '@/lib/hooks'
import { relativeTime } from '@/lib/ledger'

export function HistoryList({ collection, limit = 5 }: { collection: string; limit?: number }) {
  const { data, isPending } = useHistory(collection, limit)
  if (isPending) return <Skeleton className="h-14 w-full" />
  if (!data?.length) return <p className="text-sm text-muted-foreground">{t.show.historyEmpty}</p>
  return (
    <ul className="divide-y">
      {data.map((c) => (
        <li key={c.hash} className="flex items-baseline gap-3 py-2 text-sm">
          <GitCommitHorizontal className="size-3.5 shrink-0 translate-y-0.5 text-muted-foreground" />
          <code className="shrink-0 font-mono text-xs text-muted-foreground">{c.hash.slice(0, 7)}</code>
          <span className="min-w-0 flex-1 truncate">{c.subject}</span>
          <span className="hidden shrink-0 text-xs text-muted-foreground sm:inline">{c.author}</span>
          <span className="shrink-0 text-xs text-muted-foreground" title={c.date}>
            {relativeTime(c.date)}
          </span>
        </li>
      ))}
    </ul>
  )
}
