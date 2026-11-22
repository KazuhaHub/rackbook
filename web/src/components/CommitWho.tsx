import { ShieldCheck, ShieldQuestion } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { t } from '@/i18n'
import type { ActivityItem } from '@/lib/activity'
import { cn } from '@/lib/utils'

/** Whether this server made the commit (its audit log has the line), or the person is only what the commit says. */
export function VerifiedBadge({ verified, audit }: { verified: boolean; audit: boolean }) {
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

/** The person behind a commit or an event, as the activity view shows them. */
export function Who({ item }: { item: ActivityItem }) {
  const shown = item.name || item.identity || t.activity.system
  return (
    <span className="min-w-0 break-words">
      <span className="font-medium">{shown}</span>
      {item.identity && item.identity !== shown && <span className="ml-1 font-mono text-xs text-muted-foreground">{item.identity}</span>}
    </span>
  )
}
