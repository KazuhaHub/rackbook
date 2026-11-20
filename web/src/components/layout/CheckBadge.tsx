import { CheckCircle2, CircleAlert, Loader2 } from 'lucide-react'
import { Link } from 'react-router'
import { t } from '@/i18n'
import { useCheck } from '@/providers/meta'
import { cn } from '@/lib/utils'

export function CheckBadge({ className }: { className?: string }) {
  const { data, isPending, isError } = useCheck()
  let body
  let tone = 'bg-muted text-muted-foreground'
  if (isPending) {
    body = <><Loader2 className="size-3.5 animate-spin" />{t.check.loading}</>
  } else if (isError || !data) {
    body = <>{t.check.unknown}</>
  } else if (data.ok) {
    tone = 'bg-success/15 text-success'
    body = <><CheckCircle2 className="size-3.5" />{t.check.ok}</>
  } else {
    tone = 'bg-destructive/10 text-destructive'
    body = <><CircleAlert className="size-3.5" />{t.check.problems(data.errors.length)}</>
  }
  return (
    <Link
      to="/check"
      className={cn(
        'inline-flex h-6 items-center gap-1.5 rounded-full px-2.5 text-xs font-medium transition-opacity hover:opacity-80',
        tone,
        className,
      )}
    >
      {body}
    </Link>
  )
}
