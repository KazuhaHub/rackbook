import { CheckCircle2, CircleDashed, PauseCircle, SkipForward, XCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { t } from '@/i18n/zh-CN'
import { tone, type ModuleView, type RunStatus, type Tone } from '@/lib/modules'

const look: Record<Tone, { icon: typeof CheckCircle2; className: string; variant: 'secondary' | 'destructive' | 'outline' }> = {
  ok: { icon: CheckCircle2, className: 'text-success', variant: 'secondary' },
  failed: { icon: XCircle, className: '', variant: 'destructive' },
  paused: { icon: PauseCircle, className: 'text-amber-700 dark:text-amber-400', variant: 'outline' },
  skipped: { icon: SkipForward, className: 'text-muted-foreground', variant: 'outline' },
  never: { icon: CircleDashed, className: 'text-muted-foreground', variant: 'outline' },
  due: { icon: CircleDashed, className: 'text-muted-foreground', variant: 'outline' },
}

/** The one badge of a module: red when its last run failed, amber when paused. */
export function ModuleStatus({ module }: { module: Pick<ModuleView, 'status' | 'paused'> }) {
  const k = tone(module)
  const { icon: Icon, className, variant } = look[k]
  return (
    <Badge variant={variant} className={className} title={t.modules.statusHint[k]}>
      <Icon /> {t.modules.status[k]}
    </Badge>
  )
}

/** The result of one run in the history table. */
export function RunStatusBadge({ status }: { status: RunStatus }) {
  const { icon: Icon, className, variant } = look[status === 'ok' ? 'ok' : status === 'failed' ? 'failed' : 'skipped']
  return (
    <Badge variant={variant} className={className}>
      <Icon /> {status === 'ok' ? t.modules.status.ok : status === 'failed' ? t.modules.status.failed : t.modules.status.skipped}
    </Badge>
  )
}
