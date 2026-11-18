import { Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { t } from '@/i18n/zh-CN'
import type { Plan } from '@/lib/typedef'
import { DiffView } from './DiffView'

export function PreviewTab({ plan, planning }: { plan?: Plan; planning: boolean }) {
  if (!plan) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        {planning ? <Loader2 className="size-4 animate-spin" /> : null}
        {planning ? t.types.preview.loading : t.types.preview.nothing}
      </div>
    )
  }
  if (plan.files.length === 0) return <p className="text-sm text-muted-foreground">{t.types.preview.nothing}</p>
  return (
    <div className="space-y-5">
      {plan.subject && (
        <div className="text-sm">
          <span className="text-muted-foreground">{t.types.preview.subject}：</span>
          <code className="font-mono">{plan.subject}</code>
        </div>
      )}
      {plan.files.map((f) => (
        <section key={f.path} className="space-y-2">
          <div className="flex items-center gap-2">
            <Badge variant={f.status === 'removed' ? 'destructive' : 'secondary'}>{t.types.preview[f.status]}</Badge>
            <code className="font-mono text-sm">{f.path}</code>
          </div>
          <DiffView diff={f.diff} className="max-h-[28rem]" />
        </section>
      ))}
    </div>
  )
}
