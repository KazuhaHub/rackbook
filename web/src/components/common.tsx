import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { FileQuestion, ServerCrash } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { t } from '@/i18n/zh-CN'
import { errorMessage } from '@/lib/api'

export function PageFallback() {
  return (
    <div className="space-y-3">
      <Skeleton className="h-8 w-56" />
      <Skeleton className="h-64 w-full" />
    </div>
  )
}

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  eyebrow?: ReactNode
}) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1 text-xs text-muted-foreground">{eyebrow}</div>}
        <h1 className="text-2xl font-semibold tracking-tight break-words">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  )
}

export function EmptyState({
  icon,
  title,
  body,
  action,
}: {
  icon?: ReactNode
  title: string
  body?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed px-6 py-16 text-center">
      <div className="text-muted-foreground">{icon}</div>
      <div className="text-lg font-medium">{title}</div>
      {body && <p className="max-w-md text-sm text-muted-foreground">{body}</p>}
      {action}
    </div>
  )
}

export function NotFound({
  title = t.notFound.title,
  body = t.notFound.body,
  backTo = '/',
  backLabel = t.notFound.back,
}: {
  title?: string
  body?: string
  backTo?: string
  backLabel?: string
}) {
  return (
    <EmptyState
      icon={<FileQuestion className="size-10" />}
      title={title}
      body={body}
      action={<Button render={<Link to={backTo} />}>{backLabel}</Button>}
    />
  )
}

export function Unreachable({ error, onRetry }: { error?: unknown; onRetry: () => void }) {
  return (
    <div className="flex min-h-svh items-center justify-center p-6">
      <div className="max-w-md text-center">
        <ServerCrash className="mx-auto mb-4 size-12 text-muted-foreground" />
        <h1 className="text-xl font-semibold">{t.errors.unreachableTitle}</h1>
        <p className="mt-2 text-sm text-muted-foreground">{t.errors.unreachableBody}</p>
        {error != null && <p className="mt-3 font-mono text-xs break-words text-muted-foreground">{errorMessage(error)}</p>}
        <Button className="mt-5" onClick={onRetry}>
          {t.errors.retry}
        </Button>
      </div>
    </div>
  )
}
