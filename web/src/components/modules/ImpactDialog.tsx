import { AlertTriangle } from 'lucide-react'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { t } from '@/i18n'
import type { Affected, Impact } from '@/lib/modules'

function List({ rows }: { rows: Affected[] }) {
  return (
    <ul className="max-h-48 divide-y overflow-auto rounded-lg border text-sm">
      {rows.map((r) => (
        <li key={r.id} className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 px-3 py-1.5">
          <span className="min-w-0 truncate font-mono text-xs" title={r.id}>
            {r.label}
          </span>
          <span className="flex items-center gap-2 text-xs text-muted-foreground">
            {r.expires}
            <Badge variant={r.effect === 'frozen' ? 'secondary' : 'destructive'}>{r.effect === 'frozen' ? t.modules.impact.frozen : t.modules.impact.maybeRevoked}</Badge>
          </span>
        </li>
      ))}
    </ul>
  )
}

/**
 * Asks before a change that can freeze or retire records, and lists them.
 * impact is undefined while the preview is being computed.
 */
export function ImpactDialog({
  open,
  impact,
  error,
  saving,
  onConfirm,
  onCancel,
}: {
  open: boolean
  impact?: Impact
  error?: string
  saving: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const frozen = impact?.records.filter((r) => r.effect === 'frozen') ?? []
  const maybe = impact?.records.filter((r) => r.effect === 'maybe_revoked') ?? []
  const none = !!impact && impact.records.length === 0
  return (
    <AlertDialog open={open} onOpenChange={(o) => !o && !saving && onCancel()}>
      <AlertDialogContent className="max-h-[90svh] overflow-y-auto data-[size=default]:sm:max-w-lg">
        <AlertDialogHeader>
          <AlertDialogTitle className="flex items-center gap-2">
            {!none && <AlertTriangle className="size-5 text-amber-600" />}
            {none ? t.modules.impact.titleNone : t.modules.impact.title}
          </AlertDialogTitle>
          <AlertDialogDescription className="sr-only">{t.modules.impact.title}</AlertDialogDescription>
        </AlertDialogHeader>
        <div className="space-y-3 text-sm">
          {!impact && !error && <p className="text-muted-foreground">{t.modules.impact.loading}</p>}
          {error && <p className="rounded-md bg-destructive/10 px-3 py-2 text-destructive">{error}</p>}
          {none && <p className="text-muted-foreground">{t.modules.impact.none}</p>}
          {frozen.length > 0 && (
            <>
              <p>{t.modules.impact.bodyFrozen}</p>
              <List rows={frozen} />
            </>
          )}
          {maybe.length > 0 && (
            <>
              <p>{t.modules.impact.bodyRevoke}</p>
              <List rows={maybe} />
            </>
          )}
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={saving}>{t.modules.impact.cancel}</AlertDialogCancel>
          <Button disabled={!impact || saving} onClick={onConfirm}>
            {saving ? t.modules.settings.saving : t.modules.impact.confirm}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
