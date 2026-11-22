import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { t } from '@/i18n'
import { errorMessage } from '@/lib/api'
import { ackThrough, acknowledgeAudit, useAuditStatus } from '@/lib/activity'
import { useMeta } from '@/providers/meta'

/**
 * Red banner for administrators and auditors while the audit log has recorded chain problems
 * nobody acknowledged. It sits where the other admin banners do (the top of every page, so it is
 * also on the Activity page). Only an administrator can acknowledge, which records that they
 * have looked; an auditor sees the same banner without the button.
 */
export function AuditAlert() {
  const { meta, refresh } = useMeta()
  const alert = meta.auditAlert
  const canAck = !!meta.user?.canAdmin
  const status = useAuditStatus(!!alert && (canAck || !!meta.user?.auditor))
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  if (!alert || !(canAck || meta.user?.auditor)) return null

  const problems = status.data?.problems ?? []
  const kinds = [...new Set(problems.map((p) => p.kind))].map((k) => t.activity.banner.kinds[k] ?? k).join(', ')
  const through = ackThrough(status.data)
  const firstSeq = problems.length ? Math.min(...problems.map((p) => p.seq)) : alert.firstSeq

  const acknowledge = async () => {
    setBusy(true)
    setError('')
    try {
      await acknowledgeAudit(through)
      setConfirm(false)
      await refresh()
    } catch (e) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div role="alert" className="flex flex-wrap items-center gap-x-3 gap-y-1 bg-destructive px-4 py-2 text-sm text-white">
      <ShieldAlert className="size-4 shrink-0" />
      <span className="font-medium">{t.activity.banner.title}</span>
      {problems.length > 0 ? (
        <span className="min-w-0 text-xs opacity-90">{t.activity.banner.detail(kinds, firstSeq)}</span>
      ) : (
        status.isSuccess && <span className="min-w-0 text-xs opacity-90">{t.activity.banner.failed}</span>
      )}
      {through > 0 && canAck && (
        <Button size="sm" variant="secondary" className="ml-auto" onClick={() => setConfirm(true)}>
          {t.activity.banner.acknowledge}
        </Button>
      )}
      {!canAck && <span className="ml-auto text-xs opacity-90">{t.activity.banner.adminsAcknowledge}</span>}
      <AlertDialog open={confirm} onOpenChange={setConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.activity.banner.confirmTitle}</AlertDialogTitle>
            <AlertDialogDescription>{t.activity.banner.confirmBody}</AlertDialogDescription>
          </AlertDialogHeader>
          {error && <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}
          <AlertDialogFooter>
            <AlertDialogCancel>{t.activity.banner.cancel}</AlertDialogCancel>
            <Button variant="destructive" disabled={busy} onClick={acknowledge}>
              {busy ? t.activity.banner.working : t.activity.banner.acknowledge}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
