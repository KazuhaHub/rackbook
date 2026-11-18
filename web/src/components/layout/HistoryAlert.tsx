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
import { t } from '@/i18n/zh-CN'
import { apiFetch, errorMessage } from '@/lib/api'
import { useMeta } from '@/providers/meta'

const short = (h: string) => h.slice(0, 7)

/** Red banner shown while the server pauses writes: the remote history was rewritten, or rackbook.yml does not load. */
export function HistoryAlert() {
  const { meta, refresh } = useMeta()
  const alert = meta.alert
  const [confirm, setConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  if (alert?.kind === 'config_error') {
    return (
      <div role="alert" className="flex flex-wrap items-center gap-x-3 gap-y-1 bg-destructive px-4 py-2 text-sm text-white">
        <ShieldAlert className="size-4 shrink-0" />
        <span className="font-medium">{t.alert.configError}</span>
        <span className="min-w-0 truncate font-mono text-xs opacity-90" title={alert.message}>
          {alert.message}
        </span>
        <span className="hidden text-xs opacity-90 lg:inline">{t.alert.configErrorHint}</span>
      </div>
    )
  }
  if (alert?.kind !== 'history_rewritten') return null

  const accept = async () => {
    setBusy(true)
    setError('')
    try {
      await apiFetch('/admin/accept-remote', { method: 'POST', body: JSON.stringify({ commit: alert.remote }) })
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
      <span className="font-medium">{t.alert.historyRewritten}</span>
      <span className="font-mono text-xs opacity-90">
        {t.alert.lastGood} {short(alert.lastGood)} · {t.alert.remote} {short(alert.remote)}
      </span>
      <span className="hidden flex-1 text-xs opacity-90 lg:inline">{t.alert.historyRewrittenHint}</span>
      {meta.user?.canAdmin && (
        <Button size="sm" variant="secondary" className="ml-auto" onClick={() => setConfirm(true)}>
          {t.alert.accept}
        </Button>
      )}
      <AlertDialog open={confirm} onOpenChange={setConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.alert.acceptTitle}</AlertDialogTitle>
            <AlertDialogDescription>{t.alert.acceptBody(short(alert.remote))}</AlertDialogDescription>
          </AlertDialogHeader>
          {error && <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}
          <AlertDialogFooter>
            <AlertDialogCancel>{t.alert.cancel}</AlertDialogCancel>
            <Button variant="destructive" disabled={busy} onClick={accept}>
              {busy ? t.alert.accepting : t.alert.accept}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
