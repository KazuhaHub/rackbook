import { useState } from 'react'
import { useNavigate } from 'react-router'
import { toast } from 'sonner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertDialog, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { CellValue } from '@/components/CellValue'
import { FieldChanges } from '@/components/FieldChanges'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { ApiError, errorMessage } from '@/lib/api'
import { restoreVersion, useVersionDetail } from '@/lib/history'
import { fieldTitle, schemaProps } from '@/lib/ledger'
import { recordHref } from '@/lib/recordUrl'
import { restoreStep, shortHash } from '@/lib/versionValue'
import type { Collection } from '@/lib/types'
import { useAfterWrite } from '@/providers/meta'

/** What the editor form is opened with when a version cannot be restored as it is. */
export type RestoreDraft = { data: Record<string, unknown>; commit: string; /** JSON pointers of the values the old version hid */ hiddenPaths: string[]; issues: ApiError['errors'] }

/**
 * Asks before a version is restored, shows what would change from the current record, and does it. `hash` is
 * the current record's hash, "" for a record that was deleted (it comes back as a new record).
 */
export function RestoreDialog({
  col,
  id,
  commit,
  time,
  hash,
  onClose,
  onRestored,
}: {
  col: Collection
  id: string
  commit: string
  time: string
  hash: string
  onClose: () => void
  /** the record changed: the page asks for it again */
  onRestored: () => void
}) {
  const navigate = useNavigate()
  const afterWrite = useAfterWrite()
  const detail = useVersionDetail(col.name, id, commit)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [conflict, setConflict] = useState(false)
  const [suspected, setSuspected] = useState(false)
  const [notSecret, setNotSecret] = useState(false)
  const deleted = hash === ''

  const go = async () => {
    setBusy(true)
    setError(null)
    setConflict(false)
    try {
      const res = await restoreVersion(col.name, id, commit, hash, notSecret)
      toast.success(res.pullRequest ? t.history.restoredPR : t.history.restored(res.commit ?? ''))
      void afterWrite()
      onRestored()
      onClose()
      if (deleted) navigate(recordHref(col.name, res.id))
    } catch (e) {
      if (!(e instanceof ApiError)) return setError(errorMessage(e))
      setSuspected(false)
      switch (restoreStep(e)) {
        case 'secret':
          setSuspected(true)
          setError(e.errors.map((x) => x.message).join(t.common.clauseSep) || e.message)
          break
        case 'conflict':
          setConflict(true)
          break
        case 'edit': {
          // the old content is opened in the editor, to be fixed and saved as an ordinary edit
          const draft: RestoreDraft = { data: e.body?.data ?? {}, commit: e.body?.commit ?? commit, hiddenPaths: Array.isArray(e.body?.hiddenPaths) ? e.body.hiddenPaths : [], issues: e.errors }
          onClose()
          navigate(deleted ? `/c/${encodeURIComponent(col.name)}/-/new` : `${recordHref(col.name, id)}/edit`, { state: { restore: draft } })
          break
        }
        case 'unchanged':
          setError(t.history.unchanged)
          break
        case 'refused':
          setError(t.history.refused)
          break
        default:
          setError(errorMessage(e))
      }
    } finally {
      setBusy(false)
    }
  }

  const d = detail.data
  return (
    <AlertDialog open onOpenChange={(o) => !o && onClose()}>
      <AlertDialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <AlertDialogHeader>
          <AlertDialogTitle>{t.history.restoreTitle}</AlertDialogTitle>
          <AlertDialogDescription>
            {deleted ? t.history.restoreBodyDeleted() : t.history.restoreBody(formatDateTime(time))}
            <span className="ml-1 font-mono text-xs">{shortHash(commit)}</span>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="min-w-0 space-y-2">
          {detail.isPending ? (
            <Skeleton className="h-20 w-full" />
          ) : detail.isError ? (
            <Alert variant="destructive">
              <AlertDescription>{errorMessage(detail.error)}</AlertDescription>
            </Alert>
          ) : d && !deleted ? (
            <>
              <h3 className="text-xs font-medium text-muted-foreground">{t.history.willChange}</h3>
              {d.changes.length || d.moreChanges ? <FieldChanges changes={d.changes} more={d.moreChanges} /> : <p className="text-sm text-muted-foreground">{t.history.nothingToChange}</p>}
            </>
          ) : d ? (
            <>
              <h3 className="text-xs font-medium text-muted-foreground">{t.history.fields}</h3>
              <dl className="grid max-h-72 gap-x-4 gap-y-2 overflow-y-auto rounded-lg border bg-muted/20 p-3 text-sm sm:grid-cols-[minmax(6rem,10rem)_minmax(0,1fr)]">
                {schemaProps(col)
                  .filter(([f]) => d.data[f] !== undefined)
                  .map(([f, schema]) => (
                    <div key={f} className="contents">
                      <dt className="text-muted-foreground">{fieldTitle(col, f)}</dt>
                      <dd className="min-w-0 break-words">
                        <CellValue value={d.data[f]} variant="detail" schema={schema} />
                      </dd>
                    </div>
                  ))}
              </dl>
            </>
          ) : null}
          {d?.approximate && (
            <Alert>
              <AlertDescription>{t.history.approximate}</AlertDescription>
            </Alert>
          )}
          {conflict && (
            <Alert variant="destructive">
              <AlertDescription>
                <p>{t.history.conflictBody}</p>
                <Button
                  size="sm"
                  variant="outline"
                  className="mt-2"
                  onClick={() => {
                    onRestored()
                    onClose()
                  }}
                >
                  {t.history.reload}
                </Button>
              </AlertDescription>
            </Alert>
          )}
          {error && (
            <Alert variant="destructive">
              <AlertDescription>
                <p>{suspected ? t.errors.suspectedBody : error}</p>
                {suspected && (
                  <div className="mt-2 flex items-center gap-2">
                    <Checkbox id="restore-not-a-secret" checked={notSecret} onCheckedChange={(v) => setNotSecret(v === true)} />
                    <Label htmlFor="restore-not-a-secret">{t.errors.notASecret}</Label>
                  </div>
                )}
                {suspected && <p className="mt-1 text-xs">{error}</p>}
              </AlertDescription>
            </Alert>
          )}
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel>{t.show.cancel}</AlertDialogCancel>
          <Button disabled={busy || detail.isPending || conflict || (suspected && !notSecret)} onClick={() => void go()}>
            {busy ? t.history.restoring : t.history.restoreConfirm}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
