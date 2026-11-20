import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { PlugZap, ShieldAlert, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
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
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/common'
import { t } from '@/i18n'
import { errorMessage } from '@/lib/api'
import { grantsKey, revokeGrant, useGrants, type Grant, type GrantScope } from '@/lib/grants'
import { relativeTime } from '@/lib/ledger'

/** The MCP clients a person authorized (account page) or everyone did (admin page), with a revoke button. */
export function GrantsList({ scope }: { scope: GrantScope }) {
  const G = t.oauth.grants
  const q = useGrants(scope)
  const qc = useQueryClient()
  const [revoking, setRevoking] = useState<Grant | null>(null)
  const revoke = useMutation({
    mutationFn: (id: string) => revokeGrant(scope, id),
    onSuccess: () => {
      toast.success(G.revoked)
      setRevoking(null)
      void qc.invalidateQueries({ queryKey: grantsKey(scope) })
    },
    onError: (e) => {
      setRevoking(null)
      toast.error(errorMessage(e))
    },
  })
  const admin = scope === 'admin'
  const grants = q.data ?? []

  return (
    <>
      {q.isPending ? (
        <Skeleton className="h-16 w-full" />
      ) : q.isError ? (
        <EmptyState icon={<ShieldAlert className="size-8" />} title={t.errors.generic} body={errorMessage(q.error)} />
      ) : grants.length === 0 ? (
        <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">{G.empty}</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                {[G.client, admin ? G.user : null, G.scopes, G.created, G.lastUsed, '']
                  .filter((h) => h !== null)
                  .map((h, i) => (
                    <th key={i} className="h-9 px-4 font-semibold tracking-wide whitespace-nowrap">
                      {h}
                    </th>
                  ))}
              </tr>
            </thead>
            <tbody>
              {grants.map((g) => (
                <tr key={g.id} className="border-b last:border-0 even:bg-muted/25">
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2 font-medium">
                      <PlugZap className="size-4 shrink-0 text-muted-foreground" />
                      <span className="max-w-56 truncate" title={g.clientName}>
                        {g.clientName}
                      </span>
                    </div>
                  </td>
                  {admin && (
                    <td className="px-4 py-2.5">
                      <div className="max-w-48 truncate" title={g.user}>
                        {g.user}
                      </div>
                    </td>
                  )}
                  <td className="px-4 py-2.5">
                    <Badge variant="secondary">{g.canWrite ? G.readWrite : G.readOnly}</Badge>
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">{relativeTime(g.created)}</td>
                  <td className="px-4 py-2.5 whitespace-nowrap">{relativeTime(g.lastUsed)}</td>
                  <td className="px-4 py-2.5 text-right">
                    <Button variant="ghost" size="sm" onClick={() => setRevoking(g)}>
                      <Trash2 /> {G.revoke}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <AlertDialog open={revoking !== null} onOpenChange={(o) => !o && setRevoking(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{G.revokeTitle(revoking?.clientName ?? '')}</AlertDialogTitle>
            <AlertDialogDescription>{G.revokeBody}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{G.cancel}</AlertDialogCancel>
            <Button variant="destructive" disabled={revoke.isPending} onClick={() => revoking && revoke.mutate(revoking.id)}>
              {revoke.isPending ? G.revoking : G.revoke}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
