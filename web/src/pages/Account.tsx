import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Fingerprint, KeyRound, LogOut, PlugZap, Plus, ShieldCheck, Trash2 } from 'lucide-react'
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
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { GrantsList } from '@/components/GrantsList'
import { PageHeader } from '@/components/common'
import { roleLabel } from '@/components/layout/UserMenu'
import { t } from '@/i18n'
import { apiFetch, errorMessage } from '@/lib/api'
import { hasSession, isSSO, logout, useAccount, type Passkey } from '@/lib/auth'
import { relativeTime } from '@/lib/ledger'
import { createCredential, isCancelled, passkeysSupported } from '@/lib/webauthn'
import { useMeta } from '@/providers/meta'

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[7rem_1fr] items-baseline gap-3 border-b py-2.5 text-sm last:border-0">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  )
}

export default function Account() {
  const A = t.auth.account
  const { meta } = useMeta()
  const u = meta.user
  const session = hasSession(u?.authMethod)
  const q = useAccount(session)
  const qc = useQueryClient()
  const acc = q.data
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [removing, setRemoving] = useState<Passkey | null>(null)

  const refresh = () => qc.invalidateQueries({ queryKey: ['rb', 'account'] })

  const add = async () => {
    setError('')
    setBusy(true)
    try {
      const begin = await apiFetch<{ ceremony: string; options: { publicKey: Record<string, unknown> } }>('/account/passkeys/begin', {
        method: 'POST',
        body: JSON.stringify({ name: name.trim() }),
      })
      const cred = await createCredential(begin.options)
      await apiFetch(`/account/passkeys/finish?ceremony=${encodeURIComponent(begin.ceremony)}`, {
        method: 'POST',
        body: JSON.stringify(cred),
      })
      setName('')
      toast.success(A.added)
      await refresh()
    } catch (e) {
      setError(isCancelled(e) ? A.cancelled : errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    if (!removing) return
    try {
      await apiFetch(`/account/passkeys/${encodeURIComponent(removing.id)}`, { method: 'DELETE' })
      toast.success(A.deleted)
      setRemoving(null)
      await refresh()
    } catch (e) {
      setRemoving(null)
      toast.error(errorMessage(e))
    }
  }

  const method = u?.authMethod ?? 'none'
  const sso = isSSO(u?.authMethod)
  const kinds = (list?: string[]) => (list ?? []).map((k) => A.roleFromKinds[k] ?? k).join(t.common.listSep)
  return (
    <div className="max-w-3xl">
      <PageHeader
        icon={<ShieldCheck />}
        title={A.title}
        description={A.description}
        actions={
          session && (
            <Button variant="outline" size="sm" onClick={() => void logout()}>
              <LogOut /> {A.logout}
            </Button>
          )
        }
      />

      <Card className="mb-6">
        <CardContent>
          <dl>
            <Field label={A.identity}>
              <span className="font-mono text-[0.8125rem]">{u?.id || u?.email || t.user.anonymous}</span>
            </Field>
            {u?.name && <Field label={A.name}>{u.name}</Field>}
            <Field label={A.role}>
              <Badge variant={u?.role === 'admin' ? 'default' : 'secondary'}>{roleLabel(u?.role) || '—'}</Badge>
              {u?.auditor && (
                <Badge variant="outline" className="ml-1.5" title={t.auth.auditor.hint}>
                  {t.auth.auditor.label}
                </Badge>
              )}
              <span className="ml-2 text-xs text-muted-foreground">{A.roleHint}</span>
              {u?.auditor && <p className="mt-1.5 text-xs text-muted-foreground">{t.auth.auditor.hint}</p>}
            </Field>
            {acc && kinds(acc.roleFrom) && (
              <Field label={A.roleFrom}>
                <span data-testid="role-from">{kinds(acc.roleFrom)}</span>
                {acc.claimsAbsolute ? (
                  <p className="mt-1.5 text-xs text-muted-foreground">{A.claimsNote(Math.max(1, Math.round(acc.claimsAbsolute / 3600)))}</p>
                ) : null}
              </Field>
            )}
            {acc && kinds(acc.auditorFrom) && <Field label={A.auditorFrom}>{kinds(acc.auditorFrom)}</Field>}
            <Field label={A.method}>{t.auth.method[method] ?? method}</Field>
          </dl>
        </CardContent>
      </Card>

      {meta.oauthServer && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <PlugZap className="size-4" /> {t.oauth.grants.title}
            </CardTitle>
            <CardDescription>{t.oauth.grants.hint}</CardDescription>
          </CardHeader>
          <CardContent>
            <GrantsList scope="account" />
          </CardContent>
        </Card>
      )}

      {session && !sso && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Fingerprint className="size-4" /> {A.passkeys}
            </CardTitle>
            <CardDescription>{A.passkeysHint}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {q.isPending ? (
              <Skeleton className="h-16 w-full" />
            ) : q.isError ? (
              <p className="text-sm text-destructive">{errorMessage(q.error)}</p>
            ) : !acc?.passkeysEnabled ? (
              <p className="text-sm text-muted-foreground">{A.disabledHint}</p>
            ) : (
              <>
                {acc.passkeyError && <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{A.fileError}</p>}
                {acc.passkeys.length === 0 ? (
                  <p className="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">{A.passkeysEmpty}</p>
                ) : (
                  <ul className="divide-y rounded-lg border">
                    {acc.passkeys.map((k, i) => (
                      <li key={k.id} style={{ ['--i' as string]: i }} className="rb-row-in flex items-center gap-3 px-4 py-3">
                        <KeyRound className="size-4 shrink-0 text-muted-foreground" />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm font-medium">{k.name}</div>
                          <div className="text-xs text-muted-foreground">{A.created(relativeTime(k.created))}</div>
                        </div>
                        <Button variant="ghost" size="sm" onClick={() => setRemoving(k)}>
                          <Trash2 /> {A.delete}
                        </Button>
                      </li>
                    ))}
                  </ul>
                )}

                {!passkeysSupported() ? (
                  <p className="text-sm text-muted-foreground">{A.unsupported}</p>
                ) : meta.readOnly ? (
                  <p className="text-sm text-muted-foreground">{A.readOnly}</p>
                ) : acc.canEnrol ? (
                  <form
                    className="flex flex-wrap items-end gap-2"
                    onSubmit={(e) => {
                      e.preventDefault()
                      void add()
                    }}
                  >
                    <label className="min-w-48 flex-1 space-y-1.5 text-sm">
                      <span className="text-muted-foreground">{A.passkeyName}</span>
                      <Input value={name} maxLength={100} placeholder={A.passkeyNamePlaceholder} onChange={(e) => setName(e.target.value)} />
                    </label>
                    <Button type="submit" disabled={busy}>
                      <Plus /> {busy ? A.adding : A.add}
                    </Button>
                  </form>
                ) : (
                  <div className="flex flex-wrap items-center gap-3 rounded-lg bg-muted/60 px-4 py-3 text-sm">
                    <span className="flex-1 text-muted-foreground">{A.needRecent}</span>
                    <Button variant="outline" size="sm" render={<a href="/auth/oidc/start?return=%2Faccount" />}>
                      {A.reauth}
                    </Button>
                  </div>
                )}
                {error && <p className="text-sm text-destructive">{error}</p>}
              </>
            )}
          </CardContent>
        </Card>
      )}

      <AlertDialog open={removing !== null} onOpenChange={(o) => !o && setRemoving(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{A.deleteTitle}</AlertDialogTitle>
            <AlertDialogDescription>{A.deleteBody(removing?.name ?? '')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{A.cancel}</AlertDialogCancel>
            <Button variant="destructive" onClick={() => void remove()}>
              {A.deleteConfirm}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
