import { useState } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { CircleAlert, KeyRound, Trash2, Users as UsersIcon } from 'lucide-react'
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
import { Tabs, TabsContent, TabsIndicator, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { EmptyState, PageHeader } from '@/components/common'
import { RolesEditor } from '@/components/users/RolesEditor'
import { roleLabel } from '@/components/layout/UserMenu'
import { t } from '@/i18n'
import { apiFetch, errorMessage } from '@/lib/api'
import { useUsers, type ManagedUser, type Passkey } from '@/lib/auth'
import { relativeTime } from '@/lib/ledger'
import { useMeta } from '@/providers/meta'

/** Users: who has signed in (everyone with a role), and Roles, where an administrator edits the role lists. */
export default function Users() {
  const U = t.auth.users
  const { meta } = useMeta()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const admin = !!meta.user?.canAdmin
  const tab = admin && /\/roles\/?$/.test(pathname) ? 'roles' : 'people'
  const header = (
    <PageHeader icon={<UsersIcon />} title={U.title} description={tab === 'roles' ? t.auth.rolesEditor.description : undefined} />
  )
  if (!admin) {
    return (
      <div>
        {header}
        <People />
      </div>
    )
  }
  return (
    <div>
      {header}
      <Tabs value={tab} onValueChange={(v) => navigate(v === 'roles' ? '/admin/users/roles' : '/admin/users')}>
        <TabsList>
          <TabsIndicator />
          <TabsTrigger value="people">{t.auth.rolesEditor.tabPeople}</TabsTrigger>
          <TabsTrigger value="roles">{t.auth.rolesEditor.tabRoles}</TabsTrigger>
        </TabsList>
        <TabsContent value="people">
          <People />
        </TabsContent>
        <TabsContent value="roles">
          <RolesEditor />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function People() {
  const U = t.auth.users
  const q = useUsers()
  const qc = useQueryClient()
  const [removing, setRemoving] = useState<{ user: ManagedUser; key: Passkey } | null>(null)

  const remove = async () => {
    if (!removing) return
    try {
      await apiFetch(`/admin/passkeys/${encodeURIComponent(removing.key.id)}`, { method: 'DELETE' })
      toast.success(U.deleted)
      setRemoving(null)
      await qc.invalidateQueries({ queryKey: ['rb', 'users'] })
    } catch (e) {
      setRemoving(null)
      toast.error(errorMessage(e))
    }
  }

  const users = q.data?.users ?? []
  // under single sign-on nobody has a passkey: the column and its dialog have nothing to show
  const showPasskeys = q.data?.passkeysEnabled === true
  return (
    <div>
      <p className="mb-5 max-w-3xl text-sm text-muted-foreground">{showPasskeys ? U.description : U.descriptionNoPasskeys}</p>
      {q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : q.isError ? (
        <EmptyState icon={<CircleAlert className="size-8" />} title={t.errors.generic} body={errorMessage(q.error)} />
      ) : users.length === 0 ? (
        <EmptyState icon={<UsersIcon className="size-8" />} title={U.empty} body={U.emptyBody} />
      ) : (
        <>
          {q.data?.passkeyError && (
            <p className="mb-4 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{U.fileError}</p>
          )}
          <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
            <table className="w-full border-collapse text-sm">
              <thead className="bg-muted/60">
                <tr className="border-b text-left text-xs text-muted-foreground">
                  {[U.id, U.role, U.method, U.lastSeen, ...(showPasskeys ? [U.passkeys] : [])].map((h) => (
                    <th key={h} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map((u, i) => (
                  <tr
                    key={u.id}
                    style={{ ['--i' as string]: i }}
                    className="rb-row-in border-b align-top transition-colors duration-150 last:border-0 even:bg-muted/25 hover:bg-muted/50"
                  >
                    <td className="px-4 py-2.5">
                      <div className="font-mono text-[0.8125rem] break-all">{u.id}</div>
                      {u.name && <div className="text-xs text-muted-foreground">{u.name}</div>}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <Badge variant={u.role === 'admin' ? 'default' : u.role === 'none' ? 'destructive' : 'secondary'}>{roleLabel(u.role)}</Badge>
                      {u.auditor && (
                        <Badge variant="outline" className="ml-1.5" title={t.auth.auditor.users}>
                          {t.auth.auditor.label}
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap">{u.method ? (t.auth.method[u.method] ?? u.method) : '—'}</td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-muted-foreground">
                      {u.seen && u.lastSeen ? relativeTime(u.lastSeen) : U.notSeen}
                    </td>
                    {showPasskeys && (
                      <td className="px-4 py-2.5">
                        {u.passkeys.length === 0 ? (
                          <span className="text-muted-foreground">{U.none}</span>
                        ) : (
                          <ul className="space-y-1">
                            {u.passkeys.map((k) => (
                              <li key={k.id} className="flex items-center gap-2">
                                <KeyRound className="size-3.5 shrink-0 text-muted-foreground" />
                                <span className="min-w-0 truncate">{k.name}</span>
                                <Button
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label={`${U.deleteKey}${t.common.colon}${k.name}`}
                                  title={U.deleteKey}
                                  onClick={() => setRemoving({ user: u, key: k })}
                                >
                                  <Trash2 />
                                </Button>
                              </li>
                            ))}
                          </ul>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-xs text-muted-foreground">{U.count(users.length)}</p>
        </>
      )}
      <AlertDialog open={removing !== null} onOpenChange={(o) => !o && setRemoving(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{U.deleteTitle}</AlertDialogTitle>
            <AlertDialogDescription>{U.deleteBody(removing?.key.name ?? '', removing?.user.id ?? '')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{U.cancel}</AlertDialogCancel>
            <Button variant="destructive" onClick={() => void remove()}>
              {U.deleteConfirm}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
