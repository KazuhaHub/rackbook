import { useState } from 'react'
import { Link } from 'react-router'
import { Copy, KeyRound, Plus, Puzzle, ShieldAlert, Trash2 } from 'lucide-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
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
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState, PageHeader } from '@/components/common'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { apiFetch, errorMessage } from '@/lib/api'
import type { ApiToken, CreatedToken } from '@/lib/types'
import { useMeta } from '@/providers/meta'

type List = { tokens: ApiToken[]; mcpUrl: string }

const field = 'h-9 w-full rounded-lg border border-input bg-transparent px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50'

function when(s?: string) {
  if (!s) return '—'
  const d = new Date(s)
  return Number.isNaN(d.getTime()) ? s : formatDateTime(d)
}

function CopyBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <Label>{label}</Label>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => navigator.clipboard.writeText(value).then(() => toast.success(t.tokens.copied))}
        >
          <Copy /> {t.tokens.copy}
        </Button>
      </div>
      <pre className="max-h-48 overflow-auto rounded-lg border bg-muted/50 p-3 font-mono text-xs break-all whitespace-pre-wrap">{value}</pre>
    </div>
  )
}

function CreateDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (o: boolean) => void; onCreated: (c: CreatedToken) => void }) {
  const { meta } = useMeta()
  const [name, setName] = useState('')
  const [scope, setScope] = useState<'read' | 'write'>('read')
  const [cols, setCols] = useState<string[]>([])
  const [acts, setActs] = useState<string[]>([])
  const [mode, setMode] = useState<'pr' | 'push'>('pr')
  const [days, setDays] = useState(90)
  const [error, setError] = useState('')
  const toggle = (list: string[], set: (v: string[]) => void, v: string) => set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v])
  const write = scope === 'write'
  const m = useMutation({
    mutationFn: () =>
      apiFetch<CreatedToken>('/admin/tokens', {
        method: 'POST',
        body: JSON.stringify({
          name: name.trim(),
          scope,
          collections: write ? cols : [],
          actions: write ? acts : [],
          writeMode: write ? mode : '',
          expiresDays: days,
        }),
      }),
    onSuccess: (c) => {
      setName('')
      setCols([])
      setActs([])
      setMode('pr')
      setScope('read')
      setError('')
      onCreated(c)
    },
    onError: (e) => setError(errorMessage(e)),
  })
  const pushNeedsCols = write && mode === 'push' && cols.length === 0
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t.tokens.create}</DialogTitle>
          <DialogDescription>{t.tokens.description}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            m.mutate()
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="tk-name">{t.tokens.name}</Label>
            <Input id="tk-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-bot" autoComplete="off" required />
            <p className="text-xs text-muted-foreground">{t.tokens.nameHint}</p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="tk-scope">{t.tokens.scope}</Label>
              <select id="tk-scope" className={field} value={scope} onChange={(e) => setScope(e.target.value as 'read' | 'write')}>
                <option value="read">{t.tokens.scopes.read}</option>
                <option value="write">{t.tokens.scopes.write}</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="tk-exp">{t.tokens.expires}</Label>
              <select id="tk-exp" className={field} value={days} onChange={(e) => setDays(Number(e.target.value))}>
                {t.tokens.expiresOptions.map((o) => (
                  <option key={o.days} value={o.days}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          {write && (
            <>
              <p className="text-xs text-muted-foreground">{t.tokens.scopeHint}</p>
              <fieldset className="space-y-1.5">
                <legend className="mb-1.5 text-sm font-medium">{t.tokens.collections}</legend>
                <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                  {meta.collections.map((c) => (
                    <label key={c.name} className="flex items-center gap-1.5 text-sm">
                      <input type="checkbox" checked={cols.includes(c.name)} onChange={() => toggle(cols, setCols, c.name)} /> {c.title}
                    </label>
                  ))}
                </div>
              </fieldset>
              <fieldset className="space-y-1.5">
                <legend className="mb-1.5 text-sm font-medium">{t.tokens.actions}</legend>
                <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                  {Object.entries(t.tokens.actionNames).map(([k, label]) => (
                    <label key={k} className="flex items-center gap-1.5 text-sm">
                      <input type="checkbox" checked={acts.includes(k)} onChange={() => toggle(acts, setActs, k)} /> {label}
                    </label>
                  ))}
                </div>
              </fieldset>
              <div className="space-y-1.5">
                <Label htmlFor="tk-mode">{t.tokens.writeMode}</Label>
                <select id="tk-mode" className={field} value={mode} onChange={(e) => setMode(e.target.value as 'pr' | 'push')}>
                  <option value="pr">{t.tokens.writeModes.pr}</option>
                  <option value="push">{t.tokens.writeModes.push}</option>
                </select>
                {pushNeedsCols && <p className="text-xs text-destructive">{t.tokens.pushNeedsCollections}</p>}
              </div>
            </>
          )}
          {error && <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t.tokens.cancel}
            </Button>
            <Button type="submit" disabled={m.isPending || !name.trim() || pushNeedsCols}>
              {m.isPending ? t.tokens.submitting : t.tokens.submit}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function SecretDialog({ created, onClose }: { created: CreatedToken | null; onClose: () => void }) {
  return (
    <Dialog open={!!created} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
        {created && (
          <>
            <DialogHeader>
              <DialogTitle>{t.tokens.secretTitle}</DialogTitle>
              <DialogDescription>{t.tokens.secretBody}</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <CopyBox label={t.tokens.secret} value={created.secret} />
              <CopyBox label={t.tokens.mcpSnippet} value={JSON.stringify(created.snippet, null, 2)} />
              <CopyBox label={t.tokens.claudeCode} value={created.claudeCode} />
              {created.pullRequest && <p className="text-sm text-muted-foreground">{t.tokens.prNotice}</p>}
            </div>
            <DialogFooter>
              <Button onClick={onClose}>{t.tokens.done}</Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

export default function Tokens() {
  const qc = useQueryClient()
  const { byName } = useMeta()
  const q = useQuery({ queryKey: ['rb', 'tokens'], queryFn: () => apiFetch<List>('/admin/tokens') })
  const [creating, setCreating] = useState(false)
  const [created, setCreated] = useState<CreatedToken | null>(null)
  const [revoking, setRevoking] = useState<ApiToken | null>(null)
  const [error, setError] = useState('')
  const revoke = useMutation({
    mutationFn: (n: string) => apiFetch('/admin/tokens/' + encodeURIComponent(n), { method: 'DELETE' }),
    onSuccess: (_, n) => {
      toast.success(t.tokens.revoked(n))
      setRevoking(null)
      qc.invalidateQueries({ queryKey: ['rb', 'tokens'] })
    },
    onError: (e) => setError(errorMessage(e)),
  })
  const tokens = q.data?.tokens ?? []

  return (
    <div>
      <PageHeader
        title={t.tokens.title}
        description={t.tokens.description}
        actions={
          <Button size="sm" onClick={() => setCreating(true)}>
            <Plus /> {t.tokens.create}
          </Button>
        }
      />
      {q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : q.isError ? (
        <EmptyState icon={<ShieldAlert className="size-8" />} title={t.errors.generic} body={errorMessage(q.error)} />
      ) : tokens.length === 0 ? (
        <EmptyState icon={<KeyRound className="size-8" />} title={t.tokens.empty} body={t.tokens.emptyBody} />
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                {[t.tokens.name, t.tokens.scope, t.tokens.limits, t.tokens.createdBy, t.tokens.expiresAt, t.tokens.lastUsed, ''].map((h, i) => (
                  <th key={i} className="h-10 px-4 font-semibold tracking-wide whitespace-nowrap" title={i === 5 ? t.tokens.lastUsedHint : undefined}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {tokens.map((k) => (
                <tr key={k.name} className="border-b align-top last:border-0 even:bg-muted/25">
                  <td className="px-4 py-2.5">
                    <div className="font-medium">{k.name}</div>
                    <div className="font-mono text-xs text-muted-foreground">{k.prefix}…</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      <Badge variant={k.status === 'active' ? 'secondary' : 'outline'}>{t.tokens.status[k.status]}</Badge>
                      {k.module && (
                        <Badge variant="outline" title={t.tokens.moduleHint(k.module)} render={<Link to={`/modules/${encodeURIComponent(k.module)}`} />}>
                          <Puzzle /> {t.tokens.module}{t.common.colon}{k.module}
                        </Badge>
                      )}
                    </div>
                    {k.warnings.map((w) => (
                      <p key={w} className="mt-1 flex max-w-xs items-start gap-1 text-xs text-amber-700 dark:text-amber-400">
                        <ShieldAlert className="mt-0.5 size-3.5 shrink-0" /> {t.tokens.warnings[w] ?? w}
                      </p>
                    ))}
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">{t.tokens.scopes[k.scope]}</td>
                  <td className="px-4 py-2.5 text-xs">
                    {k.scope === 'write' ? (
                      <>
                        <div>{k.collections?.length ? k.collections.map((c) => byName.get(c)?.title ?? c).join(t.common.listSep) : t.tokens.allCollections}</div>
                        <div className="text-muted-foreground">
                          {(k.actions?.length ? k.actions : ['create', 'update', 'delete']).map((a) => t.tokens.actionNames[a] ?? a).join(' / ')}
                          {' · '}
                          {k.writeMode === 'push' ? t.tokens.writeModesShort.push : t.tokens.writeModesShort.pr}
                        </div>
                      </>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="max-w-48 truncate" title={k.createdBy}>
                      {k.createdBy}
                    </div>
                    <div className="text-xs text-muted-foreground">{when(k.created)}</div>
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">{k.expires ? when(k.expires) : t.tokens.expiresOptions[0].label}</td>
                  <td className="px-4 py-2.5 whitespace-nowrap">{k.lastUsed ? when(k.lastUsed) : t.tokens.never}</td>
                  <td className="px-4 py-2.5 text-right">
                    {k.status === 'active' && (
                      <Button variant="ghost" size="sm" onClick={() => (setError(''), setRevoking(k))}>
                        <Trash2 /> {t.tokens.revoke}
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <CreateDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(c) => {
          setCreating(false)
          setCreated(c)
          qc.invalidateQueries({ queryKey: ['rb', 'tokens'] })
        }}
      />
      <SecretDialog created={created} onClose={() => setCreated(null)} />
      <AlertDialog open={!!revoking} onOpenChange={(o) => !o && setRevoking(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{revoking && t.tokens.revokeTitle(revoking.name)}</AlertDialogTitle>
            <AlertDialogDescription>{t.tokens.revokeBody}</AlertDialogDescription>
          </AlertDialogHeader>
          {error && <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}
          <AlertDialogFooter>
            <AlertDialogCancel>{t.tokens.cancel}</AlertDialogCancel>
            <Button variant="destructive" disabled={revoke.isPending} onClick={() => revoking && revoke.mutate(revoking.name)}>
              {revoke.isPending ? t.tokens.revoking : t.tokens.revoke}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
